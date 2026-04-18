#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_afxdp_fq_pool.h"
#include "../../inc/ne_afxdp_zc_i.h"

#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fq_push_one(struct ne_zc_port *port, struct xsk_socket *xsk, uint64_t addr)
{
	uint32_t idx;
	int r = xsk_ring_prod__reserve(&port->fq, 1, &idx);
	if (r != 1) {
		struct pollfd pfd = {.fd = xsk_socket__fd(xsk), .events = POLLOUT};
		(void)poll(&pfd, 1, 0);
		r = xsk_ring_prod__reserve(&port->fq, 1, &idx);
		if (r != 1)
			return -1;
	}
	*xsk_ring_prod__fill_addr(&port->fq, idx) = addr;
	xsk_ring_prod__submit(&port->fq, 1);
	return 0;
}

int ne_afxdp_fq_fill_one(struct ne_zc_port *port, struct xsk_socket *xsk, uint64_t addr)
{
	return fq_push_one(port, xsk, addr);
}

static void pool_push(struct ne_afxdp_pair *p, uint64_t addr)
{
	pthread_mutex_lock(&p->pool_lock);
	if (p->stack_top >= p->stack_cap) {
		fprintf(stderr, "[ne] frame pool overflow (top=%u cap=%u)\n", p->stack_top, p->stack_cap);
		pthread_mutex_unlock(&p->pool_lock);
		return;
	}
	p->frame_stack[p->stack_top++] = addr;
	pthread_mutex_unlock(&p->pool_lock);
}

static uint64_t pool_pop(struct ne_afxdp_pair *p)
{
	pthread_mutex_lock(&p->pool_lock);
	if (p->stack_top == 0) {
		pthread_mutex_unlock(&p->pool_lock);
		return UINT64_MAX;
	}
	uint64_t a = p->frame_stack[--p->stack_top];
	pthread_mutex_unlock(&p->pool_lock);
	return a;
}

void ne_afxdp_drain_wan_cq(struct ne_afxdp_pair *p)
{
	uint32_t idx;
	int n = xsk_ring_cons__peek(&p->wan.cq, (int)p->ring_size, &idx);
	if (n <= 0)
		return;
	for (int i = 0; i < n; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&p->wan.cq, idx + i);
		pool_push(p, a);
	}
	xsk_ring_cons__release(&p->wan.cq, n);
}

void ne_afxdp_drain_ing_cq(struct ne_afxdp_pair *p)
{
	uint32_t idx;
	int n = xsk_ring_cons__peek(&p->ing.cq, (int)p->ring_size, &idx);
	if (n <= 0)
		return;
	for (int i = 0; i < n; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&p->ing.cq, idx + i);
		pool_push(p, a);
	}
	xsk_ring_cons__release(&p->ing.cq, n);
}

static void drain_both_cq_to_pool(struct ne_afxdp_pair *p)
{
	ne_afxdp_drain_wan_cq(p);
	ne_afxdp_drain_ing_cq(p);
}

static int fq_replenish(struct ne_afxdp_pair *p, struct ne_zc_port *prt, struct xsk_socket *xsk, uint32_t n,
			pthread_mutex_t *fq_lock)
{
	if (n == 0)
		return 0;
	uint64_t tmp[256];
	if (n > (uint32_t)(sizeof(tmp) / sizeof(tmp[0])))
		return -1;

	drain_both_cq_to_pool(p);

	for (uint32_t got = 0; got < n;) {
		uint64_t a = pool_pop(p);
		if (a != UINT64_MAX) {
			tmp[got++] = a;
			continue;
		}
		drain_both_cq_to_pool(p);
		sched_yield();
	}

	pthread_mutex_lock(fq_lock);
	uint32_t idx;
	int resv = xsk_ring_prod__reserve(&prt->fq, n, &idx);
	if (resv < 0 || (uint32_t)resv != n) {
		pthread_mutex_unlock(fq_lock);
		for (uint32_t j = 0; j < n; j++)
			pool_push(p, tmp[j]);
		return -1;
	}
	for (uint32_t j = 0; j < n; j++)
		*xsk_ring_prod__fill_addr(&prt->fq, idx + j) = tmp[j];
	xsk_ring_prod__submit(&prt->fq, n);

	if (xsk_ring_prod__needs_wakeup(&prt->fq))
		(void)sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	pthread_mutex_unlock(fq_lock);
	return 0;
}

int ne_afxdp_fq_replenish_all(struct ne_afxdp_pair *p, struct ne_zc_port *prt, struct xsk_socket *xsk,
			      uint32_t n, pthread_mutex_t *fq_lock)
{
	while (n > 0) {
		uint32_t chunk = n > 256u ? 256u : n;
		if (fq_replenish(p, prt, xsk, chunk, fq_lock) != 0)
			return -1;
		n -= chunk;
	}
	return 0;
}

void ne_afxdp_zc_frame_pool_destroy(struct ne_afxdp_pair *p)
{
	if (p->frame_stack) {
		free(p->frame_stack);
		p->frame_stack = NULL;
	}
	p->stack_top = 0;
	p->stack_cap = 0;
	p->n_frames = 0;
	if (p->pool_lock_inited) {
		(void)pthread_mutex_destroy(&p->pool_lock);
		p->pool_lock_inited = 0;
	}
}

void ne_afxdp_zc_fq_locks_destroy(struct ne_afxdp_pair *p)
{
	if (!p->fq_locks_inited)
		return;
	p->fq_locks_inited = 0;
	(void)pthread_mutex_destroy(&p->ing_fq_lock);
	(void)pthread_mutex_destroy(&p->wan_fq_lock);
}

int ne_afxdp_zc_prime_fq(struct ne_afxdp_pair *p, uint32_t ring_size)
{
	if (ne_afxdp_fq_replenish_all(p, &p->ing, p->ing.xsk, ring_size, &p->ing_fq_lock) != 0) {
		fprintf(stderr, "[ne] initial ingress FQ replenish failed\n");
		return -1;
	}
	if (ne_afxdp_fq_replenish_all(p, &p->wan, p->wan.xsk, ring_size, &p->wan_fq_lock) != 0) {
		fprintf(stderr, "[ne] initial wan FQ replenish failed\n");
		return -1;
	}
	return 0;
}

void ne_afxdp_fq_return_ing(struct ne_afxdp_pair *p, uint64_t addr)
{
	if (!p->fq_locks_inited)
		return;
	pthread_mutex_lock(&p->ing_fq_lock);
	(void)ne_afxdp_fq_fill_one(&p->ing, p->ing.xsk, addr);
	pthread_mutex_unlock(&p->ing_fq_lock);
}

void ne_afxdp_fq_return_wan(struct ne_afxdp_pair *p, uint64_t addr)
{
	if (!p->fq_locks_inited)
		return;
	pthread_mutex_lock(&p->wan_fq_lock);
	(void)ne_afxdp_fq_fill_one(&p->wan, p->wan.xsk, addr);
	pthread_mutex_unlock(&p->wan_fq_lock);
}
