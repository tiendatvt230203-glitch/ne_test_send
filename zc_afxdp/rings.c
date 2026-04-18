#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "zc.h"

#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>

void zc_pool_push(struct zc *z, uint64_t addr)
{
	pthread_mutex_lock(&z->pool_mu);
	if (z->stk_top < z->stk_cap)
		z->stk[z->stk_top++] = addr;
	pthread_mutex_unlock(&z->pool_mu);
}

uint64_t zc_pool_pop(struct zc *z)
{
	pthread_mutex_lock(&z->pool_mu);
	if (z->stk_top == 0) {
		pthread_mutex_unlock(&z->pool_mu);
		return UINT64_MAX;
	}
	uint64_t a = z->stk[--z->stk_top];
	pthread_mutex_unlock(&z->pool_mu);
	return a;
}

void zc_drain_cq(struct zc *z)
{
	uint32_t idx;
	int n = xsk_ring_cons__peek(&z->cq, (int)RING_SZ, &idx);
	if (n <= 0)
		return;
	for (int i = 0; i < n; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&z->cq, idx + i);
		zc_pool_push(z, a);
	}
	xsk_ring_cons__release(&z->cq, n);
}

static int zc_fq_fill_chunk(struct zc *z, uint32_t n)
{
	if (n == 0)
		return 0;
	uint64_t tmp[256];
	if (n > (uint32_t)(sizeof(tmp) / sizeof(tmp[0])))
		return -1;

	zc_drain_cq(z);
	for (uint32_t got = 0; got < n;) {
		uint64_t a = zc_pool_pop(z);
		if (a != UINT64_MAX) {
			tmp[got++] = a;
			continue;
		}
		zc_drain_cq(z);
		sched_yield();
	}

	pthread_mutex_lock(&z->fq_mu);
	uint32_t idx;
	int resv = xsk_ring_prod__reserve(&z->fq, n, &idx);
	if (resv < 0 || (uint32_t)resv != n) {
		pthread_mutex_unlock(&z->fq_mu);
		for (uint32_t j = 0; j < n; j++)
			zc_pool_push(z, tmp[j]);
		return -1;
	}
	for (uint32_t j = 0; j < n; j++)
		*xsk_ring_prod__fill_addr(&z->fq, idx + j) = tmp[j];
	xsk_ring_prod__submit(&z->fq, n);
	if (xsk_ring_prod__needs_wakeup(&z->fq))
		(void)sendto(xsk_socket__fd(z->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	pthread_mutex_unlock(&z->fq_mu);
	return 0;
}

int zc_fq_prime(struct zc *z)
{
	for (uint32_t left = RING_SZ; left > 0;) {
		uint32_t chunk = left > 256u ? 256u : left;
		if (zc_fq_fill_chunk(z, chunk) != 0)
			return -1;
		left -= chunk;
	}
	return 0;
}
