#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ne.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <xdp/xsk.h>

static int iface_xdp_detach(int ifindex, __u32 flags)
{
	return bpf_xdp_detach(ifindex, flags, NULL);
}

int iface_xdp_attach(int ifindex, int prog_fd, __u32 flags)
{
	return bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
}

void iface_xdp_try_detach(int ifindex, const char *ifname)
{
	(void)ifname;
	static const int modes[] = {
		XDP_FLAGS_SKB_MODE,
		XDP_FLAGS_DRV_MODE,
		XDP_FLAGS_HW_MODE,
	};
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
		(void)iface_xdp_detach(ifindex, modes[i]);
}

static int umem_sizing_ok(uint32_t frame_size, uint32_t ring_size, size_t umem_bytes)
{
	if (frame_size == 0 || ring_size == 0)
		return 0;
	size_t nframes = umem_bytes / (size_t)frame_size;
	size_t min_frames = (size_t)ring_size * 2u;
	return nframes >= min_frames;
}

int iface_local_umem_ok(const char *ifname, const struct local_config *lc, size_t umem_bytes)
{
	(void)ifname;
	return umem_sizing_ok(lc->frame_size, lc->ring_size, umem_bytes);
}

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

static int ne_afxdp_fq_fill_one(struct ne_zc_port *port, struct xsk_socket *xsk, uint64_t addr)
{
	return fq_push_one(port, xsk, addr);
}

static void pool_push(struct ne_afxdp_pair *p, uint64_t addr)
{
	pthread_mutex_lock(&p->pool_lock);
	if (p->stack_top < p->stack_cap)
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

static int ne_afxdp_fq_replenish_all(struct ne_afxdp_pair *p, struct ne_zc_port *prt, struct xsk_socket *xsk,
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

static int ne_afxdp_zc_prime_fq(struct ne_afxdp_pair *p, uint32_t ring_size)
{
	if (ne_afxdp_fq_replenish_all(p, &p->ing, p->ing.xsk, ring_size, &p->ing_fq_lock) != 0)
		return -1;
	if (ne_afxdp_fq_replenish_all(p, &p->wan, p->wan.xsk, ring_size, &p->wan_fq_lock) != 0)
		return -1;
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

int ne_afxdp_recv_ing(struct ne_afxdp_pair *p, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		      int max_pkts)
{
	if (!p->ing.xsk)
		return 0;
	uint32_t idx_rx = 0;
	int rcvd = xsk_ring_cons__peek(&p->ing.rx, max_pkts, &idx_rx);
	if (rcvd == 0) {
		struct pollfd pfd = {.fd = xsk_socket__fd(p->ing.xsk), .events = POLLIN};
		if (poll(&pfd, 1, 1) <= 0)
			return 0;
		rcvd = xsk_ring_cons__peek(&p->ing.rx, max_pkts, &idx_rx);
		if (rcvd == 0)
			return 0;
	}
	for (int j = 0; j < rcvd; j++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&p->ing.rx, idx_rx + j);
		addrs[j] = desc->addr;
		pkt_ptrs[j] = xsk_umem__get_data(p->bufs, xsk_umem__add_offset_to_addr(desc->addr));
		pkt_lens[j] = desc->len;
	}
	xsk_ring_cons__release(&p->ing.rx, rcvd);
	while (ne_afxdp_fq_replenish_all(p, &p->ing, p->ing.xsk, (uint32_t)rcvd, &p->ing_fq_lock) != 0)
		sched_yield();
	p->ing.rx_packets += (uint64_t)rcvd;
	for (int j = 0; j < rcvd; j++)
		p->ing.rx_bytes += pkt_lens[j];
	return rcvd;
}

int ne_afxdp_tx_wan(struct ne_afxdp_pair *p, uint64_t addr, uint32_t len)
{
	if (!p->wan.xsk || len == 0 || len > p->frame_size)
		return -1;
	ne_afxdp_drain_wan_cq(p);

	uint32_t tx_idx;
	if (xsk_ring_prod__reserve(&p->wan.tx, 1, &tx_idx) != 1) {
		ne_afxdp_drain_wan_cq(p);
		if (xsk_ring_prod__reserve(&p->wan.tx, 1, &tx_idx) != 1)
			return -1;
	}

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&p->wan.tx, tx_idx);
	d->addr = addr;
	d->len = len;
	d->options = 0;
	xsk_ring_prod__submit(&p->wan.tx, 1);

	(void)sendto(xsk_socket__fd(p->wan.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	p->wan.tx_packets++;
	p->wan.tx_bytes += len;
	return 0;
}

static int xdp_attach_try(int ifindex, int prog_fd, const char *ifn)
{
	(void)ifn;
	if (iface_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE) == 0)
		return 0;
	if (iface_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) == 0)
		return 0;
	return -1;
}

static int load_sock_map_and_attach(struct bpf_object **out_obj_ptr, const char *bpf_path,
				    const char *prog_name, const char *map_name, int ifindex,
				    const char *ifname, int sock_fd, uint32_t qid)
{
	(void)ifname;
	if (access(bpf_path, F_OK) != 0)
		return -1;
	struct bpf_object *obj = bpf_object__open_file(bpf_path, NULL);
	if (libbpf_get_error(obj))
		return -1;
	if (bpf_object__load(obj)) {
		bpf_object__close(obj);
		return -1;
	}
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		bpf_object__close(obj);
		return -1;
	}
	int prog_fd = bpf_program__fd(prog);
	struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		bpf_object__close(obj);
		return -1;
	}
	int map_fd = bpf_map__fd(map);
	if (bpf_map_update_elem(map_fd, &qid, &sock_fd, BPF_ANY)) {
		bpf_object__close(obj);
		return -1;
	}
	if (xdp_attach_try(ifindex, prog_fd, ifname)) {
		bpf_object__close(obj);
		return -1;
	}
	*out_obj_ptr = obj;
	return 0;
}

int ne_afxdp_pair_open(struct ne_afxdp_pair *p, const struct ne_afxdp_cfg *cfg)
{
	memset(p, 0, sizeof(*p));
	p->ring_size = cfg->ring_size;
	p->frame_size = cfg->frame_size;
	p->batch_size = cfg->batch_size;

	snprintf(p->ing.ifname, sizeof(p->ing.ifname), "%s", cfg->ing_if);
	snprintf(p->wan.ifname, sizeof(p->wan.ifname), "%s", cfg->wan_if);
	p->ing.ifindex = if_nametoindex(cfg->ing_if);
	p->wan.ifindex = if_nametoindex(cfg->wan_if);
	if (p->ing.ifindex == 0 || p->wan.ifindex == 0)
		return -1;

	struct local_config lc = {0};
	lc.umem_mb = cfg->umem_mb;
	lc.ring_size = cfg->ring_size;
	lc.batch_size = cfg->batch_size;
	lc.frame_size = cfg->frame_size;
	snprintf(lc.ifname, sizeof(lc.ifname), "%s", cfg->ing_if);

	uint32_t nbuf = cfg->ring_size * 8u;
	if (nbuf < cfg->ring_size * 2u)
		nbuf = cfg->ring_size * 2u;
	p->bufsize = (size_t)nbuf * (size_t)cfg->frame_size;
	if (!iface_local_umem_ok(cfg->ing_if, &lc, p->bufsize))
		return -1;

	iface_xdp_try_detach(p->ing.ifindex, p->ing.ifname);
	iface_xdp_try_detach(p->wan.ifindex, p->wan.ifname);

	if (posix_memalign(&p->bufs, getpagesize(), p->bufsize) != 0 || !p->bufs)
		return -1;
	(void)mlock(p->bufs, p->bufsize);

	struct xsk_umem_config umem_cfg = {
		.fill_size = cfg->ring_size,
		.comp_size = cfg->ring_size,
		.frame_size = cfg->frame_size,
		.frame_headroom = 0,
		.flags = 0,
	};

	if (xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->umem_fq, &p->umem_cq, &umem_cfg)) {
		munlock(p->bufs, p->bufsize);
		free(p->bufs);
		p->bufs = NULL;
		return -1;
	}

	struct xsk_socket_config sock_cfg = {
		.rx_size = cfg->ring_size,
		.tx_size = cfg->ring_size,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
	};

	int r = xsk_socket__create_shared(&p->ing.xsk, cfg->ing_if, 0, p->umem, &p->ing.rx, &p->ing.tx,
					  &p->ing.fq, &p->ing.cq, &sock_cfg);
	if (r) {
		xsk_umem__delete(p->umem);
		p->umem = NULL;
		munlock(p->bufs, p->bufsize);
		free(p->bufs);
		p->bufs = NULL;
		return -1;
	}

	r = xsk_socket__create_shared(&p->wan.xsk, cfg->wan_if, 0, p->umem, &p->wan.rx, &p->wan.tx,
				      &p->wan.fq, &p->wan.cq, &sock_cfg);
	if (r) {
		xsk_socket__delete(p->ing.xsk);
		p->ing.xsk = NULL;
		xsk_umem__delete(p->umem);
		p->umem = NULL;
		munlock(p->bufs, p->bufsize);
		free(p->bufs);
		p->bufs = NULL;
		return -1;
	}

	if (pthread_mutex_init(&p->ing_fq_lock, NULL) != 0)
		goto err_sock;
	if (pthread_mutex_init(&p->wan_fq_lock, NULL) != 0) {
		(void)pthread_mutex_destroy(&p->ing_fq_lock);
		goto err_sock;
	}
	p->fq_locks_inited = 1;

	if (pthread_mutex_init(&p->pool_lock, NULL) != 0) {
		ne_afxdp_zc_fq_locks_destroy(p);
		goto err_sock;
	}
	p->pool_lock_inited = 1;
	p->n_frames = nbuf;
	p->stack_cap = nbuf;
	p->frame_stack = calloc((size_t)nbuf, sizeof(uint64_t));
	if (!p->frame_stack) {
		ne_afxdp_zc_frame_pool_destroy(p);
		goto err_sock;
	}
	for (uint32_t k = 0; k < nbuf; k++)
		p->frame_stack[k] = (uint64_t)k * (uint64_t)cfg->frame_size;
	p->stack_top = nbuf;

	if (ne_afxdp_zc_prime_fq(p, cfg->ring_size) != 0) {
		ne_afxdp_zc_frame_pool_destroy(p);
		goto err_sock;
	}

	int ing_fd = xsk_socket__fd(p->ing.xsk);
	if (load_sock_map_and_attach(&p->bpf_ing, cfg->bpf_ing, "xdp_redirect_prog", "xsks_map",
				     p->ing.ifindex, p->ing.ifname, ing_fd, 0))
		goto err_bpf_ing;

	return 0;

err_bpf_ing:
	xsk_socket__delete(p->wan.xsk);
	p->wan.xsk = NULL;
	xsk_socket__delete(p->ing.xsk);
	p->ing.xsk = NULL;
	xsk_umem__delete(p->umem);
	p->umem = NULL;
err_sock:
	ne_afxdp_zc_frame_pool_destroy(p);
	ne_afxdp_zc_fq_locks_destroy(p);
	if (p->wan.xsk) {
		xsk_socket__delete(p->wan.xsk);
		p->wan.xsk = NULL;
	}
	if (p->ing.xsk) {
		xsk_socket__delete(p->ing.xsk);
		p->ing.xsk = NULL;
	}
	if (p->umem) {
		xsk_umem__delete(p->umem);
		p->umem = NULL;
	}
	if (p->bufs) {
		munlock(p->bufs, p->bufsize);
		free(p->bufs);
		p->bufs = NULL;
	}
	return -1;
}

void ne_afxdp_pair_close(struct ne_afxdp_pair *p)
{
	if (!p)
		return;
	iface_xdp_try_detach(p->ing.ifindex, p->ing.ifname);
	if (p->bpf_ing) {
		bpf_object__close(p->bpf_ing);
		p->bpf_ing = NULL;
	}
	if (p->wan.xsk)
		xsk_socket__delete(p->wan.xsk);
	if (p->ing.xsk)
		xsk_socket__delete(p->ing.xsk);
	ne_afxdp_zc_fq_locks_destroy(p);
	ne_afxdp_zc_frame_pool_destroy(p);
	if (p->umem)
		xsk_umem__delete(p->umem);
	if (p->bufs) {
		munlock(p->bufs, p->bufsize);
		free(p->bufs);
	}
	memset(p, 0, sizeof(*p));
}
