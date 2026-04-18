#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "zc.h"

#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <xdp/xsk.h>

static void xdp_detach_all(int ifindex)
{
	static const int modes[] = {XDP_FLAGS_SKB_MODE, XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE};
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
		(void)bpf_xdp_detach(ifindex, modes[i], NULL);
}

static int umem_ok(size_t umem_bytes)
{
	size_t nframes = umem_bytes / (size_t)FRAME_SZ;
	size_t need = (size_t)RING_SZ * 2u;
	return nframes >= need;
}

void zc_close(struct zc *z)
{
	if (!z)
		return;
	if (z->ifindex)
		xdp_detach_all(z->ifindex);
	if (z->xsk) {
		xsk_socket__delete(z->xsk);
		z->xsk = NULL;
	}
	if (z->umem) {
		xsk_umem__delete(z->umem);
		z->umem = NULL;
	}
	if (z->locks_ok) {
		(void)pthread_mutex_destroy(&z->fq_mu);
		(void)pthread_mutex_destroy(&z->pool_mu);
		z->locks_ok = 0;
	}
	free(z->stk);
	z->stk = NULL;
	if (z->umem_area) {
		(void)munlock(z->umem_area, z->umem_bytes);
		free(z->umem_area);
		z->umem_area = NULL;
	}
	memset(z, 0, sizeof(*z));
}

int zc_open(struct zc *z, const char *ifname)
{
	memset(z, 0, sizeof(*z));
	if (pthread_mutex_init(&z->fq_mu, NULL) != 0)
		return -1;
	if (pthread_mutex_init(&z->pool_mu, NULL) != 0) {
		(void)pthread_mutex_destroy(&z->fq_mu);
		return -1;
	}
	z->locks_ok = 1;

	z->ifindex = (int)if_nametoindex(ifname);
	if (z->ifindex <= 0)
		goto fail;

	uint32_t nbuf = RING_SZ * 8u;
	if (nbuf < RING_SZ * 2u)
		nbuf = RING_SZ * 2u;
	z->umem_bytes = (size_t)nbuf * (size_t)FRAME_SZ;
	if (!umem_ok(z->umem_bytes))
		goto fail;

	xdp_detach_all(z->ifindex);

	if (posix_memalign(&z->umem_area, getpagesize(), z->umem_bytes) != 0)
		goto fail;
	(void)mlock(z->umem_area, z->umem_bytes);

	struct xsk_umem_config ucfg = {
		.fill_size = RING_SZ,
		.comp_size = RING_SZ,
		.frame_size = FRAME_SZ,
		.frame_headroom = 0,
		.flags = 0,
	};
	if (xsk_umem__create(&z->umem, z->umem_area, z->umem_bytes, &z->umem_fq, &z->umem_cq, &ucfg))
		goto fail;

	struct xsk_socket_config scfg = {
		.rx_size = RING_SZ,
		.tx_size = RING_SZ,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
	};
	if (xsk_socket__create_shared(&z->xsk, ifname, 0, z->umem, &z->rx, &z->tx, &z->fq, &z->cq,
				      &scfg))
		goto fail;

	z->stk_cap = nbuf;
	z->stk = calloc((size_t)nbuf, sizeof(uint64_t));
	if (!z->stk)
		goto fail;
	for (uint32_t k = 0; k < nbuf; k++)
		z->stk[k] = (uint64_t)k * (uint64_t)FRAME_SZ;
	z->stk_top = nbuf;

	if (zc_fq_prime(z) != 0)
		goto fail;
	return 0;

fail:
	zc_close(z);
	return -1;
}
