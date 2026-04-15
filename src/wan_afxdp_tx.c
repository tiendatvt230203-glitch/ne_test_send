#include "../inc/wan_afxdp.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static void ne_wan_reclaim(struct ne_wan_tx *w)
{
	uint32_t idx = 0;
	int n = xsk_ring_cons__peek(&w->comp, w->ring_size, &idx);
	if (n <= 0)
		return;
	for (int i = 0; i < n; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&w->comp, idx + i);
		if (w->free_n < w->frame_cap)
			w->free_pool[w->free_n++] = a;
	}
	xsk_ring_cons__release(&w->comp, n);
}

int ne_wan_tx_open(struct ne_wan_tx *w, const char *ifname, uint32_t ring_size, uint32_t frame_size,
		   uint32_t umem_mb)
{
	memset(w, 0, sizeof(*w));
	strncpy(w->ifname, ifname, IF_NAMESIZE - 1);
	w->ifindex = if_nametoindex(ifname);
	if (w->ifindex == 0)
		return -1;
	w->ring_size = ring_size;
	w->frame_size = frame_size;
	w->umem_size = (size_t)umem_mb * 1024 * 1024;

	if (posix_memalign(&w->bufs, getpagesize(), w->umem_size) != 0 || !w->bufs)
		return -1;
	(void)mlock(w->bufs, w->umem_size);

	struct xsk_umem_config ucfg = {
		.fill_size = ring_size,
		.comp_size = ring_size,
		.frame_size = frame_size,
		.frame_headroom = 0,
		.flags = 0,
	};
	if (xsk_umem__create(&w->umem, w->bufs, w->umem_size, &w->fill, &w->comp, &ucfg)) {
		munlock(w->bufs, w->umem_size);
		free(w->bufs);
		w->bufs = NULL;
		return -1;
	}

	struct xsk_socket_config scfg = {
		.rx_size = ring_size,
		.tx_size = ring_size,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
	};

	int ret = xsk_socket__create(&w->xsk, w->ifname, 0, w->umem, &w->rx, &w->tx, &scfg);
	if (ret) {
		fprintf(stderr, "%s: xsk_socket__create (zero-copy) failed: %d (%s)\n", ifname, ret,
			ret < 0 ? strerror(-ret) : "non-negative error");
		xsk_umem__delete(w->umem);
		w->umem = NULL;
		munlock(w->bufs, w->umem_size);
		free(w->bufs);
		w->bufs = NULL;
		return -1;
	}

	uint32_t nfr = (uint32_t)(w->umem_size / (size_t)w->frame_size);
	if (nfr == 0) {
		ne_wan_tx_close(w);
		return -1;
	}
	w->free_pool = calloc(nfr, sizeof(uint64_t));
	if (!w->free_pool) {
		ne_wan_tx_close(w);
		return -1;
	}
	w->free_n = nfr;
	for (uint32_t i = 0; i < nfr; i++)
		w->free_pool[i] = (uint64_t)i * w->frame_size;
	w->frame_cap = nfr;

	return 0;
}

void ne_wan_tx_close(struct ne_wan_tx *w)
{
	free(w->free_pool);
	w->free_pool = NULL;
	w->free_n = 0;
	if (w->xsk)
		xsk_socket__delete(w->xsk);
	if (w->umem)
		xsk_umem__delete(w->umem);
	if (w->bufs) {
		munlock(w->bufs, w->umem_size);
		free(w->bufs);
	}
	memset(w, 0, sizeof(*w));
}

int ne_wan_tx_send(struct ne_wan_tx *w, const void *pkt, uint32_t len)
{
	if (!w->xsk || len == 0 || len > w->frame_size)
		return -1;

	ne_wan_reclaim(w);
	if (w->free_n == 0) {
		ne_wan_reclaim(w);
		if (w->free_n == 0)
			return -1;
	}

	uint64_t addr = w->free_pool[--w->free_n];
	memcpy((uint8_t *)w->bufs + addr, pkt, len);

	uint32_t tx_idx = 0;
	if (xsk_ring_prod__reserve(&w->tx, 1, &tx_idx) != 1) {
		w->free_pool[w->free_n++] = addr;
		return -1;
	}

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&w->tx, tx_idx);
	d->addr = addr;
	d->len = len;
	xsk_ring_prod__submit(&w->tx, 1);

	if (xsk_ring_prod__needs_wakeup(&w->tx)) {
		int rc = sendto(xsk_socket__fd(w->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (rc < 0 && errno != EAGAIN && errno != EBUSY && errno != ENOBUFS)
			return -1;
	}

	w->tx_pkts++;
	w->tx_bytes += len;
	return 0;
}
