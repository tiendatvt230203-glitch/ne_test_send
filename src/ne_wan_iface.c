#include "../inc/ne_wan_iface.h"
#include "../inc/netdev_xdp_internal.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>

static struct bpf_object *g_wan_bpf;

static void ne_wan_tx_reclaim(struct xsk_interface *wan)
{
	uint32_t idx = 0;
	int n = xsk_ring_cons__peek(&wan->comp, (int)wan->ring_size, &idx);
	if (n <= 0)
		return;
	for (int i = 0; i < n; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&wan->comp, idx + i);
		if (wan->tx_free_n < wan->tx_nfr)
			wan->tx_free[wan->tx_free_n++] = a;
	}
	xsk_ring_cons__release(&wan->comp, n);
}

int ne_wan_iface_open(struct xsk_interface *wan, const struct local_config *lc, const char *bpf_file)
{
	memset(wan, 0, sizeof(*wan));
	wan->ifindex = if_nametoindex(lc->ifname);
	strncpy(wan->ifname, lc->ifname, IF_NAMESIZE - 1);
	if (wan->ifindex == 0) {
		fprintf(stderr, "WAN interface %s not found\n", lc->ifname);
		return -1;
	}

	const uint32_t qid = 0;
	iface_xdp_try_detach(wan->ifindex, wan->ifname);

	if (access(bpf_file, F_OK) != 0) {
		fprintf(stderr, "WAN BPF object not found: %s\n", bpf_file);
		return -1;
	}

	struct bpf_object *bpf_obj = bpf_object__open_file(bpf_file, NULL);
	if (libbpf_get_error(bpf_obj)) {
		fprintf(stderr, "Failed to open WAN BPF %s\n", bpf_file);
		return -1;
	}

	if (bpf_object__load(bpf_obj)) {
		fprintf(stderr, "Failed to load WAN BPF object\n");
		bpf_object__close(bpf_obj);
		return -1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, "xdp_wan_redirect_prog");
	if (!prog) {
		fprintf(stderr, "WAN XDP program not found\n");
		bpf_object__close(bpf_obj);
		return -1;
	}
	int prog_fd = bpf_program__fd(prog);

	struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "wan_xsks_map");
	if (!map) {
		fprintf(stderr, "wan_xsks_map not found\n");
		bpf_object__close(bpf_obj);
		return -1;
	}
	int xsk_map_fd = bpf_map__fd(map);

	size_t umem_bytes = (size_t)lc->umem_mb * 1024 * 1024;
	if (!iface_local_umem_ok(lc->ifname, lc, umem_bytes)) {
		bpf_object__close(bpf_obj);
		return -1;
	}

	wan->umem_size = umem_bytes;
	wan->ring_size = lc->ring_size;
	wan->frame_size = lc->frame_size;
	wan->batch_size = lc->batch_size;

	struct xsk_umem_config umem_cfg = {
		.fill_size = lc->ring_size,
		.comp_size = lc->ring_size,
		.frame_size = lc->frame_size,
		.frame_headroom = 0,
		.flags = 0,
	};

	struct xsk_socket_config sock_cfg = {
		.rx_size = lc->ring_size,
		.tx_size = lc->ring_size,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
	};

	if (posix_memalign(&wan->bufs, getpagesize(), umem_bytes) != 0 || !wan->bufs) {
		bpf_object__close(bpf_obj);
		return -1;
	}
	mlock(wan->bufs, umem_bytes);

	int ret = xsk_umem__create(&wan->umem, wan->bufs, umem_bytes, &wan->fill, &wan->comp, &umem_cfg);
	if (ret) {
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}

	ret = xsk_socket__create(&wan->xsk, wan->ifname, qid, wan->umem, &wan->rx, &wan->tx, &sock_cfg);
	if (ret) {
		fprintf(stderr, "WAN xsk_socket__create failed: %d (%s)\n", ret,
			ret < 0 ? strerror(-ret) : "");
		xsk_umem__delete(wan->umem);
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}

	int sock_fd = xsk_socket__fd(wan->xsk);
	if (bpf_map_update_elem(xsk_map_fd, &qid, &sock_fd, BPF_ANY)) {
		fprintf(stderr, "WAN bpf_map_update_elem failed\n");
		xsk_socket__delete(wan->xsk);
		xsk_umem__delete(wan->umem);
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}

	uint32_t nfr = (uint32_t)(umem_bytes / (size_t)lc->frame_size);
	if (nfr <= lc->ring_size) {
		fprintf(stderr, "WAN UMEM too small for ring\n");
		xsk_socket__delete(wan->xsk);
		xsk_umem__delete(wan->umem);
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}

	wan->tx_nfr = nfr - lc->ring_size;
	wan->tx_free = calloc(wan->tx_nfr, sizeof(uint64_t));
	if (!wan->tx_free) {
		xsk_socket__delete(wan->xsk);
		xsk_umem__delete(wan->umem);
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}
	wan->tx_free_n = 0;
	for (uint32_t i = lc->ring_size; i < nfr; i++)
		wan->tx_free[wan->tx_free_n++] = (uint64_t)i * lc->frame_size;

	uint32_t idx;
	ret = xsk_ring_prod__reserve(&wan->fill, lc->ring_size, &idx);
	if (ret != (int)lc->ring_size) {
		fprintf(stderr, "WAN fill reserve failed\n");
		free(wan->tx_free);
		wan->tx_free = NULL;
		xsk_socket__delete(wan->xsk);
		xsk_umem__delete(wan->umem);
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}
	for (int i = 0; i < ret; i++)
		*xsk_ring_prod__fill_addr(&wan->fill, idx++) = (uint32_t)((unsigned)i * lc->frame_size);
	xsk_ring_prod__submit(&wan->fill, ret);

	if (iface_xdp_attach(wan->ifindex, prog_fd, XDP_FLAGS_SKB_MODE)) {
		fprintf(stderr, "WAN XDP attach failed\n");
		free(wan->tx_free);
		wan->tx_free = NULL;
		xsk_socket__delete(wan->xsk);
		xsk_umem__delete(wan->umem);
		munlock(wan->bufs, umem_bytes);
		free(wan->bufs);
		bpf_object__close(bpf_obj);
		return -1;
	}

	g_wan_bpf = bpf_obj;
	fprintf(stderr, "[ne-pipeline] WAN AF_XDP ready on %s (q0)\n", wan->ifname);
	return 0;
}

void ne_wan_iface_close(struct xsk_interface *wan)
{
	if (!wan || !wan->ifname[0])
		return;
	iface_xdp_try_detach(wan->ifindex, wan->ifname);
	if (wan->xsk)
		xsk_socket__delete(wan->xsk);
	if (wan->umem)
		xsk_umem__delete(wan->umem);
	free(wan->tx_free);
	wan->tx_free = NULL;
	if (wan->bufs) {
		munlock(wan->bufs, wan->umem_size);
		free(wan->bufs);
	}
	if (g_wan_bpf) {
		bpf_object__close(g_wan_bpf);
		g_wan_bpf = NULL;
	}
	memset(wan, 0, sizeof(*wan));
}

int ne_wan_iface_send(struct xsk_interface *wan, const void *pkt, uint32_t len)
{
	if (!wan->xsk || len == 0 || len > wan->frame_size || !wan->tx_free)
		return -1;

	ne_wan_tx_reclaim(wan);
	if (wan->tx_free_n == 0) {
		ne_wan_tx_reclaim(wan);
		if (wan->tx_free_n == 0)
			return -1;
	}

	uint64_t addr = wan->tx_free[--wan->tx_free_n];
	memcpy((uint8_t *)wan->bufs + addr, pkt, len);

	uint32_t tx_idx = 0;
	if (xsk_ring_prod__reserve(&wan->tx, 1, &tx_idx) != 1) {
		wan->tx_free[wan->tx_free_n++] = addr;
		return -1;
	}

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&wan->tx, tx_idx);
	d->addr = addr;
	d->len = len;
	xsk_ring_prod__submit(&wan->tx, 1);

	if (xsk_ring_prod__needs_wakeup(&wan->tx)) {
		int rc = sendto(xsk_socket__fd(wan->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (rc < 0 && errno != EAGAIN && errno != EBUSY && errno != ENOBUFS)
			return -1;
	}

	wan->tx_packets++;
	wan->tx_bytes += len;
	return 0;
}

int ne_wan_iface_recv(struct xsk_interface *wan, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		      int max_pkts)
{
	if (!wan->xsk)
		return 0;

	uint32_t idx_rx = 0;
	int rcvd = xsk_ring_cons__peek(&wan->rx, max_pkts, &idx_rx);
	if (rcvd == 0) {
		struct pollfd pfd = {.fd = xsk_socket__fd(wan->xsk), .events = POLLIN};
		if (poll(&pfd, 1, 1) <= 0)
			return 0;
		rcvd = xsk_ring_cons__peek(&wan->rx, max_pkts, &idx_rx);
		if (rcvd == 0)
			return 0;
	}

	for (int j = 0; j < rcvd; j++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&wan->rx, idx_rx + j);
		addrs[j] = desc->addr;
		pkt_ptrs[j] = (uint8_t *)wan->bufs + desc->addr;
		pkt_lens[j] = desc->len;
	}
	xsk_ring_cons__release(&wan->rx, rcvd);

	wan->rx_packets += (uint64_t)rcvd;
	for (int j = 0; j < rcvd; j++)
		wan->rx_bytes += pkt_lens[j];
	return rcvd;
}

void ne_wan_iface_recv_release(struct xsk_interface *wan, uint64_t *addrs, int count)
{
	if (!wan->xsk)
		return;

	for (int i = 0; i < count; i++) {
		uint32_t idx_fill;
		int r = xsk_ring_prod__reserve(&wan->fill, 1, &idx_fill);
		if (r != 1) {
			uint32_t comp_idx;
			int comp = xsk_ring_cons__peek(&wan->comp, wan->batch_size, &comp_idx);
			if (comp > 0)
				xsk_ring_cons__release(&wan->comp, comp);
			r = xsk_ring_prod__reserve(&wan->fill, 1, &idx_fill);
			if (r != 1)
				continue;
		}
		*xsk_ring_prod__fill_addr(&wan->fill, idx_fill) = (uint32_t)addrs[i];
		xsk_ring_prod__submit(&wan->fill, 1);
	}
}
