#include "../inc/ingress_afxdp.h"
#include "../inc/netdev_xdp_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>

int interface_init_local(struct xsk_interface *iface, const struct local_config *local_cfg,
			 const char *bpf_file)
{
	memset(iface, 0, sizeof(*iface));
	iface->ifindex = if_nametoindex(local_cfg->ifname);
	strncpy(iface->ifname, local_cfg->ifname, IF_NAMESIZE - 1);

	if (iface->ifindex == 0) {
		fprintf(stderr, "Interface %s not found\n", local_cfg->ifname);
		return -1;
	}

	const uint32_t qid = 0;
	iface_xdp_try_detach(iface->ifindex, iface->ifname);

	if (access(bpf_file, F_OK) != 0) {
		fprintf(stderr, "XDP object not found: %s\n", bpf_file);
		return -1;
	}

	struct bpf_object *bpf_obj = bpf_object__open_file(bpf_file, NULL);
	if (libbpf_get_error(bpf_obj)) {
		fprintf(stderr, "Failed to open %s\n", bpf_file);
		return -1;
	}

	if (bpf_object__load(bpf_obj)) {
		fprintf(stderr, "Failed to load BPF object\n");
		bpf_object__close(bpf_obj);
		return -1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, "xdp_redirect_prog");
	if (!prog) {
		fprintf(stderr, "XDP program not found\n");
		bpf_object__close(bpf_obj);
		return -1;
	}
	int prog_fd = bpf_program__fd(prog);

	struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
	if (!map) {
		fprintf(stderr, "xsks_map not found\n");
		bpf_object__close(bpf_obj);
		return -1;
	}
	int xsk_map_fd = bpf_map__fd(map);

	size_t local_umem_size = (size_t)local_cfg->umem_mb * 1024 * 1024;
	if (!iface_local_umem_ok(local_cfg->ifname, local_cfg, local_umem_size)) {
		bpf_object__close(bpf_obj);
		return -1;
	}

	iface->umem_size = local_umem_size;
	iface->ring_size = local_cfg->ring_size;
	iface->frame_size = local_cfg->frame_size;
	iface->batch_size = local_cfg->batch_size;

	struct xsk_umem_config umem_cfg = {
		.fill_size = local_cfg->ring_size,
		.comp_size = local_cfg->ring_size,
		.frame_size = local_cfg->frame_size,
		.frame_headroom = 0,
		.flags = 0,
	};

	struct xsk_socket_config sock_cfg = {
		.rx_size = local_cfg->ring_size,
		.tx_size = local_cfg->ring_size,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
	};

	int ret = posix_memalign(&iface->bufs, getpagesize(), local_umem_size);
	if (ret || !iface->bufs) {
		fprintf(stderr, "posix_memalign failed\n");
		bpf_object__close(bpf_obj);
		return -1;
	}
	mlock(iface->bufs, local_umem_size);

	ret = xsk_umem__create(&iface->umem, iface->bufs, local_umem_size, &iface->fill, &iface->comp,
			       &umem_cfg);
	if (ret) {
		fprintf(stderr, "xsk_umem__create failed: %d\n", ret);
		munlock(iface->bufs, local_umem_size);
		free(iface->bufs);
		iface->bufs = NULL;
		bpf_object__close(bpf_obj);
		return -1;
	}

	ret = xsk_socket__create(&iface->xsk, iface->ifname, qid, iface->umem, &iface->rx, &iface->tx,
				 &sock_cfg);
	if (ret) {
		fprintf(stderr, "xsk_socket__create (zero-copy) failed: %d (%s)\n", ret,
			ret < 0 ? strerror(-ret) : "non-negative error");
		xsk_umem__delete(iface->umem);
		munlock(iface->bufs, local_umem_size);
		free(iface->bufs);
		iface->bufs = NULL;
		iface->umem = NULL;
		bpf_object__close(bpf_obj);
		return -1;
	}

	int sock_fd = xsk_socket__fd(iface->xsk);
	if (bpf_map_update_elem(xsk_map_fd, &qid, &sock_fd, BPF_ANY)) {
		fprintf(stderr, "bpf_map_update_elem (xsks_map[%u]) failed\n", qid);
		xsk_socket__delete(iface->xsk);
		xsk_umem__delete(iface->umem);
		munlock(iface->bufs, local_umem_size);
		free(iface->bufs);
		iface->xsk = NULL;
		iface->umem = NULL;
		iface->bufs = NULL;
		bpf_object__close(bpf_obj);
		return -1;
	}

	uint32_t idx;
	ret = xsk_ring_prod__reserve(&iface->fill, local_cfg->ring_size, &idx);
	if (ret != (int)local_cfg->ring_size) {
		fprintf(stderr, "FILL reserve got %d, need %u\n", ret, local_cfg->ring_size);
		xsk_socket__delete(iface->xsk);
		xsk_umem__delete(iface->umem);
		munlock(iface->bufs, local_umem_size);
		free(iface->bufs);
		iface->xsk = NULL;
		iface->umem = NULL;
		iface->bufs = NULL;
		bpf_object__close(bpf_obj);
		return -1;
	}
	for (int i = 0; i < ret; i++)
		*xsk_ring_prod__fill_addr(&iface->fill, idx++) =
			(uint32_t)((unsigned)i * local_cfg->frame_size);
	xsk_ring_prod__submit(&iface->fill, ret);

	fprintf(stderr,
		"[umem] local if=%s rxq=%u bytes=%zu frame=%u ring=%u frames=%zu (single queue)\n",
		iface->ifname, qid, local_umem_size, local_cfg->frame_size, local_cfg->ring_size,
		local_umem_size / (size_t)local_cfg->frame_size);

	if (iface_xdp_attach(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE)) {
		fprintf(stderr, "XDP attach failed\n");
		xsk_socket__delete(iface->xsk);
		xsk_umem__delete(iface->umem);
		munlock(iface->bufs, iface->umem_size);
		free(iface->bufs);
		iface->xsk = NULL;
		iface->umem = NULL;
		iface->bufs = NULL;
		bpf_object__close(bpf_obj);
		return -1;
	}

	(void)bpf_obj;
	return 0;
}

void interface_cleanup(struct xsk_interface *iface)
{
	if (iface->ifindex)
		iface_xdp_try_detach(iface->ifindex, iface->ifname);

	if (iface->xsk)
		xsk_socket__delete(iface->xsk);
	if (iface->umem)
		xsk_umem__delete(iface->umem);
	if (iface->bufs) {
		munlock(iface->bufs, iface->umem_size);
		free(iface->bufs);
	}

	memset(iface, 0, sizeof(*iface));
}
