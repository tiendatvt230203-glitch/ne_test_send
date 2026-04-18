#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_afxdp_zc_i.h"
#include "../../inc/netdev_xdp_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

static int xdp_attach_try(int ifindex, int prog_fd, const char *ifn)
{
	if (iface_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE) == 0) {
		fprintf(stderr, "[ne] %s: XDP native (DRV)\n", ifn);
		return 0;
	}
	if (iface_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) == 0) {
		fprintf(stderr, "[ne] %s: XDP generic (SKB), AF_XDP copy mode\n", ifn);
		return 0;
	}
	return -1;
}

static int load_sock_map_and_attach(struct bpf_object **out_obj_ptr, const char *bpf_path,
				    const char *prog_name, const char *map_name, int ifindex,
				    const char *ifname, int sock_fd, uint32_t qid)
{
	if (access(bpf_path, F_OK) != 0) {
		fprintf(stderr, "[ne] BPF not found: %s\n", bpf_path);
		return -1;
	}
	struct bpf_object *obj = bpf_object__open_file(bpf_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "[ne] open %s failed\n", bpf_path);
		return -1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "[ne] load %s failed\n", bpf_path);
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

	strncpy(p->ing.ifname, cfg->ing_if, IF_NAMESIZE - 1);
	strncpy(p->wan.ifname, cfg->wan_if, IF_NAMESIZE - 1);
	p->ing.ifindex = if_nametoindex(cfg->ing_if);
	p->wan.ifindex = if_nametoindex(cfg->wan_if);
	if (p->ing.ifindex == 0 || p->wan.ifindex == 0) {
		fprintf(stderr, "[ne] bad ifindex\n");
		return -1;
	}

	struct local_config lc = {0};
	lc.umem_mb = cfg->umem_mb;
	lc.ring_size = cfg->ring_size;
	lc.batch_size = cfg->batch_size;
	lc.frame_size = cfg->frame_size;
	strncpy(lc.ifname, cfg->ing_if, IF_NAMESIZE - 1);

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

	unsigned int xbind = XDP_USE_NEED_WAKEUP;
	if (cfg->af_xdp_copy)
		xbind |= XDP_COPY;
	else
		xbind |= XDP_ZEROCOPY;

	struct xsk_socket_config sock_cfg = {
		.rx_size = cfg->ring_size,
		.tx_size = cfg->ring_size,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = xbind,
	};

	int r = xsk_socket__create_shared(&p->ing.xsk, cfg->ing_if, 0, p->umem, &p->ing.rx, &p->ing.tx,
					  &p->ing.fq, &p->ing.cq, &sock_cfg);
	if (r) {
		fprintf(stderr, "[ne] xsk_socket__create_shared ingress: %d (%s)\n", r,
			r < 0 ? strerror(-r) : "");
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
		fprintf(stderr, "[ne] xsk_socket__create_shared wan: %d (%s)\n", r,
			r < 0 ? strerror(-r) : "");
		xsk_socket__delete(p->ing.xsk);
		p->ing.xsk = NULL;
		xsk_umem__delete(p->umem);
		p->umem = NULL;
		munlock(p->bufs, p->bufsize);
		free(p->bufs);
		p->bufs = NULL;
		return -1;
	}

	if (pthread_mutex_init(&p->ing_fq_lock, NULL) != 0) {
		fprintf(stderr, "[ne] ing_fq_lock init failed\n");
		goto err_sock;
	}
	if (pthread_mutex_init(&p->wan_fq_lock, NULL) != 0) {
		fprintf(stderr, "[ne] wan_fq_lock init failed\n");
		(void)pthread_mutex_destroy(&p->ing_fq_lock);
		goto err_sock;
	}
	p->fq_locks_inited = 1;

	if (pthread_mutex_init(&p->pool_lock, NULL) != 0) {
		fprintf(stderr, "[ne] pool mutex init failed\n");
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

	int wan_fd = xsk_socket__fd(p->wan.xsk);
	if (load_sock_map_and_attach(&p->bpf_wan, cfg->bpf_wan, "xdp_wan_redirect_prog", "wan_xsks_map",
				     p->wan.ifindex, p->wan.ifname, wan_fd, 0)) {
		iface_xdp_try_detach(p->ing.ifindex, p->ing.ifname);
		bpf_object__close(p->bpf_ing);
		p->bpf_ing = NULL;
		goto err_bpf_ing;
	}

	fprintf(stderr, "[ne] shared UMEM AF_XDP %s ingress=%s wan=%s\n",
		cfg->af_xdp_copy ? "COPY (test)" : "ZC", cfg->ing_if, cfg->wan_if);
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
	iface_xdp_try_detach(p->wan.ifindex, p->wan.ifname);
	if (p->bpf_wan) {
		bpf_object__close(p->bpf_wan);
		p->bpf_wan = NULL;
	}
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
