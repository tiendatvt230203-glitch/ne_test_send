#ifndef INGRESS_AFXDP_H
#define INGRESS_AFXDP_H

#include "common.h"

struct local_config {
	char ifname[IF_NAMESIZE];
	uint32_t umem_mb;
	uint32_t ring_size;
	uint32_t batch_size;
	uint32_t frame_size;
};

struct xsk_interface {
	size_t umem_size;
	uint32_t ring_size;
	uint32_t frame_size;
	uint32_t batch_size;

	struct xsk_socket *xsk;
	struct xsk_umem *umem;
	void *bufs;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;

	int ifindex;
	char ifname[IF_NAMESIZE];

	uint64_t rx_packets;
	uint64_t rx_bytes;
};

int interface_init_local(struct xsk_interface *iface, const struct local_config *local_cfg,
			 const char *bpf_file);

void interface_cleanup(struct xsk_interface *iface);

int interface_recv(struct xsk_interface *iface, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		   int max_pkts);

void interface_recv_release(struct xsk_interface *iface, uint64_t *addrs, int count);

#endif
