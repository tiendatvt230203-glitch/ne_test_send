#ifndef WAN_AFXDP_H
#define WAN_AFXDP_H

#include "ingress_afxdp.h"

#define NE_WAN_COUNT 3
#define NE_CPU_RX 0
#define NE_CPU_TX 11
#define NE_CPU_WORKER_LO 2
#define NE_CPU_WORKER_HI 9

struct ne_wan_tx {
	char ifname[IF_NAMESIZE];
	int ifindex;
	size_t umem_size;
	uint32_t ring_size;
	uint32_t frame_size;

	struct xsk_socket *xsk;
	struct xsk_umem *umem;
	void *bufs;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;

	uint64_t *free_pool;
	uint32_t free_n;
	uint32_t frame_cap;

	uint64_t tx_pkts;
	uint64_t tx_bytes;
};

int ne_wan_tx_open(struct ne_wan_tx *w, const char *ifname, uint32_t ring_size, uint32_t frame_size,
		   uint32_t umem_mb);
void ne_wan_tx_close(struct ne_wan_tx *w);
int ne_wan_tx_send(struct ne_wan_tx *w, const void *pkt, uint32_t len);

#endif
