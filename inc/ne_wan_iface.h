#ifndef NE_WAN_IFACE_H
#define NE_WAN_IFACE_H

#include "ingress_afxdp.h"

int ne_wan_iface_open(struct xsk_interface *wan, const struct local_config *lc, const char *bpf_file);
void ne_wan_iface_close(struct xsk_interface *wan);

int ne_wan_iface_send(struct xsk_interface *wan, const void *pkt, uint32_t len);
int ne_wan_iface_recv(struct xsk_interface *wan, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		      int max_pkts);
void ne_wan_iface_recv_release(struct xsk_interface *wan, uint64_t *addrs, int count);

#endif
