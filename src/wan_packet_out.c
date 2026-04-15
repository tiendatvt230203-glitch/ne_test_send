#include "../inc/wan_packet_out.h"

int wan_packet_out_rr(struct ne_wan_tx wans[NE_WAN_COUNT], uint32_t *rr_idx, const void *pkt,
		      uint32_t len)
{
	uint32_t w = (*rr_idx)++ % NE_WAN_COUNT;
	return ne_wan_tx_send(&wans[w], pkt, len);
}
