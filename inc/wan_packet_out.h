#ifndef WAN_PACKET_OUT_H
#define WAN_PACKET_OUT_H

#include "wan_afxdp.h"

int wan_packet_out_rr(struct ne_wan_tx wans[NE_WAN_COUNT], uint32_t *rr_idx, const void *pkt,
		      uint32_t len);

#endif
