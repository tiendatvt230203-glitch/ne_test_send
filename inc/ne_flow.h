#ifndef NE_FLOW_H
#define NE_FLOW_H

#include "ne_meta.h"
#include <stdint.h>

#define NE_WAN_SENDER_ETHTYPE 0x88B5u
#define NE_WAN_TAG_MAGIC 0x4E453031u
#define NE_WAN_FLOW_TAG_VERSION 1u
#define NE_WAN_FLOW_TAG_SIZE 16u

struct ne_wan_flow_tag_wire {
	uint32_t magic_be;
	uint32_t conn_id_be;
	uint8_t worker_idx;
	uint8_t version;
	uint16_t flags_be;
	uint32_t cookie_be;
} __attribute__((packed));

uint32_t ne_flow_hash_from_packet(const void *pkt, uint32_t len);

static inline uint8_t ne_flow_worker_idx(uint32_t flow_hash)
{
	return (uint8_t)(flow_hash % NE_NUM_WORKERS);
}

void ne_wan_flow_tag_pack(uint8_t out[NE_WAN_FLOW_TAG_SIZE], uint32_t conn_id, uint8_t worker_idx);

int ne_wan_route_from_sender_tag(const void *pkt, uint32_t len, uint32_t *conn_id_out,
				 uint8_t *worker_idx_out);

uint32_t ne_flow_strip_before_local_tx(void *pkt, uint32_t len);

#endif
