#include "../../inc/ne_flow.h"

#include <string.h>

_Static_assert(sizeof(struct ne_wan_flow_tag_wire) == NE_WAN_FLOW_TAG_SIZE, "wan tag");

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void ne_wan_flow_tag_pack(uint8_t out[NE_WAN_FLOW_TAG_SIZE], uint32_t conn_id, uint8_t worker_idx)
{
	put_be32(out + 0, NE_WAN_TAG_MAGIC);
	put_be32(out + 4, conn_id);
	out[8] = worker_idx;
	out[9] = (uint8_t)NE_WAN_FLOW_TAG_VERSION;
	out[10] = 0;
	out[11] = 0;
	put_be32(out + 12, 0u);
}

static uint32_t fnv1a32(uint32_t h, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
}

uint32_t ne_flow_hash_from_packet(const void *pkt, uint32_t len)
{
	const uint8_t *b = pkt;
	if (len < 14u)
		return fnv1a32(2166136261u, b, len);

	uint16_t et = ((uint16_t)b[12] << 8) | b[13];
	const uint8_t *nh = b + 14;
	uint32_t rest = len - 14u;

	if (et == 0x8100u) {
		if (rest < 4u)
			return fnv1a32(2166136261u, b, len);
		et = ((uint16_t)nh[2] << 8) | nh[3];
		nh += 4;
		rest -= 4u;
	}
	if (et != 0x0800u || rest < 20u)
		return fnv1a32(2166136261u, b, len < 64u ? len : 64u);

	const uint8_t *ip = nh;
	uint8_t ihl = (uint8_t)((ip[0] & 0x0fu) * 4u);
	if (ihl < 20u || rest < (uint32_t)ihl)
		return fnv1a32(2166136261u, b, len < 64u ? len : 64u);

	uint8_t proto = ip[9];
	uint32_t saddr = ((uint32_t)ip[12] << 24) | ((uint32_t)ip[13] << 16) | ((uint32_t)ip[14] << 8) |
			 (uint32_t)ip[15];
	uint32_t daddr = ((uint32_t)ip[16] << 24) | ((uint32_t)ip[17] << 16) | ((uint32_t)ip[18] << 8) |
			 (uint32_t)ip[19];

	uint16_t sport = 0, dport = 0;
	if (proto == 6u || proto == 17u) {
		if (rest < (uint32_t)ihl + 4u)
			goto ip_only;
		const uint8_t *l4 = nh + ihl;
		sport = ((uint16_t)l4[0] << 8) | l4[1];
		dport = ((uint16_t)l4[2] << 8) | l4[3];
	}

ip_only: {
	uint32_t a = saddr, b = daddr;
	uint16_t pa = sport, pb = dport;
	if (a > b || (a == b && pa > pb)) {
		uint32_t t = a;
		a = b;
		b = t;
		uint16_t tp = pa;
		pa = pb;
		pb = tp;
	}
	uint8_t mix[13];
	mix[0] = proto;
	memcpy(mix + 1, &a, 4);
	memcpy(mix + 5, &b, 4);
	memcpy(mix + 9, &pa, 2);
	memcpy(mix + 11, &pb, 2);
	return fnv1a32(2166136261u, mix, sizeof mix);
}
}

int ne_wan_route_from_sender_tag(const void *pkt, uint32_t len, uint32_t *conn_id_out,
				 uint8_t *worker_idx_out)
{
	const uint8_t *b = pkt;
	if (!b || len < 14u + NE_WAN_FLOW_TAG_SIZE)
		return -1;

	uint16_t et = ((uint16_t)b[12] << 8) | b[13];
	const uint8_t *pay = b + 14;
	uint32_t rest = len - 14u;

	if (et == 0x8100u) {
		if (rest < 4u + NE_WAN_FLOW_TAG_SIZE)
			return -1;
		et = ((uint16_t)pay[2] << 8) | pay[3];
		pay += 4;
		rest -= 4u;
	}

	if (et != NE_WAN_SENDER_ETHTYPE || rest < NE_WAN_FLOW_TAG_SIZE)
		return -1;

	uint32_t mag = get_be32(pay + 0);
	if (mag != NE_WAN_TAG_MAGIC)
		return -1;

	uint32_t cid = get_be32(pay + 4);
	uint8_t w = pay[8];
	uint8_t ver = pay[9];
	uint16_t flags = ((uint16_t)pay[10] << 8) | pay[11];

	if (ver != NE_WAN_FLOW_TAG_VERSION || w >= NE_NUM_WORKERS)
		return -1;
	(void)flags;

	*conn_id_out = cid;
	*worker_idx_out = w;
	return 0;
}

uint32_t ne_flow_strip_before_local_tx(void *pkt, uint32_t len)
{
	(void)pkt;
	return len;
}
