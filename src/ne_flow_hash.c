#include "../inc/ne_flow_hash.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static uint32_t fnv32(uint32_t h, uint32_t v)
{
	h ^= v;
	return h * 16777619u;
}

uint32_t ne_flow_hash_ipv4(const uint8_t *pkt, uint32_t len)
{
	if (len < sizeof(struct ethhdr))
		return 0;
	const struct ethhdr *eth = (const struct ethhdr *)pkt;
	uint16_t et = eth->h_proto;
	const uint8_t *l3 = pkt + sizeof(struct ethhdr);
	uint32_t l3_off = sizeof(struct ethhdr);

	if (et == htons(ETH_P_8021Q)) {
		if (len < l3_off + 4)
			return 0;
		const uint16_t *tp = (const uint16_t *)(pkt + l3_off + 2);
		et = *tp;
		l3_off += 4;
		l3 = pkt + l3_off;
	}

	if (et != htons(ETH_P_IP))
		return 0;
	if (len < l3_off + sizeof(struct iphdr))
		return 0;

	const struct iphdr *ip = (const struct iphdr *)l3;
	uint32_t ihl = (uint32_t)ip->ihl * 4u;
	if (ihl < sizeof(struct iphdr) || len < l3_off + ihl)
		return 0;

	uint8_t proto = ip->protocol;
	uint32_t sip = ip->saddr;
	uint32_t dip = ip->daddr;
	uint16_t sport = 0, dport = 0;

	if (proto == IPPROTO_TCP) {
		if (len < l3_off + ihl + sizeof(struct tcphdr))
			return 0;
		const struct tcphdr *tcp = (const struct tcphdr *)(pkt + l3_off + ihl);
		sport = tcp->source;
		dport = tcp->dest;
	} else if (proto == IPPROTO_UDP) {
		if (len < l3_off + ihl + sizeof(struct udphdr))
			return 0;
		const struct udphdr *udp = (const struct udphdr *)(pkt + l3_off + ihl);
		sport = udp->source;
		dport = udp->dest;
	} else {
		uint32_t h = 2166136261u;
		h = fnv32(h, sip);
		h = fnv32(h, dip);
		h = fnv32(h, (uint32_t)proto << 16 | (uint32_t)ntohs(ip->id));
		return h ? h : 1u;
	}

	uint32_t s0 = ntohl(sip);
	uint32_t d0 = ntohl(dip);
	uint16_t sp = ntohs(sport);
	uint16_t dp = ntohs(dport);
	if (s0 > d0 || (s0 == d0 && sp > dp)) {
		uint32_t t = s0;
		s0 = d0;
		d0 = t;
		uint16_t tp = sp;
		sp = dp;
		dp = tp;
	}

	uint32_t h = 2166136261u;
	h = fnv32(h, s0);
	h = fnv32(h, d0);
	h = fnv32(h, ((uint32_t)sp << 16) | (uint32_t)dp);
	h = fnv32(h, proto);
	return h ? h : 1u;
}
