#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "zc.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string.h>

static const uint8_t MAC_SRC[6] = {0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xcf};
static const uint8_t MAC_DST[6] = {0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4d};

static uint16_t ipv4_checksum(const uint8_t *hdr, size_t hlen)
{
	uint32_t s = 0;
	for (size_t i = 0; i + 1 < hlen; i += 2)
		s += ((uint32_t)hdr[i] << 8) | hdr[i + 1];
	if (hlen & 1)
		s += (uint32_t)hdr[hlen - 1] << 8;
	while (s >> 16)
		s = (s & 0xffffu) + (s >> 16);
	return (uint16_t)~s;
}

void zc_build_pkt(void *pkt, uint32_t len)
{
	if (len < MIN_ETH_LEN)
		len = MIN_ETH_LEN;
	memset(pkt, 0, len);
	uint8_t *e = pkt;
	memcpy(e, MAC_DST, 6);
	memcpy(e + 6, MAC_SRC, 6);
	*(uint16_t *)(e + 12) = htons(ETH_P_IP);

	uint8_t *ip = e + 14;
	ip[0] = 0x45;
	ip[1] = 0;
	*(uint16_t *)(ip + 2) = htons(IP_UDP_BYTES);
	*(uint16_t *)(ip + 4) = htons(1);
	*(uint16_t *)(ip + 6) = 0;
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	*(uint16_t *)(ip + 10) = 0;
	*(uint32_t *)(ip + 12) = htonl((192u << 24) | (168u << 16) | (9u << 8) | 1u);
	*(uint32_t *)(ip + 16) = htonl((192u << 24) | (168u << 16) | (10u << 8) | 1u);
	uint16_t c = ipv4_checksum(ip, 20);
	ip[10] = (uint8_t)(c >> 8);
	ip[11] = (uint8_t)c;

	uint8_t *udp = ip + 20;
	*(uint16_t *)(udp + 0) = htons(12345);
	*(uint16_t *)(udp + 2) = htons(23456);
	*(uint16_t *)(udp + 4) = htons(8);
	*(uint16_t *)(udp + 6) = 0;
}
