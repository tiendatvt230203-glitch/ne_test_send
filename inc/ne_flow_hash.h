#ifndef NE_FLOW_HASH_H
#define NE_FLOW_HASH_H

#include <stdint.h>

uint32_t ne_flow_hash_ipv4(const uint8_t *pkt, uint32_t len);

#endif
