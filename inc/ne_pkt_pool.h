#ifndef NE_PKT_POOL_H
#define NE_PKT_POOL_H

#include <pthread.h>
#include <stdint.h>

struct ne_pkt_pool {
	pthread_mutex_t mu;
	uint8_t *buf;
	uint32_t nslots;
	uint32_t slot_bytes;
	uint32_t *stack;
	uint32_t sn;
};

int ne_pool_init(struct ne_pkt_pool *p, uint32_t nslots, uint32_t slot_bytes);
void ne_pool_fini(struct ne_pkt_pool *p);
int ne_pool_acquire(struct ne_pkt_pool *p, uint32_t *slot_out);
void ne_pool_release(struct ne_pkt_pool *p, uint32_t slot);
uint8_t *ne_pool_at(struct ne_pkt_pool *p, uint32_t slot);

#endif
