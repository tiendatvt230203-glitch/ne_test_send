#ifndef NE_PKT_RING_H
#define NE_PKT_RING_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>

struct ne_job {
	uint32_t slot;
	uint32_t len;
	uint32_t conn_id;
	uint8_t worker_idx;
	uint8_t part;
	uint8_t dir;
	uint8_t pad;
};

struct ne_ring {
	pthread_mutex_t mu;
	pthread_cond_t nonempty;
	pthread_cond_t nonfull;
	struct ne_job *buf;
	uint32_t cap;
	uint32_t head;
	uint32_t tail;
	uint32_t count;
};

int ne_ring_init(struct ne_ring *r, uint32_t cap);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_push(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop);
int ne_ring_try_push(struct ne_ring *r, const struct ne_job *j);
int ne_ring_pop(struct ne_ring *r, struct ne_job *j, volatile sig_atomic_t *stop);
int ne_ring_try_pop(struct ne_ring *r, struct ne_job *j);
void ne_ring_wake_all(struct ne_ring *r);

#endif
