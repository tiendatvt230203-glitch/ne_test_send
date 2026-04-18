#include "../../inc/ne_pkt_ring.h"
#include <stdlib.h>
#include <string.h>

int ne_ring_init(struct ne_ring *r, uint32_t cap)
{
	memset(r, 0, sizeof(*r));
	if (cap == 0 || cap > 65536)
		return -1;
	r->buf = calloc(cap, sizeof(struct ne_job));
	if (!r->buf)
		return -1;
	r->cap = cap;
	pthread_mutex_init(&r->mu, NULL);
	pthread_cond_init(&r->nonempty, NULL);
	pthread_cond_init(&r->nonfull, NULL);
	return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
	if (!r)
		return;
	free(r->buf);
	r->buf = NULL;
	pthread_cond_destroy(&r->nonfull);
	pthread_cond_destroy(&r->nonempty);
	pthread_mutex_destroy(&r->mu);
	memset(r, 0, sizeof(*r));
}

int ne_ring_push(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop)
{
	pthread_mutex_lock(&r->mu);
	while (r->count == r->cap && (!stop || !*stop))
		pthread_cond_wait(&r->nonfull, &r->mu);
	if (r->count == r->cap) {
		pthread_mutex_unlock(&r->mu);
		return -1;
	}
	r->buf[r->tail] = *j;
	r->tail = (r->tail + 1) % r->cap;
	r->count++;
	pthread_cond_signal(&r->nonempty);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

int ne_ring_try_push(struct ne_ring *r, const struct ne_job *j)
{
	pthread_mutex_lock(&r->mu);
	if (r->count == r->cap) {
		pthread_mutex_unlock(&r->mu);
		return -1;
	}
	r->buf[r->tail] = *j;
	r->tail = (r->tail + 1) % r->cap;
	r->count++;
	pthread_cond_signal(&r->nonempty);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

int ne_ring_pop(struct ne_ring *r, struct ne_job *j, volatile sig_atomic_t *stop)
{
	pthread_mutex_lock(&r->mu);
	while (r->count == 0 && (!stop || !*stop))
		pthread_cond_wait(&r->nonempty, &r->mu);
	if (r->count == 0) {
		pthread_mutex_unlock(&r->mu);
		return -1;
	}
	*j = r->buf[r->head];
	r->head = (r->head + 1) % r->cap;
	r->count--;
	pthread_cond_signal(&r->nonfull);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

int ne_ring_try_pop(struct ne_ring *r, struct ne_job *j)
{
	pthread_mutex_lock(&r->mu);
	if (r->count == 0) {
		pthread_mutex_unlock(&r->mu);
		return -1;
	}
	*j = r->buf[r->head];
	r->head = (r->head + 1) % r->cap;
	r->count--;
	pthread_cond_signal(&r->nonfull);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

void ne_ring_wake_all(struct ne_ring *r)
{
	if (!r)
		return;
	pthread_mutex_lock(&r->mu);
	pthread_cond_broadcast(&r->nonempty);
	pthread_cond_broadcast(&r->nonfull);
	pthread_mutex_unlock(&r->mu);
}
