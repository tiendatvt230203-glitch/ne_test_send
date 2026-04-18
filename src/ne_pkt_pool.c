#include "../inc/ne_pkt_pool.h"

#include <stdlib.h>
#include <string.h>

int ne_pool_init(struct ne_pkt_pool *p, uint32_t nslots, uint32_t slot_bytes)
{
	memset(p, 0, sizeof(*p));
	if (nslots == 0 || slot_bytes == 0 || nslots > 65536u)
		return -1;
	p->buf = calloc((size_t)nslots * slot_bytes, 1u);
	p->stack = calloc(nslots, sizeof(uint32_t));
	if (!p->buf || !p->stack) {
		free(p->buf);
		free(p->stack);
		memset(p, 0, sizeof(*p));
		return -1;
	}
	p->nslots = nslots;
	p->slot_bytes = slot_bytes;
	p->sn = nslots;
	for (uint32_t i = 0; i < nslots; i++)
		p->stack[i] = nslots - 1u - i;
	pthread_mutex_init(&p->mu, NULL);
	return 0;
}

void ne_pool_fini(struct ne_pkt_pool *p)
{
	if (!p)
		return;
	free(p->buf);
	free(p->stack);
	pthread_mutex_destroy(&p->mu);
	memset(p, 0, sizeof(*p));
}

int ne_pool_acquire(struct ne_pkt_pool *p, uint32_t *slot_out)
{
	pthread_mutex_lock(&p->mu);
	if (p->sn == 0) {
		pthread_mutex_unlock(&p->mu);
		return -1;
	}
	uint32_t s = p->stack[--p->sn];
	pthread_mutex_unlock(&p->mu);
	*slot_out = s;
	return 0;
}

void ne_pool_release(struct ne_pkt_pool *p, uint32_t slot)
{
	if (slot >= p->nslots)
		return;
	pthread_mutex_lock(&p->mu);
	if (p->sn < p->nslots)
		p->stack[p->sn++] = slot;
	pthread_mutex_unlock(&p->mu);
}

uint8_t *ne_pool_at(struct ne_pkt_pool *p, uint32_t slot)
{
	if (slot >= p->nslots)
		return NULL;
	return p->buf + (size_t)slot * p->slot_bytes;
}
