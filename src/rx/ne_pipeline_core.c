#include "../../inc/ne_pipeline_core.h"
#include "../../inc/ne_flow.h"

#include <stdlib.h>
#include <time.h>

#include <xdp/xsk.h>

int ne_pl_ring_push_retry(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop)
{
	while (!*stop) {
		if (ne_ring_try_push(r, j) == 0)
			return 0;
		struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000L};
		nanosleep(&ts, NULL);
	}
	return -1;
}

void *ne_pl_job_pkt(struct ne_pipeline *pl, uint64_t umem_addr)
{
	return xsk_umem__get_data(pl->zc.bufs, xsk_umem__add_offset_to_addr(umem_addr));
}

uint8_t ne_pl_bind_worker(struct ne_pipeline *pl, uint32_t fh)
{
	struct ne_flow_slot *t = pl->flow_bind;
	if (!t)
		return ne_flow_worker_idx(fh);

	const uint32_t mask = NE_FLOW_BIND_CAP - 1u;
	uint32_t i = fh & mask;
	for (uint32_t probe = 0; probe < 64u && probe < NE_FLOW_BIND_CAP; probe++) {
		uint32_t s = (i + probe) & mask;
		if (!t[s].in_use) {
			uint8_t w = (uint8_t)(atomic_fetch_add_explicit(&pl->flow_bind_rr, 1u, memory_order_relaxed) %
					      NE_NUM_WORKERS);
			t[s].hash = fh;
			t[s].worker_idx = w;
			t[s].in_use = 1u;
			return w;
		}
		if (t[s].hash == fh)
			return t[s].worker_idx;
	}
	return ne_flow_worker_idx(fh);
}
