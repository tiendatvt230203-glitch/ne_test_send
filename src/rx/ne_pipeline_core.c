#include "../../inc/ne_pipeline_core.h"

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
