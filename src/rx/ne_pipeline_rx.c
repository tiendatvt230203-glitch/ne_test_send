#include "../../inc/ne_pipeline_core.h"
#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_flow.h"
#include <stdatomic.h>

void ne_pl_ingress_rx_workers(struct ne_pipeline *pl, int n, void **ptrs, uint32_t *lens, uint64_t *addrs)
{
	for (int i = 0; i < n; i++) {
		uint32_t fh = ne_flow_hash_from_packet(ptrs[i], lens[i]);
		uint8_t widx = ne_pl_bind_worker(pl, fh);

		struct ne_job job = {.umem_addr = addrs[i],
				     .len = lens[i],
				     .conn_id = fh,
				     .worker_idx = widx,
				     .part = 0,
				     .dir = NE_DIR_TO_WAN,
				     .pad = 0};
		if (ne_pl_ring_push_retry(&pl->r0_to_w[widx], &job, &pl->stop) != 0) {
			ne_afxdp_fq_return_ing(&pl->zc, addrs[i]);
			atomic_fetch_add_explicit(&pl->drops_ring_ingress, 1, memory_order_relaxed);
		}
	}
}

void ne_pl_wan_rx_workers(struct ne_pipeline *pl, int n, void **ptrs, uint32_t *lens, uint64_t *addrs)
{
	for (int i = 0; i < n; i++) {
		uint32_t cid = 0;
		uint8_t widx = 0;
		if (ne_wan_route_from_sender_tag(ptrs[i], lens[i], &cid, &widx) != 0) {
			ne_afxdp_fq_return_wan(&pl->zc, addrs[i]);
			atomic_fetch_add_explicit(&pl->drops_wan_no_sender_tag, 1, memory_order_relaxed);
			continue;
		}

		struct ne_job job = {.umem_addr = addrs[i],
				     .len = lens[i],
				     .conn_id = cid,
				     .worker_idx = widx,
				     .part = 0,
				     .dir = NE_DIR_TO_CLIENT,
				     .pad = 0};
		if (ne_pl_ring_push_retry(&pl->r11_to_w[widx], &job, &pl->stop) != 0) {
			ne_afxdp_fq_return_wan(&pl->zc, addrs[i]);
			atomic_fetch_add_explicit(&pl->drops_ring_wan, 1, memory_order_relaxed);
		}
	}
}
