#include "../../inc/ne_pipeline_core.h"
#include "../../inc/ne_afxdp_pair.h"

#include <stdatomic.h>

void ne_pl_ingress_tx_client(struct ne_pipeline *pl)
{
	struct ne_job j;
	while (!pl->stop && ne_ring_try_pop(&pl->w_to_client, &j) == 0) {
		if (ne_afxdp_tx_ing(&pl->zc, j.umem_addr, j.len) != 0) {
			atomic_fetch_add_explicit(&pl->ing_tx_fail, 1, memory_order_relaxed);
			ne_afxdp_fq_return_wan(&pl->zc, j.umem_addr);
		}
	}
}

void ne_pl_wan_tx_wan(struct ne_pipeline *pl)
{
	struct ne_job j;
	while (!pl->stop && ne_ring_try_pop(&pl->w_to_wan, &j) == 0) {
		if (ne_afxdp_tx_wan(&pl->zc, j.umem_addr, j.len) != 0) {
			atomic_fetch_add_explicit(&pl->wan_tx_fail, 1, memory_order_relaxed);
			ne_afxdp_fq_return_ing(&pl->zc, j.umem_addr);
		}
	}
}
