#ifndef NE_PIPELINE_CORE_H
#define NE_PIPELINE_CORE_H

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>

#include "ne_afxdp_pair.h"
#include "ne_meta.h"
#include "ne_pkt_ring.h"

#define NE_FLOW_BIND_CAP (1024u)

struct ne_flow_slot {
	uint32_t hash;
	uint8_t worker_idx;
	uint8_t in_use;
};

struct ne_pipeline {
	volatile sig_atomic_t stop;
	struct ne_afxdp_pair zc;
	struct ne_flow_slot *flow_bind;
	_Atomic uint32_t flow_bind_rr;
	struct ne_ring r0_to_w[10];
	struct ne_ring r11_to_w[10];
	struct ne_ring w_to_wan;
	struct ne_ring w_to_client;

	pthread_t th_ingress;
	pthread_t th_wan;
	pthread_t th_worker[10];

	_Atomic uint64_t drops_ring_ingress;
	_Atomic uint64_t drops_ring_wan;
	_Atomic uint64_t drops_wan_no_sender_tag;
	_Atomic uint64_t drops_worker_wan;
	_Atomic uint64_t drops_worker_cli;
	_Atomic uint64_t wan_tx_fail;
	_Atomic uint64_t ing_tx_fail;
};

int ne_pl_ring_push_retry(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop);
void *ne_pl_job_pkt(struct ne_pipeline *pl, uint64_t umem_addr);
uint8_t ne_pl_bind_worker(struct ne_pipeline *pl, uint32_t fh);

void ne_pl_ingress_tx_client(struct ne_pipeline *pl);
void ne_pl_ingress_rx_workers(struct ne_pipeline *pl, int n, void **ptrs, uint32_t *lens, uint64_t *addrs);
void ne_pl_wan_tx_wan(struct ne_pipeline *pl);
void ne_pl_wan_rx_workers(struct ne_pipeline *pl, int n, void **ptrs, uint32_t *lens, uint64_t *addrs);

#endif
