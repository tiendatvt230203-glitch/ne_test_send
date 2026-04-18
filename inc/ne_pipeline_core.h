#ifndef NE_PIPELINE_CORE_H
#define NE_PIPELINE_CORE_H

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>

#include "ne_afxdp_pair.h"
#include "ne_pkt_ring.h"

struct ne_pipeline {
	volatile sig_atomic_t stop;
	struct ne_afxdp_pair zc;
	struct ne_ring ing_to_mid;
	struct ne_ring wan_to_mid;
	struct ne_ring w_to_wan;
	struct ne_ring w_to_client;

	pthread_t th_ingress;
	pthread_t th_mid;
	pthread_t th_wan;

	_Atomic uint64_t drops_ring_ingress;
	_Atomic uint64_t drops_ring_wan;
	_Atomic uint64_t drops_mid_wan;
	_Atomic uint64_t drops_mid_cli;
	_Atomic uint64_t wan_tx_fail;
	_Atomic uint64_t ing_tx_fail;
};

int ne_pl_ring_push_retry(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop);
void *ne_pl_job_pkt(struct ne_pipeline *pl, uint64_t umem_addr);

void ne_pl_ingress_tx_client(struct ne_pipeline *pl);
void ne_pl_wan_tx_wan(struct ne_pipeline *pl);

#endif
