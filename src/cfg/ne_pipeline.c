#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../../inc/ne_pipeline_core.h"
#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_defaults.h"
#include "../../inc/ne_meta.h"
#include "../../inc/ne_pipeline.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct ne_pipeline *g_pl;

static void pin_cpu(unsigned cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	(void)pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void wake_all_rings(struct ne_pipeline *pl)
{
	ne_ring_wake_all(&pl->ing_to_mid);
	ne_ring_wake_all(&pl->wan_to_mid);
	ne_ring_wake_all(&pl->w_to_wan);
	ne_ring_wake_all(&pl->w_to_client);
}

static void on_sig(int s)
{
	(void)s;
	if (g_pl)
		g_pl->stop = 1;
}

static void *thread_ingress(void *arg)
{
	struct ne_pipeline *pl = arg;
	pin_cpu(NE_CPU_INGRESS);

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!pl->stop) {
		ne_pl_ingress_tx_client(pl);

		int n = ne_afxdp_recv_ing(&pl->zc, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;

		for (int i = 0; i < n; i++) {
			struct ne_job job = {.umem_addr = addrs[i],
					     .len = lens[i],
					     .conn_id = 0,
					     .worker_idx = 0,
					     .part = 0,
					     .dir = NE_DIR_TO_WAN,
					     .pad = 0};
			if (ne_pl_ring_push_retry(&pl->ing_to_mid, &job, &pl->stop) != 0) {
				ne_afxdp_fq_return_ing(&pl->zc, addrs[i]);
				atomic_fetch_add_explicit(&pl->drops_ring_ingress, 1, memory_order_relaxed);
			}
		}
	}
	return NULL;
}

static void *thread_mid(void *arg)
{
	struct ne_pipeline *pl = arg;
	pin_cpu(NE_CPU_MID);

	while (!pl->stop) {
		struct ne_job j;
		if (ne_ring_try_pop(&pl->ing_to_mid, &j) == 0) {
			if (ne_pl_ring_push_retry(&pl->w_to_wan, &j, &pl->stop) != 0) {
				ne_afxdp_fq_return_ing(&pl->zc, j.umem_addr);
				atomic_fetch_add_explicit(&pl->drops_mid_wan, 1, memory_order_relaxed);
			}
			continue;
		}
		if (ne_ring_try_pop(&pl->wan_to_mid, &j) == 0) {
			if (ne_pl_ring_push_retry(&pl->w_to_client, &j, &pl->stop) != 0) {
				ne_afxdp_fq_return_wan(&pl->zc, j.umem_addr);
				atomic_fetch_add_explicit(&pl->drops_mid_cli, 1, memory_order_relaxed);
			}
			continue;
		}
		sched_yield();
	}
	return NULL;
}

static void *thread_wan(void *arg)
{
	struct ne_pipeline *pl = arg;
	pin_cpu(NE_CPU_WAN);

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!pl->stop) {
		ne_pl_wan_tx_wan(pl);

		int n = ne_afxdp_recv_wan(&pl->zc, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;

		for (int i = 0; i < n; i++) {
			struct ne_job job = {.umem_addr = addrs[i],
					     .len = lens[i],
					     .conn_id = 0,
					     .worker_idx = 0,
					     .part = 0,
					     .dir = NE_DIR_TO_CLIENT,
					     .pad = 0};
			if (ne_pl_ring_push_retry(&pl->wan_to_mid, &job, &pl->stop) != 0) {
				ne_afxdp_fq_return_wan(&pl->zc, addrs[i]);
				atomic_fetch_add_explicit(&pl->drops_ring_wan, 1, memory_order_relaxed);
			}
		}
	}
	return NULL;
}

static void destroy_mid_rings(struct ne_pipeline *pl, int have_ing_to_mid, int have_wan_to_mid)
{
	if (have_wan_to_mid)
		ne_ring_destroy(&pl->wan_to_mid);
	if (have_ing_to_mid)
		ne_ring_destroy(&pl->ing_to_mid);
}

static void destroy_merged_rings(struct ne_pipeline *pl, int have_w_to_wan, int have_w_to_cli)
{
	if (have_w_to_cli)
		ne_ring_destroy(&pl->w_to_client);
	if (have_w_to_wan)
		ne_ring_destroy(&pl->w_to_wan);
}

int ne_pipeline_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf,
		    const char *wan_bpf)
{
	struct ne_pipeline pl;
	memset(&pl, 0, sizeof(pl));

	int have_ing_to_mid = 0, have_wan_to_mid = 0;
	int have_w_to_wan = 0, have_w_to_cli = 0;

	if (ne_ring_init(&pl.ing_to_mid, NE_PIPELINE_RING_CAP) != 0)
		goto fail_rings;
	have_ing_to_mid = 1;
	if (ne_ring_init(&pl.wan_to_mid, NE_PIPELINE_RING_CAP) != 0)
		goto fail_rings;
	have_wan_to_mid = 1;

	if (ne_ring_init(&pl.w_to_wan, NE_PIPELINE_RING_CAP) != 0)
		goto fail_rings;
	have_w_to_wan = 1;
	if (ne_ring_init(&pl.w_to_client, NE_PIPELINE_RING_CAP) != 0)
		goto fail_rings;
	have_w_to_cli = 1;

	struct ne_afxdp_cfg zcfg = {0};
	strncpy(zcfg.ing_if, ingress_if, IF_NAMESIZE - 1);
	strncpy(zcfg.wan_if, wan_if, IF_NAMESIZE - 1);
	zcfg.umem_mb = NE_LOCAL_UMEM_MB;
	zcfg.ring_size = NE_LOCAL_RING;
	zcfg.batch_size = NE_LOCAL_BATCH;
	zcfg.frame_size = NE_LOCAL_FRAME;
	zcfg.bpf_ing = ingress_bpf;
	zcfg.bpf_wan = wan_bpf;

	if (ne_afxdp_pair_open(&pl.zc, &zcfg) != 0)
		goto fail_rings;

	g_pl = &pl;
	pl.stop = 0;
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	int ok_ing = 0, ok_mid = 0, ok_wan_th = 0;

	if (pthread_create(&pl.th_ingress, NULL, thread_ingress, &pl) != 0)
		goto fail_threads;
	ok_ing = 1;
	if (pthread_create(&pl.th_mid, NULL, thread_mid, &pl) != 0)
		goto fail_threads;
	ok_mid = 1;
	if (pthread_create(&pl.th_wan, NULL, thread_wan, &pl) != 0)
		goto fail_threads;
	ok_wan_th = 1;

	while (!pl.stop)
		pause();

	pl.stop = 1;
	wake_all_rings(&pl);
	pthread_join(pl.th_ingress, NULL);
	pthread_join(pl.th_mid, NULL);
	pthread_join(pl.th_wan, NULL);

	fprintf(stderr,
		"[ne-pipeline] ingress rx %" PRIu64 " b %" PRIu64 " tx %" PRIu64 " b %" PRIu64 "\n",
		pl.zc.ing.rx_packets, pl.zc.ing.rx_bytes, pl.zc.ing.tx_packets, pl.zc.ing.tx_bytes);
	fprintf(stderr, "[ne-pipeline] wan rx %" PRIu64 " b %" PRIu64 " tx %" PRIu64 " b %" PRIu64 "\n",
		pl.zc.wan.rx_packets, pl.zc.wan.rx_bytes, pl.zc.wan.tx_packets, pl.zc.wan.tx_bytes);
	fprintf(stderr,
		"[ne-pipeline] drops ring0->mid %" PRIu64 " ring11->mid %" PRIu64 " mid->wan %" PRIu64
		" mid->cli %" PRIu64 " wan_tx_fail %" PRIu64 " ing_tx_fail %" PRIu64 "\n",
		atomic_load_explicit(&pl.drops_ring_ingress, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_ring_wan, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_mid_wan, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_mid_cli, memory_order_relaxed),
		atomic_load_explicit(&pl.wan_tx_fail, memory_order_relaxed),
		atomic_load_explicit(&pl.ing_tx_fail, memory_order_relaxed));

	ne_afxdp_pair_close(&pl.zc);
	ne_ring_destroy(&pl.ing_to_mid);
	ne_ring_destroy(&pl.wan_to_mid);
	ne_ring_destroy(&pl.w_to_wan);
	ne_ring_destroy(&pl.w_to_client);
	g_pl = NULL;
	return 0;

fail_threads:
	pl.stop = 1;
	wake_all_rings(&pl);
	if (ok_ing)
		pthread_join(pl.th_ingress, NULL);
	if (ok_mid)
		pthread_join(pl.th_mid, NULL);
	if (ok_wan_th)
		pthread_join(pl.th_wan, NULL);
	ne_afxdp_pair_close(&pl.zc);
	g_pl = NULL;
fail_rings:
	destroy_merged_rings(&pl, have_w_to_wan, have_w_to_cli);
	destroy_mid_rings(&pl, have_ing_to_mid, have_wan_to_mid);
	return -1;
}
