#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../../inc/ne_pipeline_core.h"
#include "../../inc/ne_defaults.h"
#include "../../inc/ne_flow.h"
#include "../../inc/ne_pipeline.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

_Static_assert(NE_NUM_WORKERS == 10, "ne_pipeline expects 10 worker cores");

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
	for (int i = 0; i < 10; i++) {
		ne_ring_wake_all(&pl->r0_to_w[i]);
		ne_ring_wake_all(&pl->r11_to_w[i]);
	}
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

		ne_pl_ingress_rx_workers(pl, n, ptrs, lens, addrs);
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

		ne_pl_wan_rx_workers(pl, n, ptrs, lens, addrs);
	}
	return NULL;
}

struct worker_arg {
	struct ne_pipeline *pl;
	int idx;
};

static void *thread_worker(void *arg)
{
	struct worker_arg *wa = arg;
	struct ne_pipeline *pl = wa->pl;
	int idx = wa->idx;
	pin_cpu(NE_CPU_WORKER_FIRST + (unsigned)idx);

	while (!pl->stop) {
		struct ne_job j;
		if (ne_ring_try_pop(&pl->r0_to_w[idx], &j) == 0) {
			if (j.len >= 14u + NE_WAN_FLOW_TAG_SIZE) {
				uint8_t *pkt = ne_pl_job_pkt(pl, j.umem_addr);
				uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
				if (et == NE_WAN_SENDER_ETHTYPE)
					ne_wan_flow_tag_pack(pkt + 14, j.conn_id, j.worker_idx);
			}
			if (ne_pl_ring_push_retry(&pl->w_to_wan, &j, &pl->stop) != 0) {
				ne_afxdp_fq_return_ing(&pl->zc, j.umem_addr);
				atomic_fetch_add_explicit(&pl->drops_worker_wan, 1, memory_order_relaxed);
			}
			continue;
		}
		if (ne_ring_try_pop(&pl->r11_to_w[idx], &j) == 0) {
			uint32_t out_len = ne_flow_strip_before_local_tx(ne_pl_job_pkt(pl, j.umem_addr), j.len);
			struct ne_job j2 = j;
			j2.len = out_len;
			if (ne_pl_ring_push_retry(&pl->w_to_client, &j2, &pl->stop) != 0) {
				ne_afxdp_fq_return_wan(&pl->zc, j.umem_addr);
				atomic_fetch_add_explicit(&pl->drops_worker_cli, 1, memory_order_relaxed);
			}
			continue;
		}
		sched_yield();
	}
	free(wa);
	return NULL;
}

static void destroy_worker_rings(struct ne_pipeline *pl, int pairs_ok)
{
	for (int j = 0; j < pairs_ok; j++) {
		ne_ring_destroy(&pl->r11_to_w[j]);
		ne_ring_destroy(&pl->r0_to_w[j]);
	}
}

static void destroy_merged_rings(struct ne_pipeline *pl, int have_w_to_wan, int have_w_to_cli)
{
	if (have_w_to_cli)
		ne_ring_destroy(&pl->w_to_client);
	if (have_w_to_wan)
		ne_ring_destroy(&pl->w_to_wan);
}

int ne_pipeline_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf,
		      const char *wan_bpf, int af_xdp_copy)
{
	struct ne_pipeline pl;
	memset(&pl, 0, sizeof(pl));

	int pairs_ok = 0;
	int have_w_to_wan = 0, have_w_to_cli = 0;

	for (int p = 0; p < 10; p++) {
		if (ne_ring_init(&pl.r0_to_w[p], NE_PIPELINE_RING_CAP) != 0)
			goto fail_rings;
		if (ne_ring_init(&pl.r11_to_w[p], NE_PIPELINE_RING_CAP) != 0) {
			ne_ring_destroy(&pl.r0_to_w[p]);
			goto fail_rings;
		}
		pairs_ok++;
	}

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
	zcfg.af_xdp_copy = af_xdp_copy;

	if (ne_afxdp_pair_open(&pl.zc, &zcfg) != 0)
		goto fail_rings;

	pl.flow_bind = calloc(NE_FLOW_BIND_CAP, sizeof(struct ne_flow_slot));
	if (!pl.flow_bind) {
		ne_afxdp_pair_close(&pl.zc);
		goto fail_rings;
	}

	g_pl = &pl;
	pl.stop = 0;
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	int ok_ing = 0, ok_wan_th = 0;
	int ok_wk[10] = {0};

	if (pthread_create(&pl.th_ingress, NULL, thread_ingress, &pl) != 0)
		goto fail_threads;
	ok_ing = 1;
	if (pthread_create(&pl.th_wan, NULL, thread_wan, &pl) != 0)
		goto fail_threads;
	ok_wan_th = 1;

	for (int i = 0; i < 10; i++) {
		struct worker_arg *wa = malloc(sizeof(*wa));
		if (!wa)
			goto fail_threads;
		wa->pl = &pl;
		wa->idx = i;
		if (pthread_create(&pl.th_worker[i], NULL, thread_worker, wa) != 0) {
			free(wa);
			goto fail_threads;
		}
		ok_wk[i] = 1;
	}

	while (!pl.stop)
		pause();

	pl.stop = 1;
	wake_all_rings(&pl);
	pthread_join(pl.th_ingress, NULL);
	pthread_join(pl.th_wan, NULL);
	for (int i = 0; i < 10; i++)
		pthread_join(pl.th_worker[i], NULL);

	fprintf(stderr,
		"[ne-pipeline] ingress rx %" PRIu64 " b %" PRIu64 " tx %" PRIu64 " b %" PRIu64 "\n",
		pl.zc.ing.rx_packets, pl.zc.ing.rx_bytes, pl.zc.ing.tx_packets, pl.zc.ing.tx_bytes);
	fprintf(stderr, "[ne-pipeline] wan rx %" PRIu64 " b %" PRIu64 " tx %" PRIu64 " b %" PRIu64 "\n",
		pl.zc.wan.rx_packets, pl.zc.wan.rx_bytes, pl.zc.wan.tx_packets, pl.zc.wan.tx_bytes);
	fprintf(stderr,
		"[ne-pipeline] drops ring0 %" PRIu64 " ring11 %" PRIu64 " wan_no_tag %" PRIu64
		" w_wan %" PRIu64 " w_cli %" PRIu64 " wan_tx_fail %" PRIu64 " ing_tx_fail %" PRIu64 "\n",
		atomic_load_explicit(&pl.drops_ring_ingress, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_ring_wan, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_wan_no_sender_tag, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_worker_wan, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_worker_cli, memory_order_relaxed),
		atomic_load_explicit(&pl.wan_tx_fail, memory_order_relaxed),
		atomic_load_explicit(&pl.ing_tx_fail, memory_order_relaxed));

	ne_afxdp_pair_close(&pl.zc);
	free(pl.flow_bind);
	pl.flow_bind = NULL;
	for (int i = 0; i < 10; i++) {
		ne_ring_destroy(&pl.r0_to_w[i]);
		ne_ring_destroy(&pl.r11_to_w[i]);
	}
	ne_ring_destroy(&pl.w_to_wan);
	ne_ring_destroy(&pl.w_to_client);
	g_pl = NULL;
	return 0;

fail_threads:
	pl.stop = 1;
	wake_all_rings(&pl);
	if (ok_ing)
		pthread_join(pl.th_ingress, NULL);
	if (ok_wan_th)
		pthread_join(pl.th_wan, NULL);
	for (int j = 0; j < 10; j++) {
		if (ok_wk[j])
			pthread_join(pl.th_worker[j], NULL);
	}
	ne_afxdp_pair_close(&pl.zc);
	free(pl.flow_bind);
	pl.flow_bind = NULL;
	g_pl = NULL;
fail_rings:
	destroy_merged_rings(&pl, have_w_to_wan, have_w_to_cli);
	destroy_worker_rings(&pl, pairs_ok);
	return -1;
}
