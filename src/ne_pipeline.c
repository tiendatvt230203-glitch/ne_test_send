#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../inc/ne_defaults.h"
#include "../inc/ne_flow_hash.h"
#include "../inc/ne_meta.h"
#include "../inc/ne_pkt_pool.h"
#include "../inc/ne_pkt_ring.h"
#include "../inc/ne_pipeline.h"
#include "../inc/ne_wan_iface.h"
#include "../inc/ingress_afxdp.h"
#include "../inc/wan_afxdp.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

_Static_assert(NE_NUM_WORKERS == 10, "ne_pipeline expects 10 worker cores");

struct ne_pipeline {
	volatile sig_atomic_t stop;
	struct xsk_interface ingress;
	struct xsk_interface wan;
	struct ne_pkt_pool pool;
	struct ne_ring r0_to_w[10];
	struct ne_ring r11_to_w[10];
	struct ne_ring w_to_wan;
	struct ne_ring w_to_client;

	pthread_t th_ingress;
	pthread_t th_wan;
	pthread_t th_worker[10];

	_Atomic uint64_t drops_no_slot;
	_Atomic uint64_t drops_ring_ingress;
	_Atomic uint64_t drops_ring_wan;
	_Atomic uint64_t drops_worker_wan;
	_Atomic uint64_t drops_worker_cli;
	_Atomic uint64_t wan_tx_fail;
};

static struct ne_pipeline *g_pl;

static void pin_cpu(unsigned cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	(void)pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static int push_retry(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop)
{
	while (!*stop) {
		if (ne_ring_try_push(r, j) == 0)
			return 0;
		struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000L};
		nanosleep(&ts, NULL);
	}
	return -1;
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
		struct ne_job j;
		while (!pl->stop && ne_ring_try_pop(&pl->w_to_client, &j) == 0) {
			uint8_t *data = ne_pool_at(&pl->pool, j.slot);
			if (data)
				(void)interface_send(&pl->ingress, data, j.len);
			ne_pool_release(&pl->pool, j.slot);
		}

		int n = interface_recv(&pl->ingress, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;

		for (int i = 0; i < n; i++) {
			uint32_t slot;
			if (ne_pool_acquire(&pl->pool, &slot) != 0) {
				atomic_fetch_add_explicit(&pl->drops_no_slot, (uint64_t)(n - i),
							  memory_order_relaxed);
				interface_recv_release(&pl->ingress, &addrs[i], n - i);
				break;
			}
			uint8_t *dst = ne_pool_at(&pl->pool, slot);
			memcpy(dst, ptrs[i], lens[i]);
			interface_recv_release(&pl->ingress, &addrs[i], 1);

			uint32_t h = ne_flow_hash_ipv4(dst, lens[i]);
			uint32_t cid = h ? h : 1u;
			uint8_t widx = (uint8_t)(cid % NE_NUM_WORKERS);

			struct ne_job job = {.slot = slot,
					     .len = lens[i],
					     .conn_id = cid,
					     .worker_idx = widx,
					     .part = 0,
					     .dir = NE_DIR_TO_WAN,
					     .pad = 0};
			if (push_retry(&pl->r0_to_w[widx], &job, &pl->stop) != 0) {
				ne_pool_release(&pl->pool, slot);
				atomic_fetch_add_explicit(&pl->drops_ring_ingress, 1, memory_order_relaxed);
			}
		}
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
		struct ne_job j;
		while (!pl->stop && ne_ring_try_pop(&pl->w_to_wan, &j) == 0) {
			uint8_t *d = ne_pool_at(&pl->pool, j.slot);
			if (d && ne_wan_iface_send(&pl->wan, d, j.len) != 0)
				atomic_fetch_add_explicit(&pl->wan_tx_fail, 1, memory_order_relaxed);
			ne_pool_release(&pl->pool, j.slot);
		}

		int n = ne_wan_iface_recv(&pl->wan, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;

		for (int i = 0; i < n; i++) {
			uint32_t slot;
			if (ne_pool_acquire(&pl->pool, &slot) != 0) {
				atomic_fetch_add_explicit(&pl->drops_no_slot, (uint64_t)(n - i),
							  memory_order_relaxed);
				ne_wan_iface_recv_release(&pl->wan, &addrs[i], n - i);
				break;
			}
			uint8_t *dst = ne_pool_at(&pl->pool, slot);
			memcpy(dst, ptrs[i], lens[i]);
			ne_wan_iface_recv_release(&pl->wan, &addrs[i], 1);

			uint32_t h = ne_flow_hash_ipv4(dst, lens[i]);
			uint32_t cid = h ? h : 1u;
			uint8_t widx = (uint8_t)(cid % NE_NUM_WORKERS);

			struct ne_job job = {.slot = slot,
					     .len = lens[i],
					     .conn_id = cid,
					     .worker_idx = widx,
					     .part = 0,
					     .dir = NE_DIR_TO_CLIENT,
					     .pad = 0};
			if (push_retry(&pl->r11_to_w[widx], &job, &pl->stop) != 0) {
				ne_pool_release(&pl->pool, slot);
				atomic_fetch_add_explicit(&pl->drops_ring_wan, 1, memory_order_relaxed);
			}
		}
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
			if (push_retry(&pl->w_to_wan, &j, &pl->stop) != 0) {
				ne_pool_release(&pl->pool, j.slot);
				atomic_fetch_add_explicit(&pl->drops_worker_wan, 1, memory_order_relaxed);
			}
			continue;
		}
		if (ne_ring_try_pop(&pl->r11_to_w[idx], &j) == 0) {
			if (push_retry(&pl->w_to_client, &j, &pl->stop) != 0) {
				ne_pool_release(&pl->pool, j.slot);
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
		    const char *wan_bpf)
{
	struct ne_pipeline pl;
	memset(&pl, 0, sizeof(pl));

	int pairs_ok = 0;
	int have_w_to_wan = 0, have_w_to_cli = 0;
	int have_pool = 0;

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

	if (ne_pool_init(&pl.pool, NE_PIPELINE_POOL_SLOTS, NE_LOCAL_FRAME) != 0)
		goto fail_rings;
	have_pool = 1;

	struct local_config cfg = {0};
	cfg.umem_mb = NE_LOCAL_UMEM_MB;
	cfg.ring_size = NE_LOCAL_RING;
	cfg.batch_size = NE_LOCAL_BATCH;
	cfg.frame_size = NE_LOCAL_FRAME;
	strncpy(cfg.ifname, ingress_if, IF_NAMESIZE - 1);

	if (interface_init_local(&pl.ingress, &cfg, ingress_bpf) != 0)
		goto fail_pool;
	if (ingress_tx_pool_init(&pl.ingress) != 0) {
		interface_cleanup(&pl.ingress);
		goto fail_pool;
	}

	strncpy(cfg.ifname, wan_if, IF_NAMESIZE - 1);
	if (ne_wan_iface_open(&pl.wan, &cfg, wan_bpf) != 0) {
		ingress_tx_pool_fini(&pl.ingress);
		interface_cleanup(&pl.ingress);
		goto fail_pool;
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
		pl.ingress.rx_packets, pl.ingress.rx_bytes, pl.ingress.tx_packets, pl.ingress.tx_bytes);
	fprintf(stderr, "[ne-pipeline] wan rx %" PRIu64 " b %" PRIu64 " tx %" PRIu64 " b %" PRIu64 "\n",
		pl.wan.rx_packets, pl.wan.rx_bytes, pl.wan.tx_packets, pl.wan.tx_bytes);
	fprintf(stderr,
		"[ne-pipeline] drops: no_slot %" PRIu64 " ring0 %" PRIu64 " ring11 %" PRIu64
		" w_wan %" PRIu64 " w_cli %" PRIu64 " wan_tx_fail %" PRIu64 "\n",
		atomic_load_explicit(&pl.drops_no_slot, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_ring_ingress, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_ring_wan, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_worker_wan, memory_order_relaxed),
		atomic_load_explicit(&pl.drops_worker_cli, memory_order_relaxed),
		atomic_load_explicit(&pl.wan_tx_fail, memory_order_relaxed));

	ne_wan_iface_close(&pl.wan);
	ingress_tx_pool_fini(&pl.ingress);
	interface_cleanup(&pl.ingress);
	ne_pool_fini(&pl.pool);
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
	ne_wan_iface_close(&pl.wan);
	ingress_tx_pool_fini(&pl.ingress);
	interface_cleanup(&pl.ingress);
	g_pl = NULL;
fail_pool:
	if (have_pool)
		ne_pool_fini(&pl.pool);
fail_rings:
	destroy_merged_rings(&pl, have_w_to_wan, have_w_to_cli);
	destroy_worker_rings(&pl, pairs_ok);
	return -1;
}
