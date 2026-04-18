#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ne.h"

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int ne_ring_init(struct ne_ring *r, uint32_t cap)
{
	memset(r, 0, sizeof(*r));
	if (cap == 0 || cap > 65536)
		return -1;
	r->buf = calloc(cap, sizeof(struct ne_job));
	if (!r->buf)
		return -1;
	r->cap = cap;
	pthread_mutex_init(&r->mu, NULL);
	pthread_cond_init(&r->nonempty, NULL);
	pthread_cond_init(&r->nonfull, NULL);
	return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
	if (!r)
		return;
	free(r->buf);
	r->buf = NULL;
	pthread_cond_destroy(&r->nonfull);
	pthread_cond_destroy(&r->nonempty);
	pthread_mutex_destroy(&r->mu);
	memset(r, 0, sizeof(*r));
}

int ne_ring_try_push(struct ne_ring *r, const struct ne_job *j)
{
	pthread_mutex_lock(&r->mu);
	if (r->count == r->cap) {
		pthread_mutex_unlock(&r->mu);
		return -1;
	}
	r->buf[r->tail] = *j;
	r->tail = (r->tail + 1) % r->cap;
	r->count++;
	pthread_cond_signal(&r->nonempty);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

int ne_ring_try_pop(struct ne_ring *r, struct ne_job *j)
{
	pthread_mutex_lock(&r->mu);
	if (r->count == 0) {
		pthread_mutex_unlock(&r->mu);
		return -1;
	}
	*j = r->buf[r->head];
	r->head = (r->head + 1) % r->cap;
	r->count--;
	pthread_cond_signal(&r->nonfull);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

void ne_ring_wake_all(struct ne_ring *r)
{
	if (!r)
		return;
	pthread_mutex_lock(&r->mu);
	pthread_cond_broadcast(&r->nonempty);
	pthread_cond_broadcast(&r->nonfull);
	pthread_mutex_unlock(&r->mu);
}

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

static struct ne_ctx *g_ctx;

static void pin_cpu(unsigned cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	(void)pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void wake_rings(struct ne_ctx *ctx)
{
	ne_ring_wake_all(&ctx->ing_to_mid);
	ne_ring_wake_all(&ctx->w_to_wan);
}

static void on_sig(int s)
{
	(void)s;
	if (g_ctx) {
		g_ctx->stop = 1;
		wake_rings(g_ctx);
	}
}

static void *thread_ingress(void *arg)
{
	struct ne_ctx *ctx = arg;
	pin_cpu(NE_CPU_INGRESS);

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!ctx->stop) {
		int n = ne_afxdp_recv_ing(&ctx->zc, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;
		for (int i = 0; i < n; i++) {
			struct ne_job job = {.umem_addr = addrs[i], .len = lens[i]};
			if (ne_pl_ring_push_retry(&ctx->ing_to_mid, &job, &ctx->stop) != 0)
				ne_afxdp_fq_return_ing(&ctx->zc, addrs[i]);
		}
	}
	return NULL;
}

static void *thread_mid(void *arg)
{
	struct ne_ctx *ctx = arg;
	pin_cpu(NE_CPU_MID);

	while (!ctx->stop) {
		struct ne_job j;
		if (ne_ring_try_pop(&ctx->ing_to_mid, &j) == 0) {
			if (ne_pl_ring_push_retry(&ctx->w_to_wan, &j, &ctx->stop) != 0)
				ne_afxdp_fq_return_ing(&ctx->zc, j.umem_addr);
			continue;
		}
		sched_yield();
	}
	return NULL;
}

static void *thread_wan(void *arg)
{
	struct ne_ctx *ctx = arg;
	pin_cpu(NE_CPU_WAN);

	while (!ctx->stop) {
		struct ne_job j;
		if (ne_ring_try_pop(&ctx->w_to_wan, &j) == 0) {
			if (ne_afxdp_tx_wan(&ctx->zc, j.umem_addr, j.len) != 0)
				ne_afxdp_fq_return_ing(&ctx->zc, j.umem_addr);
			continue;
		}
		sched_yield();
	}
	return NULL;
}

int ne_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf)
{
	struct ne_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	if (ne_ring_init(&ctx.ing_to_mid, NE_RING_CAP) != 0)
		return -1;
	if (ne_ring_init(&ctx.w_to_wan, NE_RING_CAP) != 0) {
		ne_ring_destroy(&ctx.ing_to_mid);
		return -1;
	}

	struct ne_afxdp_cfg zcfg = {
		.umem_mb = NE_LOCAL_UMEM_MB,
		.ring_size = NE_LOCAL_RING,
		.batch_size = NE_LOCAL_BATCH,
		.frame_size = NE_LOCAL_FRAME,
		.bpf_ing = ingress_bpf,
	};
	snprintf(zcfg.ing_if, sizeof(zcfg.ing_if), "%s", ingress_if);
	snprintf(zcfg.wan_if, sizeof(zcfg.wan_if), "%s", wan_if);

	if (ne_afxdp_pair_open(&ctx.zc, &zcfg) != 0) {
		ne_ring_destroy(&ctx.w_to_wan);
		ne_ring_destroy(&ctx.ing_to_mid);
		return -1;
	}

	ctx.stop = 0;
	g_ctx = &ctx;
	struct sigaction sa = {.sa_handler = on_sig};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	int ok_ing = 0, ok_mid = 0, ok_wan = 0;
	if (pthread_create(&ctx.th_ingress, NULL, thread_ingress, &ctx) != 0)
		goto fail_threads;
	ok_ing = 1;
	if (pthread_create(&ctx.th_mid, NULL, thread_mid, &ctx) != 0)
		goto fail_threads;
	ok_mid = 1;
	if (pthread_create(&ctx.th_wan, NULL, thread_wan, &ctx) != 0)
		goto fail_threads;
	ok_wan = 1;

	pthread_join(ctx.th_ingress, NULL);
	pthread_join(ctx.th_mid, NULL);
	pthread_join(ctx.th_wan, NULL);

	ne_afxdp_pair_close(&ctx.zc);
	ne_ring_destroy(&ctx.w_to_wan);
	ne_ring_destroy(&ctx.ing_to_mid);
	g_ctx = NULL;
	return 0;

fail_threads:
	ctx.stop = 1;
	wake_rings(&ctx);
	if (ok_wan)
		pthread_join(ctx.th_wan, NULL);
	if (ok_mid)
		pthread_join(ctx.th_mid, NULL);
	if (ok_ing)
		pthread_join(ctx.th_ingress, NULL);
	ne_afxdp_pair_close(&ctx.zc);
	ne_ring_destroy(&ctx.w_to_wan);
	ne_ring_destroy(&ctx.ing_to_mid);
	g_ctx = NULL;
	return -1;
}
