#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ne.h"

#include <inttypes.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <xdp/xsk.h>

static FILE *g_pkt_f;
static pthread_mutex_t g_pkt_mu = PTHREAD_MUTEX_INITIALIZER;
static _Atomic unsigned long long g_pkt_seq;

void ne_pkt_log_open(void)
{
	const char *p = getenv("NE_PKT_LOG");
	if (!p || !p[0])
		return;
	pthread_mutex_lock(&g_pkt_mu);
	if (g_pkt_f) {
		fclose(g_pkt_f);
		g_pkt_f = NULL;
	}
	g_pkt_f = fopen(p, "w");
	if (g_pkt_f)
		setbuf(g_pkt_f, NULL);
	pthread_mutex_unlock(&g_pkt_mu);
}

void ne_pkt_log_close(void)
{
	pthread_mutex_lock(&g_pkt_mu);
	if (g_pkt_f) {
		fclose(g_pkt_f);
		g_pkt_f = NULL;
	}
	pthread_mutex_unlock(&g_pkt_mu);
}

int ne_pkt_log_enabled(void)
{
	pthread_mutex_lock(&g_pkt_mu);
	int ok = g_pkt_f != NULL;
	pthread_mutex_unlock(&g_pkt_mu);
	return ok;
}

void ne_pkt_logf(const char *fmt, ...)
{
	va_list ap;
	pthread_mutex_lock(&g_pkt_mu);
	if (!g_pkt_f) {
		pthread_mutex_unlock(&g_pkt_mu);
		return;
	}
	unsigned long long n = atomic_fetch_add_explicit(&g_pkt_seq, 1ULL, memory_order_relaxed);
	fprintf(g_pkt_f, "%llu ", n);
	va_start(ap, fmt);
	vfprintf(g_pkt_f, fmt, ap);
	va_end(ap);
	fprintf(g_pkt_f, "\n");
	fflush(g_pkt_f);
	pthread_mutex_unlock(&g_pkt_mu);
}

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

void *ne_pl_job_pkt(struct ne_ctx *ctx, uint64_t umem_addr)
{
	return xsk_umem__get_data(ctx->zc.bufs, xsk_umem__add_offset_to_addr(umem_addr));
}

void ne_pl_ingress_tx_client(struct ne_ctx *ctx)
{
	struct ne_job j;
	while (!ctx->stop && ne_ring_try_pop(&ctx->w_to_client, &j) == 0) {
		ne_pkt_logf("c0 pop_w2c %u %" PRIx64, j.len, (uint64_t)j.umem_addr);
		if (ne_afxdp_tx_ing(&ctx->zc, j.umem_addr, j.len) != 0) {
			ne_pkt_logf("c0 tx_ing_fail");
			atomic_fetch_add_explicit(&ctx->ing_tx_fail, 1, memory_order_relaxed);
			ne_afxdp_fq_return_wan(&ctx->zc, j.umem_addr);
		}
	}
}

void ne_pl_wan_tx_wan(struct ne_ctx *ctx)
{
	struct ne_job j;
	while (!ctx->stop && ne_ring_try_pop(&ctx->w_to_wan, &j) == 0) {
		ne_pkt_logf("c11 pop_w2w %u %" PRIx64, j.len, (uint64_t)j.umem_addr);
		if (ne_afxdp_tx_wan(&ctx->zc, j.umem_addr, j.len) != 0) {
			ne_pkt_logf("c11 tx_wan_fail");
			atomic_fetch_add_explicit(&ctx->wan_tx_fail, 1, memory_order_relaxed);
			ne_afxdp_fq_return_ing(&ctx->zc, j.umem_addr);
		}
	}
}

static struct ne_ctx *g_ctx;

static void pin_cpu(unsigned cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	(void)pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void wake_all(struct ne_ctx *ctx)
{
	ne_ring_wake_all(&ctx->ing_to_mid);
	ne_ring_wake_all(&ctx->wan_to_mid);
	ne_ring_wake_all(&ctx->w_to_wan);
	ne_ring_wake_all(&ctx->w_to_client);
}

static void on_sig(int s)
{
	(void)s;
	if (g_ctx)
		g_ctx->stop = 1;
}

static void *thread_ingress(void *arg)
{
	struct ne_ctx *ctx = arg;
	pin_cpu(NE_CPU_INGRESS);

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!ctx->stop) {
		ne_pl_ingress_tx_client(ctx);

		int n = ne_afxdp_recv_ing(&ctx->zc, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;

		ne_pkt_logf("c0 rx %d %u", n, lens[0]);
		for (int i = 0; i < n; i++) {
			struct ne_job job = {.umem_addr = addrs[i],
					     .len = lens[i],
					     .conn_id = 0,
					     .worker_idx = 0,
					     .part = 0,
					     .dir = NE_DIR_TO_WAN,
					     .pad = 0};
			if (ne_pl_ring_push_retry(&ctx->ing_to_mid, &job, &ctx->stop) != 0) {
				ne_pkt_logf("c0 drop_i2m %u", lens[i]);
				ne_afxdp_fq_return_ing(&ctx->zc, addrs[i]);
				atomic_fetch_add_explicit(&ctx->drops_ring_ingress, 1, memory_order_relaxed);
			} else {
				ne_pkt_logf("c0 push_i2m %u %" PRIx64, lens[i], (uint64_t)addrs[i]);
			}
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
			ne_pkt_logf("c3 pop_i2m %u", j.len);
			if (ne_pl_ring_push_retry(&ctx->w_to_wan, &j, &ctx->stop) != 0) {
				ne_pkt_logf("c3 drop_w2w");
				ne_afxdp_fq_return_ing(&ctx->zc, j.umem_addr);
				atomic_fetch_add_explicit(&ctx->drops_mid_wan, 1, memory_order_relaxed);
			} else {
				ne_pkt_logf("c3 push_w2w %u", j.len);
			}
			continue;
		}
		if (ne_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			ne_pkt_logf("c3 pop_w2m %u", j.len);
			if (ne_pl_ring_push_retry(&ctx->w_to_client, &j, &ctx->stop) != 0) {
				ne_pkt_logf("c3 drop_w2c");
				ne_afxdp_fq_return_wan(&ctx->zc, j.umem_addr);
				atomic_fetch_add_explicit(&ctx->drops_mid_cli, 1, memory_order_relaxed);
			} else {
				ne_pkt_logf("c3 push_w2c %u", j.len);
			}
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

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!ctx->stop) {
		ne_pl_wan_tx_wan(ctx);

		int n = ne_afxdp_recv_wan(&ctx->zc, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;

		ne_pkt_logf("c11 rx %d %u", n, lens[0]);
		for (int i = 0; i < n; i++) {
			struct ne_job job = {.umem_addr = addrs[i],
					     .len = lens[i],
					     .conn_id = 0,
					     .worker_idx = 0,
					     .part = 0,
					     .dir = NE_DIR_TO_CLIENT,
					     .pad = 0};
			if (ne_pl_ring_push_retry(&ctx->wan_to_mid, &job, &ctx->stop) != 0) {
				ne_pkt_logf("c11 drop_w2m");
				ne_afxdp_fq_return_wan(&ctx->zc, addrs[i]);
				atomic_fetch_add_explicit(&ctx->drops_ring_wan, 1, memory_order_relaxed);
			} else {
				ne_pkt_logf("c11 push_w2m %u", lens[i]);
			}
		}
	}
	return NULL;
}

static void destroy_mid(struct ne_ctx *ctx, int have_i2m, int have_w2m)
{
	if (have_w2m)
		ne_ring_destroy(&ctx->wan_to_mid);
	if (have_i2m)
		ne_ring_destroy(&ctx->ing_to_mid);
}

static void destroy_w(struct ne_ctx *ctx, int have_w2w, int have_w2c)
{
	if (have_w2c)
		ne_ring_destroy(&ctx->w_to_client);
	if (have_w2w)
		ne_ring_destroy(&ctx->w_to_wan);
}

int ne_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf, const char *wan_bpf)
{
	struct ne_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	int have_i2m = 0, have_w2m = 0;
	int have_w2w = 0, have_w2c = 0;

	if (ne_ring_init(&ctx.ing_to_mid, NE_RING_CAP) != 0)
		goto fail_rings;
	have_i2m = 1;
	if (ne_ring_init(&ctx.wan_to_mid, NE_RING_CAP) != 0)
		goto fail_rings;
	have_w2m = 1;

	if (ne_ring_init(&ctx.w_to_wan, NE_RING_CAP) != 0)
		goto fail_rings;
	have_w2w = 1;
	if (ne_ring_init(&ctx.w_to_client, NE_RING_CAP) != 0)
		goto fail_rings;
	have_w2c = 1;

	ne_pkt_log_open();
	ne_pkt_logf("boot %s %s", ingress_if, wan_if);
	ne_pkt_logf("cpu %u %u %u", NE_CPU_INGRESS, NE_CPU_MID, NE_CPU_WAN);

	struct ne_afxdp_cfg zcfg = {0};
	snprintf(zcfg.ing_if, sizeof(zcfg.ing_if), "%s", ingress_if);
	snprintf(zcfg.wan_if, sizeof(zcfg.wan_if), "%s", wan_if);
	zcfg.umem_mb = NE_LOCAL_UMEM_MB;
	zcfg.ring_size = NE_LOCAL_RING;
	zcfg.batch_size = NE_LOCAL_BATCH;
	zcfg.frame_size = NE_LOCAL_FRAME;
	zcfg.bpf_ing = ingress_bpf;
	zcfg.bpf_wan = wan_bpf;

	if (ne_afxdp_pair_open(&ctx.zc, &zcfg) != 0) {
		ne_pkt_logf("fail_open");
		ne_pkt_log_close();
		goto fail_rings;
	}

	g_ctx = &ctx;
	ctx.stop = 0;
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

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

	while (!ctx.stop)
		pause();

	ctx.stop = 1;
	wake_all(&ctx);
	pthread_join(ctx.th_ingress, NULL);
	pthread_join(ctx.th_mid, NULL);
	pthread_join(ctx.th_wan, NULL);

	if (ne_pkt_log_enabled()) {
		ne_pkt_logf("sum irx=%" PRIu64 " wrx=%" PRIu64 " wtx=%" PRIu64 " itx=%" PRIu64,
			    ctx.zc.ing.rx_packets, ctx.zc.wan.rx_packets, ctx.zc.wan.tx_packets,
			    ctx.zc.ing.tx_packets);
		ne_pkt_logf("sum dr0=%" PRIu64 " dr11=%" PRIu64 " dmw=%" PRIu64 " dmc=%" PRIu64 " fw=%" PRIu64
			    " fi=%" PRIu64,
			    atomic_load_explicit(&ctx.drops_ring_ingress, memory_order_relaxed),
			    atomic_load_explicit(&ctx.drops_ring_wan, memory_order_relaxed),
			    atomic_load_explicit(&ctx.drops_mid_wan, memory_order_relaxed),
			    atomic_load_explicit(&ctx.drops_mid_cli, memory_order_relaxed),
			    atomic_load_explicit(&ctx.wan_tx_fail, memory_order_relaxed),
			    atomic_load_explicit(&ctx.ing_tx_fail, memory_order_relaxed));
	}

	ne_pkt_log_close();
	ne_afxdp_pair_close(&ctx.zc);
	ne_ring_destroy(&ctx.ing_to_mid);
	ne_ring_destroy(&ctx.wan_to_mid);
	ne_ring_destroy(&ctx.w_to_wan);
	ne_ring_destroy(&ctx.w_to_client);
	g_ctx = NULL;
	return 0;

fail_threads:
	ctx.stop = 1;
	wake_all(&ctx);
	if (ok_ing)
		pthread_join(ctx.th_ingress, NULL);
	if (ok_mid)
		pthread_join(ctx.th_mid, NULL);
	if (ok_wan)
		pthread_join(ctx.th_wan, NULL);
	ne_pkt_log_close();
	ne_afxdp_pair_close(&ctx.zc);
	g_ctx = NULL;
fail_rings:
	destroy_w(&ctx, have_w2w, have_w2c);
	destroy_mid(&ctx, have_i2m, have_w2m);
	return -1;
}
