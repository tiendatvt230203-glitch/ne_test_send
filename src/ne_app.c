#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../inc/ne_app.h"
#include "../inc/ne_defaults.h"
#include "../inc/ingress_afxdp.h"
#include "../inc/wan_afxdp.h"
#include "../inc/wan_packet_out.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop;

static void on_sig(int s)
{
	(void)s;
	g_stop = 1;
}

static void pin_cpu(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	(void)pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

struct pkt_slot {
	void *ptr;
	uint32_t len;
	uint64_t addr;
};

struct ne_app {
	struct xsk_interface ingress;
	struct ne_wan_tx wan[NE_WAN_COUNT];
	struct pkt_slot q[NE_QUEUE_CAP];
	uint32_t qh;
	uint32_t qt;
	uint32_t qn;
	pthread_mutex_t qm;
	pthread_cond_t qne;
	pthread_cond_t qnf;
	uint32_t rr;
	uint64_t q_drop;
};

struct ne_app *ne_app_create(void)
{
	struct ne_app *a = calloc(1, sizeof(*a));
	if (!a)
		return NULL;
	pthread_mutex_init(&a->qm, NULL);
	pthread_cond_init(&a->qne, NULL);
	pthread_cond_init(&a->qnf, NULL);
	return a;
}

void ne_app_destroy(struct ne_app *a)
{
	if (!a)
		return;
	pthread_mutex_destroy(&a->qm);
	pthread_cond_destroy(&a->qne);
	pthread_cond_destroy(&a->qnf);
	free(a);
}

static int q_push(struct ne_app *a, struct pkt_slot it)
{
	pthread_mutex_lock(&a->qm);
	while (!g_stop && a->qn == NE_QUEUE_CAP)
		pthread_cond_wait(&a->qnf, &a->qm);
	if (g_stop) {
		pthread_mutex_unlock(&a->qm);
		return -1;
	}
	a->q[a->qt] = it;
	a->qt = (a->qt + 1) % NE_QUEUE_CAP;
	a->qn++;
	pthread_cond_signal(&a->qne);
	pthread_mutex_unlock(&a->qm);
	return 0;
}

static int q_pop(struct ne_app *a, struct pkt_slot *it)
{
	pthread_mutex_lock(&a->qm);
	while (!g_stop && a->qn == 0)
		pthread_cond_wait(&a->qne, &a->qm);
	if (a->qn == 0 && g_stop) {
		pthread_mutex_unlock(&a->qm);
		return -1;
	}
	*it = a->q[a->qh];
	a->qh = (a->qh + 1) % NE_QUEUE_CAP;
	a->qn--;
	pthread_cond_signal(&a->qnf);
	pthread_mutex_unlock(&a->qm);
	return 0;
}

static void *rx_loop(void *arg)
{
	struct ne_app *a = (struct ne_app *)arg;
	pin_cpu(NE_CPU_RX);

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!g_stop) {
		int n = interface_recv(&a->ingress, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;
		for (int i = 0; i < n; i++) {
			struct pkt_slot it = {.ptr = ptrs[i], .len = lens[i], .addr = addrs[i]};
			if (q_push(a, it) != 0) {
				a->q_drop += (uint64_t)(n - i);
				interface_recv_release(&a->ingress, &addrs[i], n - i);
				break;
			}
		}
	}
	return NULL;
}

static void *tx_loop(void *arg)
{
	struct ne_app *a = (struct ne_app *)arg;
	pin_cpu(NE_CPU_TX);

	while (!g_stop) {
		struct pkt_slot it;
		if (q_pop(a, &it) != 0)
			break;
		if (wan_packet_out_rr(a->wan, &a->rr, it.ptr, it.len) != 0)
			(void)0;
		interface_recv_release(&a->ingress, &it.addr, 1);
	}
	return NULL;
}

int ne_app_setup(struct ne_app *a, const char *ingress_ifname, const char *bpf_path)
{
	if (!a || !ingress_ifname)
		return -1;
	const char *bpf = (bpf_path && bpf_path[0]) ? bpf_path : NE_DEFAULT_BPF;

	struct local_config cfg = {0};
	cfg.umem_mb = NE_LOCAL_UMEM_MB;
	cfg.ring_size = NE_LOCAL_RING;
	cfg.batch_size = NE_LOCAL_BATCH;
	cfg.frame_size = NE_LOCAL_FRAME;
	strncpy(cfg.ifname, ingress_ifname, IF_NAMESIZE - 1);

	if (interface_init_local(&a->ingress, &cfg, bpf) != 0)
		return -1;

	static const char *wan_if[NE_WAN_COUNT] = {NE_WAN_IF0, NE_WAN_IF1, NE_WAN_IF2};
	for (int i = 0; i < NE_WAN_COUNT; i++) {
		if (ne_wan_tx_open(&a->wan[i], wan_if[i], cfg.ring_size, cfg.frame_size, cfg.umem_mb) != 0) {
			fprintf(stderr, "ne_wan_tx_open %s failed\n", wan_if[i]);
			for (int j = 0; j < i; j++)
				ne_wan_tx_close(&a->wan[j]);
			interface_cleanup(&a->ingress);
			return -1;
		}
	}
	return 0;
}

void ne_app_run_until_signal(struct ne_app *a)
{
	if (!a)
		return;

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	g_stop = 0;

	pthread_t tr, tt;
	int ok_rx = pthread_create(&tr, NULL, rx_loop, a) == 0;
	int ok_tx = ok_rx && (pthread_create(&tt, NULL, tx_loop, a) == 0);
	if (!ok_tx) {
		g_stop = 1;
		pthread_cond_broadcast(&a->qne);
		pthread_cond_broadcast(&a->qnf);
		if (ok_rx)
			pthread_join(tr, NULL);
		for (int i = 0; i < NE_WAN_COUNT; i++)
			ne_wan_tx_close(&a->wan[i]);
		interface_cleanup(&a->ingress);
		return;
	}
	pthread_join(tr, NULL);
	pthread_join(tt, NULL);

	printf("ingress rx %" PRIu64 " pkts %" PRIu64 " bytes q_drop %" PRIu64 "\n", a->ingress.rx_packets,
	       a->ingress.rx_bytes, a->q_drop);
	for (int i = 0; i < NE_WAN_COUNT; i++) {
		printf("wan[%d] %s tx %" PRIu64 " pkts %" PRIu64 " bytes\n", i, a->wan[i].ifname, a->wan[i].tx_pkts,
		       a->wan[i].tx_bytes);
		ne_wan_tx_close(&a->wan[i]);
	}
	interface_cleanup(&a->ingress);
}
