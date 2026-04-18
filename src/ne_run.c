#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ne.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop;

static void on_sig(int s)
{
	(void)s;
	g_stop = 1;
}

int ne_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf)
{
	struct ne_afxdp_pair zc;
	memset(&zc, 0, sizeof(zc));

	struct ne_afxdp_cfg zcfg = {
		.umem_mb = NE_LOCAL_UMEM_MB,
		.ring_size = NE_LOCAL_RING,
		.batch_size = NE_LOCAL_BATCH,
		.frame_size = NE_LOCAL_FRAME,
		.bpf_ing = ingress_bpf,
	};
	snprintf(zcfg.ing_if, sizeof(zcfg.ing_if), "%s", ingress_if);
	snprintf(zcfg.wan_if, sizeof(zcfg.wan_if), "%s", wan_if);

	if (ne_afxdp_pair_open(&zc, &zcfg) != 0)
		return -1;

	g_stop = 0;
	struct sigaction sa = {.sa_handler = on_sig};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	void *ptrs[NE_RECV_BATCH];
	uint32_t lens[NE_RECV_BATCH];
	uint64_t addrs[NE_RECV_BATCH];

	while (!g_stop) {
		int n = ne_afxdp_recv_ing(&zc, ptrs, lens, addrs, NE_RECV_BATCH);
		if (n <= 0)
			continue;
		for (int i = 0; i < n; i++) {
			if (ne_afxdp_tx_wan(&zc, addrs[i], lens[i]) != 0)
				ne_afxdp_fq_return_ing(&zc, addrs[i]);
		}
	}

	ne_afxdp_pair_close(&zc);
	return 0;
}
