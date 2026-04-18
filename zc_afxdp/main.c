#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "zc.h"

#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <stdlib.h>

static volatile sig_atomic_t stop_flag;

static void on_sig(int s)
{
	(void)s;
	stop_flag = 1;
}

int main(int argc, char **argv)
{
	const char *ifname = (argc >= 2 && argv[1][0]) ? argv[1] : NULL;
	if (!ifname)
		return 1;

	zc_pin_cpu(PIN_CPU);

	struct sigaction sa = {.sa_handler = on_sig};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	struct zc z;
	if (zc_open(&z, ifname) != 0)
		return 1;

	while (!stop_flag) {
		zc_drain_cq(&z);
		uint64_t addr = zc_pool_pop(&z);
		if (addr == UINT64_MAX) {
			sched_yield();
			continue;
		}
		if (zc_tx_one(&z, addr, MIN_ETH_LEN) != 0) {
			zc_pool_push(&z, addr);
			sched_yield();
			continue;
		}
		zc_drain_cq(&z);
		struct timespec ts = {.tv_sec = PING_INTERVAL_SEC, .tv_nsec = 0};
		while (nanosleep(&ts, &ts) == -1 && errno == EINTR && !stop_flag)
			;
	}

	zc_close(&z);
	return 0;
}
