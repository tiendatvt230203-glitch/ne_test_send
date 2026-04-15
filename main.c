#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "inc/ne_app.h"
#include "inc/ne_defaults.h"

#include <stdio.h>
#include <stdlib.h>

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: sudo %s <ingress_ifname> [%s]\n", prog, NE_DEFAULT_BPF);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	const char *ingress = argv[1];
	const char *bpf = (argc >= 3) ? argv[2] : NULL;

	struct ne_app *app = ne_app_create();
	if (!app) {
		fprintf(stderr, "ne_app_create failed\n");
		return 1;
	}

	if (ne_app_setup(app, ingress, bpf) != 0) {
		fprintf(stderr, "ne_app_setup failed\n");
		ne_app_destroy(app);
		return 1;
	}

	ne_app_run_until_signal(app);
	ne_app_destroy(app);
	return 0;
}
