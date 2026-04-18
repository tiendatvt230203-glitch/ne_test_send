#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "inc/ne_defaults.h"
#include "inc/ne_pipeline.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: sudo %s <ingress_if> <wan_if> [%s] [%s]\n", argv[0] ? argv[0] : "ne",
			NE_DEFAULT_BPF, NE_DEFAULT_WAN_BPF);
		return 1;
	}

	const char *ingress = argv[1];
	const char *wan = argv[2];
	const char *bpf_in = (argc >= 4 && argv[3][0]) ? argv[3] : NE_DEFAULT_BPF;
	const char *bpf_wan = (argc >= 5 && argv[4][0]) ? argv[4] : NE_DEFAULT_WAN_BPF;

	if (ne_pipeline_run(ingress, wan, bpf_in, bpf_wan) != 0) {
		fprintf(stderr, "ne_pipeline_run failed\n");
		return 1;
	}
	return 0;
}
