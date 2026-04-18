#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "inc/ne_defaults.h"
#include "inc/ne_pipeline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int env_af_xdp_copy(void)
{
	const char *e = getenv("NE_AF_XDP_COPY");
	if (!e || !e[0])
		return 0;
	if (e[0] == '1' && e[1] == '\0')
		return 1;
	if (strcasecmp(e, "yes") == 0 || strcasecmp(e, "true") == 0)
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage: sudo %s <ingress_if> <wan_if> [--copy] [%s] [%s]\n"
			"  --copy   AF_XDP copy mode (test when ZC + XDP generic misbehaves)\n"
			"  or: NE_AF_XDP_COPY=1\n",
			argv[0] ? argv[0] : "ne", NE_DEFAULT_BPF, NE_DEFAULT_WAN_BPF);
		return 1;
	}

	const char *ingress = argv[1];
	const char *wan = argv[2];
	int af_xdp_copy = env_af_xdp_copy();
	const char *bpf_in = NE_DEFAULT_BPF;
	const char *bpf_wan = NE_DEFAULT_WAN_BPF;
	int nbpf = 0;

	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--copy") == 0) {
			af_xdp_copy = 1;
			continue;
		}
		if (nbpf == 0) {
			if (argv[i][0])
				bpf_in = argv[i];
			nbpf++;
		} else if (nbpf == 1) {
			if (argv[i][0])
				bpf_wan = argv[i];
			nbpf++;
		}
	}

	if (ne_pipeline_run(ingress, wan, bpf_in, bpf_wan, af_xdp_copy) != 0) {
		fprintf(stderr, "ne_pipeline_run failed\n");
		return 1;
	}
	return 0;
}
