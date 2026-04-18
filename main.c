#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ne.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "sudo %s <ingress_if> <wan_if> [%s] [%s]\n", argv[0] ? argv[0] : "ne",
			NE_DEFAULT_BPF, NE_DEFAULT_WAN_BPF);
		return 1;
	}

	if (ne_run(argv[1], argv[2], (argc >= 4 && argv[3][0]) ? argv[3] : NE_DEFAULT_BPF,
		   (argc >= 5 && argv[4][0]) ? argv[4] : NE_DEFAULT_WAN_BPF) != 0) {
		fprintf(stderr, "ne_run failed\n");
		return 1;
	}
	return 0;
}
