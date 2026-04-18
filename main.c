#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ne.h"

#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc < 3)
		return 1;
	if (ne_run(argv[1], argv[2], (argc >= 4 && argv[3][0]) ? argv[3] : NE_DEFAULT_BPF) != 0)
		return 1;
	return 0;
}
