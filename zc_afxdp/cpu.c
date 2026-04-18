#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "zc.h"

#include <pthread.h>
#include <sched.h>

void zc_pin_cpu(unsigned cpu)
{
	cpu_set_t m;
	CPU_ZERO(&m);
	CPU_SET(cpu, &m);
	(void)pthread_setaffinity_np(pthread_self(), sizeof(m), &m);
}
