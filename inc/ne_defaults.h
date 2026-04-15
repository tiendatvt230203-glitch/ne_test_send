#ifndef NE_DEFAULTS_H
#define NE_DEFAULTS_H

#include <stdint.h>

/* AF_XDP zero-copy ingress (local) — tune here, not in main.c */
#define NE_LOCAL_UMEM_MB   32u
#define NE_LOCAL_RING      1024u
#define NE_LOCAL_BATCH     32u
#define NE_LOCAL_FRAME     2048u

/* Handoff queue ingress RX → WAN TX threads */
#define NE_QUEUE_CAP       4096u
#define NE_RECV_BATCH      32

#define NE_DEFAULT_BPF     "bpf/xdp_redirect.o"

/* Default WAN names for round-robin demo (override later via config/CLI) */
#define NE_WAN_IF0 "enp4s0"
#define NE_WAN_IF1 "enp5s0"
#define NE_WAN_IF2 "enp6s0"

#endif
