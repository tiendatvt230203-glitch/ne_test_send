#ifndef NE_DEFAULTS_H
#define NE_DEFAULTS_H

#include <stdint.h>

#define NE_LOCAL_UMEM_MB   32u
#define NE_LOCAL_RING      1024u
#define NE_LOCAL_BATCH     32u
#define NE_LOCAL_FRAME     2048u

#define NE_QUEUE_CAP       4096u
#define NE_RECV_BATCH      32

#define NE_DEFAULT_BPF     "bpf/xdp_redirect.o"
#define NE_DEFAULT_WAN_BPF "bpf/xdp_wan_redirect_ne.o"

#define NE_PIPELINE_RING_CAP 4096u
#define NE_PIPELINE_POOL_SLOTS 8192u

#define NE_CPU_INGRESS       0u
#define NE_CPU_MID           3u
#define NE_CPU_WAN           11u

#define NE_WAN_IF0 "enp4s0"
#define NE_WAN_IF1 "enp5s0"
#define NE_WAN_IF2 "enp6s0"

#endif
