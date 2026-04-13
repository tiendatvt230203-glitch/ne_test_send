#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "inc/xsk_plane.h"

#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_BATCH 32

static volatile sig_atomic_t g_stop;

static void on_sig(int s)
{
    (void)s;
    g_stop = 1;
}

static int libbpf_log_min(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
        return 0;
    if (level == LIBBPF_WARN && fmt && strstr(fmt, "strerror_r(-524)") != NULL)
        return 0;
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <ingress_ifname> [bpf/xdp_redirect.o]\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *bpf_path = (argc >= 3) ? argv[2] : "bpf/xdp_redirect.o";

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    libbpf_set_print(libbpf_log_min);

    cpu_set_t c;
    CPU_ZERO(&c);
    CPU_SET(11, &c);
    (void)sched_setaffinity(0, sizeof(c), &c);

    struct local_config cfg = {0};
    cfg.umem_mb = 32;
    cfg.ring_size = 1024;
    cfg.batch_size = 32;
    cfg.frame_size = 2048;
    strncpy(cfg.ifname, ifname, IF_NAMESIZE - 1);

    struct xsk_interface ingress;
    if (interface_init_local(&ingress, &cfg, bpf_path) != 0)
        return 1;

    struct wan_config wan_cfg[WAN_PORTS] = {0};
    wan_cfg[0] = (struct wan_config){
        .ifname = "enp4s0",
        .src_mac = {0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xcf},
        .dst_mac = {0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4d},
    };
    wan_cfg[1] = (struct wan_config){
        .ifname = "enp5s0",
        .src_mac = {0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xd0},
        .dst_mac = {0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4e},
    };
    wan_cfg[2] = (struct wan_config){
        .ifname = "enp6s0",
        .src_mac = {0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xd1},
        .dst_mac = {0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4f},
    };

    struct wan_port wans[WAN_PORTS] = {0};
    for (int i = 0; i < WAN_PORTS; i++) {
        if (wan_port_init(&wans[i], &wan_cfg[i], cfg.ring_size, cfg.frame_size, cfg.umem_mb) != 0) {
            fprintf(stderr, "wan_port_init failed: %s\n", wan_cfg[i].ifname);
            for (int j = 0; j < i; j++)
                wan_port_cleanup(&wans[j]);
            interface_cleanup(&ingress);
            return 1;
        }
    }

    void *ptrs[MAX_BATCH];
    uint32_t lens[MAX_BATCH];
    uint64_t addrs[MAX_BATCH];
    uint32_t rr = 0;
    uint64_t tx_fail = 0;
    uint64_t tx_bad_pkt = 0;

    while (!g_stop) {
        int n = interface_recv(&ingress, ptrs, lens, addrs, MAX_BATCH);
        if (n <= 0)
            continue;
        for (int i = 0; i < n; i++) {
            if (lens[i] < sizeof(struct ethhdr)) {
                tx_bad_pkt++;
                continue;
            }
            uint32_t w = rr++ % WAN_PORTS;
            if (wan_send_one(&wans[w], ptrs[i], lens[i], wan_cfg[w].src_mac, wan_cfg[w].dst_mac) != 0)
                tx_fail++;
        }
        interface_recv_release(&ingress, addrs, n);
    }

    printf("ingress rx %" PRIu64 " pkts %" PRIu64 " bytes\n", ingress.rx_packets, ingress.rx_bytes);
    for (int i = 0; i < WAN_PORTS; i++) {
        printf("wan[%d] %s tx %" PRIu64 " pkts %" PRIu64 " bytes\n", i, wan_cfg[i].ifname,
               wans[i].tx_packets, wans[i].tx_bytes);
        wan_port_cleanup(&wans[i]);
    }
    printf("tx_fail %" PRIu64 "\n", tx_fail);
    printf("tx_bad_pkt %" PRIu64 "\n", tx_bad_pkt);

    interface_cleanup(&ingress);
    return 0;
}
