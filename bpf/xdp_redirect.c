#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP_VAL 0x0806

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    if (proto == bpf_htons(ETH_P_8021Q)) {
        if ((__u8 *)nh + 4 > (__u8 *)data_end)
            return XDP_PASS;
        __be16 *ipe = (__be16 *)((__u8 *)nh + 2);
        proto = *ipe;
        nh = (void *)((__u8 *)nh + 4);
    }

    if (proto == bpf_htons(ETH_P_ARP_VAL)) {
        bpf_printk("NE: PASS ARP\n");
        return XDP_PASS;
    }

    if (proto != bpf_htons(ETH_P_IP)) {
        bpf_printk("NE: PASS non-IP eth=0x%x\n", bpf_ntohs(proto));
        return XDP_PASS;
    }

    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_ICMP) {
        bpf_printk("NE: PASS ICMP\n");
        return XDP_PASS;
    }

    __u32 qid = 0;
    void *xs = bpf_map_lookup_elem(&xsks_map, &qid);
    if (!xs) {
        bpf_printk("NE: PASS xsks_map[0] empty (run ne-sniff)\n");
        return XDP_PASS;
    }

    bpf_printk("NE: REDIRECT q0 proto=%u ihl=%u\n", ip->protocol, ip->ihl);
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
