#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_ICMP_VAL 1

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 8);
	__type(key, int);
	__type(value, int);
} wan_xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, int);
	__type(value, __u64);
} wan_stats_map SEC(".maps");

static __always_inline void inc_stat(int idx)
{
	__u64 *v = bpf_map_lookup_elem(&wan_stats_map, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	inc_stat(0);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == __constant_htons(ETH_P_ARP)) {
		inc_stat(4);
		return XDP_PASS;
	}

	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl < 5)
		return XDP_PASS;

	if (ip->protocol == IPPROTO_ICMP_VAL) {
		inc_stat(5);
		return XDP_PASS;
	}

	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	int qid = 0;
	void *xs = bpf_map_lookup_elem(&wan_xsks_map, &qid);
	if (!xs) {
		inc_stat(3);
		return XDP_PASS;
	}

	inc_stat(2);
	return bpf_redirect_map(&wan_xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
