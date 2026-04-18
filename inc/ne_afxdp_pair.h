#ifndef NE_AFXDP_PAIR_H
#define NE_AFXDP_PAIR_H

#include <net/if.h>
#include <pthread.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;

struct ne_afxdp_cfg {
	char ing_if[IF_NAMESIZE];
	char wan_if[IF_NAMESIZE];
	uint32_t umem_mb;
	uint32_t ring_size;
	uint32_t batch_size;
	uint32_t frame_size;
	const char *bpf_ing;
	const char *bpf_wan;
};

struct ne_zc_port {
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	int ifindex;
	char ifname[IF_NAMESIZE];
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct ne_afxdp_pair {
	void *bufs;
	size_t bufsize;
	uint32_t ring_size;
	uint32_t frame_size;
	uint32_t batch_size;
	struct xsk_umem *umem;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct ne_zc_port ing;
	struct ne_zc_port wan;
	struct bpf_object *bpf_ing;
	struct bpf_object *bpf_wan;

	uint32_t n_frames;
	uint64_t *frame_stack;
	uint32_t stack_top;
	uint32_t stack_cap;
	int pool_lock_inited;
	pthread_mutex_t pool_lock;

	int fq_locks_inited;
	pthread_mutex_t ing_fq_lock;
	pthread_mutex_t wan_fq_lock;
};

int ne_afxdp_pair_open(struct ne_afxdp_pair *p, const struct ne_afxdp_cfg *cfg);
void ne_afxdp_pair_close(struct ne_afxdp_pair *p);

int ne_afxdp_recv_ing(struct ne_afxdp_pair *p, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		      int max_pkts);
int ne_afxdp_recv_wan(struct ne_afxdp_pair *p, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		      int max_pkts);

void ne_afxdp_rx_release_ing(struct ne_afxdp_pair *p, uint64_t *addrs, int count);
void ne_afxdp_rx_release_wan(struct ne_afxdp_pair *p, uint64_t *addrs, int count);

int ne_afxdp_tx_wan(struct ne_afxdp_pair *p, uint64_t addr, uint32_t len);
int ne_afxdp_tx_ing(struct ne_afxdp_pair *p, uint64_t addr, uint32_t len);

void ne_afxdp_fq_return_ing(struct ne_afxdp_pair *p, uint64_t addr);
void ne_afxdp_fq_return_wan(struct ne_afxdp_pair *p, uint64_t addr);

#endif
