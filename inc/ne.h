#ifndef NE_H
#define NE_H

#include <linux/types.h>
#include <net/if.h>
#include <stddef.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;

#define NE_LOCAL_UMEM_MB     32u
#define NE_LOCAL_RING        1024u
#define NE_LOCAL_BATCH       32u
#define NE_LOCAL_FRAME       2048u
#define NE_RECV_BATCH        32
#define NE_DEFAULT_BPF       "bpf/xdp_redirect.o"
#define NE_DEFAULT_WAN_BPF   "bpf/xdp_wan_redirect_ne.o"
#define NE_RING_CAP          4096u
#define NE_CPU_INGRESS       0u
#define NE_CPU_MID           3u
#define NE_CPU_WAN           11u

enum ne_dir {
	NE_DIR_TO_WAN = 0,
	NE_DIR_TO_CLIENT = 1,
};

struct ne_job {
	uint64_t umem_addr;
	uint32_t len;
	uint32_t conn_id;
	uint8_t worker_idx;
	uint8_t part;
	uint8_t dir;
	uint8_t pad;
};

struct ne_ring {
	pthread_mutex_t mu;
	pthread_cond_t nonempty;
	pthread_cond_t nonfull;
	struct ne_job *buf;
	uint32_t cap;
	uint32_t head;
	uint32_t tail;
	uint32_t count;
};

int ne_ring_init(struct ne_ring *r, uint32_t cap);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_push(struct ne_ring *r, const struct ne_job *j);
int ne_ring_try_pop(struct ne_ring *r, struct ne_job *j);
void ne_ring_wake_all(struct ne_ring *r);

struct local_config {
	char ifname[IF_NAMESIZE];
	uint32_t umem_mb;
	uint32_t ring_size;
	uint32_t batch_size;
	uint32_t frame_size;
};

void iface_xdp_try_detach(int ifindex, const char *ifname);
int iface_xdp_attach(int ifindex, int prog_fd, __u32 flags);
int iface_local_umem_ok(const char *ifname, const struct local_config *lc, size_t umem_bytes);

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

struct ne_ctx {
	volatile sig_atomic_t stop;
	struct ne_afxdp_pair zc;
	struct ne_ring ing_to_mid;
	struct ne_ring wan_to_mid;
	struct ne_ring w_to_wan;
	struct ne_ring w_to_client;

	pthread_t th_ingress;
	pthread_t th_mid;
	pthread_t th_wan;

	_Atomic uint64_t drops_ring_ingress;
	_Atomic uint64_t drops_ring_wan;
	_Atomic uint64_t drops_mid_wan;
	_Atomic uint64_t drops_mid_cli;
	_Atomic uint64_t wan_tx_fail;
	_Atomic uint64_t ing_tx_fail;
};

int ne_pl_ring_push_retry(struct ne_ring *r, const struct ne_job *j, volatile sig_atomic_t *stop);
void *ne_pl_job_pkt(struct ne_ctx *ctx, uint64_t umem_addr);
void ne_pl_ingress_tx_client(struct ne_ctx *ctx);
void ne_pl_wan_tx_wan(struct ne_ctx *ctx);

void ne_pkt_log_open(void);
void ne_pkt_log_close(void);
int ne_pkt_log_enabled(void);
void ne_pkt_logf(const char *fmt, ...);

int ne_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf, const char *wan_bpf);

#endif
