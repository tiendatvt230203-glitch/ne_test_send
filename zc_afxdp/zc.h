/*
 * zc.h     — hằng số, struct zc, prototype
 * main.c   — signal, vòng gửi ping
 * cpu.c    — ghim CPU
 * pkt.c    — dựng frame Ethernet/IP/UDP
 * rings.c  — pool buffer, CQ, fill ring (prime FQ)
 * tx.c     — một lần gửi TX ring + wakeup
 * ctx.c    — mở/đóng UMEM + XSK (zerocopy bind)
 */
#ifndef ZC_H
#define ZC_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include <xdp/xsk.h>

#define RING_SZ            1024u
#define FRAME_SZ           2048u
#define PIN_CPU            11u
#define MIN_ETH_LEN        60u
#define PING_INTERVAL_SEC  1
#define IP_UDP_BYTES       28u

struct zc {
	void *umem_area;
	size_t umem_bytes;
	struct xsk_umem *umem;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	pthread_mutex_t fq_mu;
	pthread_mutex_t pool_mu;
	uint64_t *stk;
	uint32_t stk_top;
	uint32_t stk_cap;
	int ifindex;
	int locks_ok;
};

void zc_pin_cpu(unsigned cpu);

void zc_pool_push(struct zc *z, uint64_t addr);
uint64_t zc_pool_pop(struct zc *z);
void zc_drain_cq(struct zc *z);
int zc_fq_prime(struct zc *z);

void zc_build_pkt(void *pkt, uint32_t len);
int zc_tx_one(struct zc *z, uint64_t addr, uint32_t len);

void zc_close(struct zc *z);
int zc_open(struct zc *z, const char *ifname);

#endif
