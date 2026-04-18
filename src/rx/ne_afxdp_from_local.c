#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_afxdp_fq_pool.h"

#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include <xdp/xsk.h>

int ne_afxdp_recv_ing(struct ne_afxdp_pair *p, void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
		      int max_pkts)
{
	if (!p->ing.xsk)
		return 0;
	uint32_t idx_rx = 0;
	int rcvd = xsk_ring_cons__peek(&p->ing.rx, max_pkts, &idx_rx);
	if (rcvd == 0) {
		struct pollfd pfd = {.fd = xsk_socket__fd(p->ing.xsk), .events = POLLIN};
		if (poll(&pfd, 1, 1) <= 0)
			return 0;
		rcvd = xsk_ring_cons__peek(&p->ing.rx, max_pkts, &idx_rx);
		if (rcvd == 0)
			return 0;
	}
	for (int j = 0; j < rcvd; j++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&p->ing.rx, idx_rx + j);
		addrs[j] = desc->addr;
		pkt_ptrs[j] = xsk_umem__get_data(p->bufs, xsk_umem__add_offset_to_addr(desc->addr));
		pkt_lens[j] = desc->len;
	}
	xsk_ring_cons__release(&p->ing.rx, rcvd);
	while (ne_afxdp_fq_replenish_all(p, &p->ing, p->ing.xsk, (uint32_t)rcvd, &p->ing_fq_lock) != 0) {
		fprintf(stderr, "[ne] ingress FQ replenish retry (n=%d)\n", rcvd);
		sched_yield();
	}
	p->ing.rx_packets += (uint64_t)rcvd;
	for (int j = 0; j < rcvd; j++)
		p->ing.rx_bytes += pkt_lens[j];
	return rcvd;
}

void ne_afxdp_rx_release_ing(struct ne_afxdp_pair *p, uint64_t *addrs, int count)
{
	if (!p->ing.xsk || !p->fq_locks_inited)
		return;
	pthread_mutex_lock(&p->ing_fq_lock);
	for (int i = 0; i < count; i++)
		(void)ne_afxdp_fq_fill_one(&p->ing, p->ing.xsk, addrs[i]);
	pthread_mutex_unlock(&p->ing_fq_lock);
}
