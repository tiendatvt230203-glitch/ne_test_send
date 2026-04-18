#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_afxdp_fq_pool.h"

#include <linux/if_xdp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <xdp/xsk.h>

int ne_afxdp_tx_wan(struct ne_afxdp_pair *p, uint64_t addr, uint32_t len)
{
	if (!p->wan.xsk || len == 0 || len > p->frame_size)
		return -1;
	ne_afxdp_drain_wan_cq(p);

	uint32_t tx_idx;
	if (xsk_ring_prod__reserve(&p->wan.tx, 1, &tx_idx) != 1) {
		ne_afxdp_drain_wan_cq(p);
		if (xsk_ring_prod__reserve(&p->wan.tx, 1, &tx_idx) != 1)
			return -1;
	}

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&p->wan.tx, tx_idx);
	d->addr = addr;
	d->len = len;
	d->options = 0;
	xsk_ring_prod__submit(&p->wan.tx, 1);

	(void)sendto(xsk_socket__fd(p->wan.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	p->wan.tx_packets++;
	p->wan.tx_bytes += len;
	return 0;
}
