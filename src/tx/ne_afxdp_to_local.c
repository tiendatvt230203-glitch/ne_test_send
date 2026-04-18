#include "../../inc/ne_afxdp_pair.h"
#include "../../inc/ne_afxdp_fq_pool.h"

#include <linux/if_xdp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <xdp/xsk.h>

int ne_afxdp_tx_ing(struct ne_afxdp_pair *p, uint64_t addr, uint32_t len)
{
	if (!p->ing.xsk || len == 0 || len > p->frame_size)
		return -1;
	ne_afxdp_drain_ing_cq(p);

	uint32_t tx_idx;
	if (xsk_ring_prod__reserve(&p->ing.tx, 1, &tx_idx) != 1) {
		ne_afxdp_drain_ing_cq(p);
		if (xsk_ring_prod__reserve(&p->ing.tx, 1, &tx_idx) != 1)
			return -1;
	}

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&p->ing.tx, tx_idx);
	d->addr = addr;
	d->len = len;
	d->options = 0;
	xsk_ring_prod__submit(&p->ing.tx, 1);

	(void)sendto(xsk_socket__fd(p->ing.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	p->ing.tx_packets++;
	p->ing.tx_bytes += len;
	return 0;
}
