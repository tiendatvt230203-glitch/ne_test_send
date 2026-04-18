#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "zc.h"

#include <sys/socket.h>
#include <unistd.h>

int zc_tx_one(struct zc *z, uint64_t addr, uint32_t len)
{
	zc_drain_cq(z);
	uint32_t tx_idx;
	if (xsk_ring_prod__reserve(&z->tx, 1, &tx_idx) != 1) {
		zc_drain_cq(z);
		if (xsk_ring_prod__reserve(&z->tx, 1, &tx_idx) != 1)
			return -1;
	}
	void *data = xsk_umem__get_data(z->umem_area, xsk_umem__add_offset_to_addr(addr));
	zc_build_pkt(data, len);

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&z->tx, tx_idx);
	d->addr = addr;
	d->len = len;
	d->options = 0;
	xsk_ring_prod__submit(&z->tx, 1);
	(void)sendto(xsk_socket__fd(z->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	return 0;
}
