#include "../inc/ingress_afxdp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void ingress_tx_reclaim(struct xsk_interface *iface)
{
	uint32_t idx = 0;
	int n = xsk_ring_cons__peek(&iface->comp, (int)iface->ring_size, &idx);
	if (n <= 0)
		return;
	for (int i = 0; i < n; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&iface->comp, idx + i);
		if (iface->tx_free_n < iface->tx_nfr)
			iface->tx_free[iface->tx_free_n++] = a;
	}
	xsk_ring_cons__release(&iface->comp, n);
}

int ingress_tx_pool_init(struct xsk_interface *iface)
{
	if (!iface->bufs || iface->frame_size == 0)
		return -1;
	uint32_t nfr = (uint32_t)(iface->umem_size / (size_t)iface->frame_size);
	if (nfr <= iface->ring_size)
		return -1;
	iface->tx_nfr = nfr - iface->ring_size;
	iface->tx_free = calloc(iface->tx_nfr, sizeof(uint64_t));
	if (!iface->tx_free)
		return -1;
	iface->tx_free_n = 0;
	for (uint32_t i = iface->ring_size; i < nfr; i++)
		iface->tx_free[iface->tx_free_n++] = (uint64_t)i * iface->frame_size;
	return 0;
}

void ingress_tx_pool_fini(struct xsk_interface *iface)
{
	free(iface->tx_free);
	iface->tx_free = NULL;
	iface->tx_free_n = 0;
	iface->tx_nfr = 0;
}

int interface_send(struct xsk_interface *iface, const void *pkt, uint32_t len)
{
	if (!iface->xsk || len == 0 || len > iface->frame_size)
		return -1;
	if (!iface->tx_free)
		return -1;

	ingress_tx_reclaim(iface);
	if (iface->tx_free_n == 0) {
		ingress_tx_reclaim(iface);
		if (iface->tx_free_n == 0)
			return -1;
	}

	uint64_t addr = iface->tx_free[--iface->tx_free_n];
	memcpy((uint8_t *)iface->bufs + addr, pkt, len);

	uint32_t tx_idx = 0;
	if (xsk_ring_prod__reserve(&iface->tx, 1, &tx_idx) != 1) {
		iface->tx_free[iface->tx_free_n++] = addr;
		return -1;
	}

	struct xdp_desc *d = xsk_ring_prod__tx_desc(&iface->tx, tx_idx);
	d->addr = addr;
	d->len = len;
	xsk_ring_prod__submit(&iface->tx, 1);

	if (xsk_ring_prod__needs_wakeup(&iface->tx)) {
		int rc = sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (rc < 0 && errno != EAGAIN && errno != EBUSY && errno != ENOBUFS)
			return -1;
	}

	iface->tx_packets++;
	iface->tx_bytes += len;
	return 0;
}
