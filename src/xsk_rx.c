#include "../inc/xsk_plane.h"

#include <poll.h>
#include <stdint.h>

int interface_recv(struct xsk_interface *iface, void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts)
{
    if (!iface->xsk)
        return 0;

    uint32_t idx_rx = 0;
    int rcvd = xsk_ring_cons__peek(&iface->rx, max_pkts, &idx_rx);
    if (rcvd == 0) {
        struct pollfd pfd = {.fd = xsk_socket__fd(iface->xsk), .events = POLLIN};
        if (poll(&pfd, 1, 1) <= 0)
            return 0;
        rcvd = xsk_ring_cons__peek(&iface->rx, max_pkts, &idx_rx);
        if (rcvd == 0)
            return 0;
    }

    for (int j = 0; j < rcvd; j++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&iface->rx, idx_rx + j);
        addrs[j] = desc->addr;
        pkt_ptrs[j] = (uint8_t *)iface->bufs + desc->addr;
        pkt_lens[j] = desc->len;
    }
    xsk_ring_cons__release(&iface->rx, rcvd);

    iface->rx_packets += (uint64_t)rcvd;
    for (int j = 0; j < rcvd; j++)
        iface->rx_bytes += pkt_lens[j];
    return rcvd;
}

void interface_recv_release(struct xsk_interface *iface, uint64_t *addrs, int count)
{
    if (!iface->xsk)
        return;

    for (int i = 0; i < count; i++) {
        uint32_t idx_fill;
        int ret = xsk_ring_prod__reserve(&iface->fill, 1, &idx_fill);
        if (ret != 1) {
            uint32_t comp_idx;
            int comp = xsk_ring_cons__peek(&iface->comp, iface->batch_size, &comp_idx);
            if (comp > 0)
                xsk_ring_cons__release(&iface->comp, comp);
            ret = xsk_ring_prod__reserve(&iface->fill, 1, &idx_fill);
            if (ret != 1)
                continue;
        }
        *xsk_ring_prod__fill_addr(&iface->fill, idx_fill) = (uint32_t)addrs[i];
        xsk_ring_prod__submit(&iface->fill, 1);
    }
}
