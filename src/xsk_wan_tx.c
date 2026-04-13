#include "../inc/xsk_plane.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static void wan_reclaim_completions(struct wan_port *port)
{
    uint32_t idx = 0;
    int n = xsk_ring_cons__peek(&port->comp, port->ring_size, &idx);
    if (n <= 0)
        return;

    for (int i = 0; i < n; i++) {
        if (port->free_count < port->free_cap)
            port->free_addrs[port->free_count++] = *xsk_ring_cons__comp_addr(&port->comp, idx + i);
    }
    xsk_ring_cons__release(&port->comp, n);
}

int wan_port_init(struct wan_port *port, const struct wan_config *cfg, uint32_t ring_size,
                  uint32_t frame_size, uint32_t umem_mb)
{
    memset(port, 0, sizeof(*port));
    strncpy(port->ifname, cfg->ifname, IF_NAMESIZE - 1);
    port->ifindex = if_nametoindex(cfg->ifname);
    if (port->ifindex == 0)
        return -1;

    port->ring_size = ring_size;
    port->frame_size = frame_size;
    port->umem_size = (size_t)umem_mb * 1024 * 1024;

    if (posix_memalign(&port->bufs, getpagesize(), port->umem_size) != 0 || !port->bufs)
        return -1;
    (void)mlock(port->bufs, port->umem_size);

    struct xsk_umem_config umem_cfg = {
        .fill_size = ring_size,
        .comp_size = ring_size,
        .frame_size = frame_size,
        .frame_headroom = 0,
        .flags = 0,
    };
    int ret = xsk_umem__create(&port->umem, port->bufs, port->umem_size, &port->fill, &port->comp,
                               &umem_cfg);
    if (ret) {
        munlock(port->bufs, port->umem_size);
        free(port->bufs);
        port->bufs = NULL;
        return -1;
    }

    struct xsk_socket_config sock_cfg = {
        .rx_size = ring_size,
        .tx_size = ring_size,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
    };

    ret = xsk_socket__create(&port->xsk, port->ifname, 0, port->umem, &port->rx, &port->tx, &sock_cfg);
    if (ret) {
        xsk_umem__delete(port->umem);
        port->umem = NULL;
        munlock(port->bufs, port->umem_size);
        free(port->bufs);
        port->bufs = NULL;
        return -1;
    }

    port->free_cap = (uint32_t)(port->umem_size / (size_t)port->frame_size);
    if (port->free_cap == 0) {
        wan_port_cleanup(port);
        return -1;
    }
    port->free_addrs = calloc(port->free_cap, sizeof(uint64_t));
    if (!port->free_addrs) {
        wan_port_cleanup(port);
        return -1;
    }
    port->free_count = port->free_cap;
    for (uint32_t i = 0; i < port->free_cap; i++)
        port->free_addrs[i] = (uint64_t)i * port->frame_size;

    return 0;
}

void wan_port_cleanup(struct wan_port *port)
{
    free(port->free_addrs);
    port->free_addrs = NULL;
    port->free_count = 0;
    port->free_cap = 0;

    if (port->xsk)
        xsk_socket__delete(port->xsk);
    if (port->umem)
        xsk_umem__delete(port->umem);
    if (port->bufs) {
        munlock(port->bufs, port->umem_size);
        free(port->bufs);
    }
    memset(port, 0, sizeof(*port));
}

int wan_send_one(struct wan_port *port, const void *pkt, uint32_t len,
                 const uint8_t src_mac[ETH_ALEN], const uint8_t dst_mac[ETH_ALEN])
{
    if (!port->xsk || len < sizeof(struct ethhdr) || len > port->frame_size)
        return -1;

    wan_reclaim_completions(port);
    if (port->free_count == 0) {
        wan_reclaim_completions(port);
        if (port->free_count == 0)
            return -1;
    }

    uint64_t addr = port->free_addrs[--port->free_count];
    uint8_t *frame = (uint8_t *)port->bufs + addr;
    memcpy(frame, pkt, len);

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);

    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&port->tx, 1, &idx) != 1) {
        port->free_addrs[port->free_count++] = addr;
        return -1;
    }

    struct xdp_desc *d = xsk_ring_prod__tx_desc(&port->tx, idx);
    d->addr = addr;
    d->len = len;
    xsk_ring_prod__submit(&port->tx, 1);
    (void)sendto(xsk_socket__fd(port->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    port->tx_packets++;
    port->tx_bytes += len;
    return 0;
}
