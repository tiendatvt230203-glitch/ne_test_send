#ifndef XSK_PLANE_H
#define XSK_PLANE_H

#include "common.h"

#define WAN_PORTS 3

struct local_config {
    char     ifname[IF_NAMESIZE];
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
};

struct xsk_interface {
    size_t umem_size;
    uint32_t ring_size;
    uint32_t frame_size;
    uint32_t batch_size;

    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    int ifindex;
    char ifname[IF_NAMESIZE];

    uint64_t rx_packets;
    uint64_t rx_bytes;
};

struct wan_config {
    char ifname[IF_NAMESIZE];
    uint8_t src_mac[ETH_ALEN];
    uint8_t dst_mac[ETH_ALEN];
};

struct wan_port {
    char ifname[IF_NAMESIZE];
    int ifindex;
    size_t umem_size;
    uint32_t frame_size;
    uint32_t ring_size;

    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    uint64_t *free_addrs;
    uint32_t free_count;
    uint32_t free_cap;

    uint64_t tx_packets;
    uint64_t tx_bytes;
};

int interface_init_local(struct xsk_interface *iface, const struct local_config *local_cfg,
                         const char *bpf_file);

void interface_cleanup(struct xsk_interface *iface);

int interface_recv(struct xsk_interface *iface, void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts);

void interface_recv_release(struct xsk_interface *iface, uint64_t *addrs, int count);

int wan_port_init(struct wan_port *port, const struct wan_config *cfg, uint32_t ring_size,
                  uint32_t frame_size, uint32_t umem_mb);
void wan_port_cleanup(struct wan_port *port);
int wan_send_one(struct wan_port *port, const void *pkt, uint32_t len,
                 const uint8_t src_mac[ETH_ALEN], const uint8_t dst_mac[ETH_ALEN]);

#endif
