#ifndef NETDEV_XDP_INTERNAL_H
#define NETDEV_XDP_INTERNAL_H

#include <linux/types.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

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

#endif
