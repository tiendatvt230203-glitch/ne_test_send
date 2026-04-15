#ifndef NETDEV_XDP_INTERNAL_H
#define NETDEV_XDP_INTERNAL_H

#include "ingress_afxdp.h"
#include <linux/types.h>
#include <stddef.h>

void iface_xdp_try_detach(int ifindex, const char *ifname);
int iface_xdp_attach(int ifindex, int prog_fd, __u32 flags);

int iface_local_umem_ok(const char *ifname, const struct local_config *lc, size_t umem_bytes);

#endif
