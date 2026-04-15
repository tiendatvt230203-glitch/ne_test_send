#include "../inc/ingress_afxdp.h"
#include "../inc/netdev_xdp_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int iface_xdp_detach(int ifindex, __u32 flags)
{
	return bpf_xdp_detach(ifindex, flags, NULL);
}

int iface_xdp_attach(int ifindex, int prog_fd, __u32 flags)
{
	return bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
}

void iface_xdp_try_detach(int ifindex, const char *ifname)
{
	static const int modes[] = {
		XDP_FLAGS_SKB_MODE,
		XDP_FLAGS_DRV_MODE,
		XDP_FLAGS_HW_MODE,
	};
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		int r = iface_xdp_detach(ifindex, modes[i]);
		if (r < 0) {
			int e = -r;
			if (e != EINVAL && e != EOPNOTSUPP && e != ENODEV && e != ENOENT && ifname)
				fprintf(stderr, "[XDP] %s: detach flags=0x%x ret=%d (%s)\n", ifname,
					(unsigned)modes[i], r, strerror(e));
		}
	}
}

static int umem_sizing_ok(const char *ifname, uint32_t frame_size, uint32_t ring_size, size_t umem_bytes,
			  const char *tag)
{
	if (frame_size == 0 || ring_size == 0) {
		fprintf(stderr, "[%s] %s: frame_size and ring_size must be non-zero\n", tag, ifname);
		return 0;
	}
	size_t nframes = umem_bytes / (size_t)frame_size;
	size_t min_frames = (size_t)ring_size * 2u;
	if (nframes < min_frames) {
		fprintf(stderr,
			"[%s] %s: umem too small: bytes=%zu frame=%u -> frames=%zu, need >= %zu "
			"(2 * ring_size=%u)\n",
			tag, ifname, umem_bytes, frame_size, nframes, min_frames, ring_size);
		return 0;
	}
	return 1;
}

int iface_local_umem_ok(const char *ifname, const struct local_config *lc, size_t umem_bytes)
{
	return umem_sizing_ok(ifname, lc->frame_size, lc->ring_size, umem_bytes, "umem");
}
