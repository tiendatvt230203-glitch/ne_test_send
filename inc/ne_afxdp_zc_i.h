#ifndef NE_AFXDP_ZC_I_H
#define NE_AFXDP_ZC_I_H

#include "ne_afxdp_pair.h"

int ne_afxdp_zc_prime_fq(struct ne_afxdp_pair *p, uint32_t ring_size);
void ne_afxdp_zc_frame_pool_destroy(struct ne_afxdp_pair *p);
void ne_afxdp_zc_fq_locks_destroy(struct ne_afxdp_pair *p);

#endif
