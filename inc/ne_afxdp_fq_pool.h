#ifndef NE_AFXDP_FQ_POOL_H
#define NE_AFXDP_FQ_POOL_H

#include <pthread.h>
#include <xdp/xsk.h>

#include "ne_afxdp_pair.h"

int ne_afxdp_fq_replenish_all(struct ne_afxdp_pair *p, struct ne_zc_port *prt, struct xsk_socket *xsk,
			      uint32_t n, pthread_mutex_t *fq_lock);
void ne_afxdp_drain_ing_cq(struct ne_afxdp_pair *p);
void ne_afxdp_drain_wan_cq(struct ne_afxdp_pair *p);

int ne_afxdp_fq_fill_one(struct ne_zc_port *port, struct xsk_socket *xsk, uint64_t addr);

#endif
