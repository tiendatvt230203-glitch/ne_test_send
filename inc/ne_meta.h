#ifndef NE_META_H
#define NE_META_H

#include <stdint.h>

#define NE_MAGIC 0x4e453031u

#define NE_NUM_WORKERS 10u

enum ne_dir {
	NE_DIR_TO_WAN = 0,
	NE_DIR_TO_CLIENT = 1,
};

struct ne_flow_meta {
	uint32_t magic;
	uint32_t conn_id;
	uint8_t worker_idx;
	uint8_t part;
	uint8_t dir;
	uint8_t reserved;
};

#endif
