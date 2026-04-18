CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

BPF_SRC := bpf/xdp_redirect.c
BPF_OBJ := bpf/xdp_redirect.o

BPF_WAN_SRC := bpf/xdp_wan_redirect_ne.c
BPF_WAN_OBJ := bpf/xdp_wan_redirect_ne.o

APP := ne

LINK_SRCS := main.c \
	src/cfg/netdev_xdp_link.c src/cfg/ne_afxdp_pair.c \
	src/cfg/ne_pkt_ring.c src/cfg/ne_pipeline.c \
	src/rx/ne_afxdp_fq_pool.c src/rx/ne_afxdp_from_local.c src/rx/ne_afxdp_from_wan.c \
	src/tx/ne_afxdp_to_local.c src/tx/ne_afxdp_to_wan.c \
	src/rx/ne_pipeline_core.c src/tx/ne_pipeline_tx.c
LINK_OBJS := $(LINK_SRCS:.c=.o)
ALL_OBJS := $(LINK_OBJS)

BPF_CFLAGS := -O2 -g -Wall -Wextra -target bpf \
	-D__TARGET_ARCH_$(ARCH)

PKG_CONFIG ?= pkg-config
LIBXDP_CFLAGS := $(shell $(PKG_CONFIG) --cflags libxdp 2>/dev/null)
LIBXDP_LIBS := $(shell $(PKG_CONFIG) --libs libxdp 2>/dev/null)
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)

ifneq ($(LIBXDP_CFLAGS),)
USR_CFLAGS := -O2 -g -Wall -Wextra $(LIBXDP_CFLAGS) $(LIBBPF_CFLAGS) -Iinc
USR_LIBS := $(LIBXDP_LIBS) $(LIBBPF_LIBS) -lpthread
else
USR_CFLAGS := -O2 -g -Wall -Wextra -Iinc
USR_LIBS := -lxdp -lbpf -lelf -lz -lpthread
endif

.PHONY: all clean

all: $(BPF_OBJ) $(BPF_WAN_OBJ) $(APP)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_WAN_OBJ): $(BPF_WAN_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(ALL_OBJS): %.o: %.c
	$(CC) $(USR_CFLAGS) -c $< -o $@

$(APP): $(LINK_OBJS)
	$(CC) -o $@ $(LINK_OBJS) $(USR_LIBS)

clean:
	rm -f $(APP)
	find . -name '*.o' -type f -delete
