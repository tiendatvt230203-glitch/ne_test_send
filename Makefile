# Userspace + BPF object cho xdp_redirect
CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

BPF_SRC := bpf/xdp_redirect.c
BPF_OBJ := bpf/xdp_redirect.o

APP := ne-sniff
SRCS := main.c src/ne_app.c src/netdev_xdp_link.c src/ingress_afxdp_init.c src/ingress_afxdp_recv.c \
	src/wan_afxdp_tx.c src/wan_packet_out.c
OBJS := $(SRCS:.c=.o)

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

all: $(BPF_OBJ) $(APP)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OBJS): %.o: %.c
	$(CC) $(USR_CFLAGS) -c $< -o $@

$(APP): $(OBJS)
	$(CC) -o $@ $(OBJS) $(USR_LIBS)

clean:
	rm -f $(APP) $(OBJS) $(BPF_OBJ)

