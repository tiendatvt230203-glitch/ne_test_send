CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

BPF_SRC := bpf/xdp_redirect.c
BPF_OBJ := bpf/xdp_redirect.o

APP := ne

LINK_SRCS := main.c src/ne_afxdp.c src/ne_threads.c
LINK_OBJS := $(LINK_SRCS:.c=.o)

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

BPF_CFLAGS := -O2 -g -Wall -Wextra -target bpf \
	-D__TARGET_ARCH_$(ARCH)

.PHONY: all clean

all: $(BPF_OBJ) $(APP)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LINK_OBJS): %.o: %.c inc/ne.h
	$(CC) $(USR_CFLAGS) -c $< -o $@

$(APP): $(LINK_OBJS)
	$(CC) -o $@ $(LINK_OBJS) $(USR_LIBS)

clean:
	rm -f $(APP)
	find . -name '*.o' -type f -delete
	find src -type d -empty -delete 2>/dev/null || true
