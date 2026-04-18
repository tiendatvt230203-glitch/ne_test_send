PKG_CONFIG ?= pkg-config
CC ?= gcc

PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags libxdp libbpf 2>/dev/null)
PC_LIBS := $(shell $(PKG_CONFIG) --libs libxdp libbpf 2>/dev/null)

ifneq ($(PC_LIBS),)
CFLAGS := -O2 -g -Wall -Wextra $(PC_CFLAGS)
LDLIBS := $(PC_LIBS) -lpthread
else
CFLAGS := -O2 -g -Wall -Wextra
LDLIBS := -lxdp -lbpf -lelf -lz -lpthread
endif

APP := zc_afxdp
SRCS := main.c cpu.c pkt.c rings.c tx.c ctx.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(APP)

$(OBJS): %.o: %.c zc.h
	$(CC) $(CFLAGS) -c $< -o $@

$(APP): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDLIBS)

clean:
	rm -f $(APP) $(OBJS)
