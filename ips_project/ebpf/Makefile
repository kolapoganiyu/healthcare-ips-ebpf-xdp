# Makefile for xdp_ips.c
CLANG    := clang
CFLAGS   := -O2 -g -Wall -target bpf
INCLUDES := -I/usr/include/x86_64-linux-gnu \
            -I/usr/include

all: xdp_ips.o

xdp_ips.o: xdp_ips.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "✓ Compiled: xdp_ips.o"

clean:
	rm -f xdp_ips.o

.PHONY: all clean
