CLANG ?= clang
CC ?= cc

MULTIARCH := $(shell $(CC) -dumpmachine)

BPF_CFLAGS := -target bpf \
	-I/usr/include/$(MULTIARCH) \
	-O2 -g -Wall -Werror

.PHONY: all clean

all: physdump

bpf/phys_dump.bpf.o: bpf/phys_dump.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

physdump: main.go go.mod bpf/phys_dump.bpf.o
	CGO_ENABLED=0 go build -trimpath -o $@ .

clean:
	rm -f physdump bpf/phys_dump.bpf.o