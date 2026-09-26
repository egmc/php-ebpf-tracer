# php-ebpf-tracer
#
# `make` builds both the eBPF object and the Go agent. Everything here assumes
# a Linux build host with clang, libbpf (>= 1.5) headers and Go installed; use
# `make docker-build` from macOS.

ARCH      := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/armv7l/arm/')
MULTIARCH := $(shell uname -m)-linux-gnu
CLANG     ?= clang
GO        ?= go

BPF_SRC   := bpf/php_tracer.bpf.c
BPF_HDR   := bpf/php_tracer.h
BPF_OBJ   ?= build/php_tracer.bpf.o
BIN       ?= build/php-ebpf-tracer

BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(MULTIARCH) -Ibpf

export CGO_ENABLED := 1
export CGO_CFLAGS  ?= -I/usr/include
export CGO_LDFLAGS ?= -lbpf -lelf -lz

.PHONY: all bpf go-build clean test docker-build up down logs

all: bpf go-build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR)
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	@llvm-strip -g $@ 2>/dev/null || true

go-build:
	@mkdir -p $(dir $(BIN))
	$(GO) build -trimpath -o $(BIN) ./cmd/php-ebpf-tracer

test:
	$(GO) test ./...

clean:
	rm -rf build

# --- macOS / any host: everything runs in containers -------------------------

docker-build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f tracer
