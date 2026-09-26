# php-ebpf-tracer
#
# `make` builds both the eBPF object and the Go agent. Everything here assumes
# a Linux build host with clang, libbpf (>= 1.5) headers and Go installed; use
# `make docker-build` from macOS.
#
# `make LIBBPF_BUNDLED=1` instead builds libbpf from the `libbpf` git submodule
# (pinned to the version libbpfgo expects) and links it statically, so only
# clang, libelf, zlib and Go are needed on the host.

ARCH      := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/armv7l/arm/')
MULTIARCH := $(shell uname -m)-linux-gnu
CLANG     ?= clang
GO        ?= go

BPF_SRC   := bpf/php_tracer.bpf.c
BPF_HDR   := bpf/php_tracer.h
BPF_OBJ   ?= build/php_tracer.bpf.o
BIN       ?= build/php-ebpf-tracer

LIBBPF_BUNDLED ?= 0
LIBBPF_SRC     := libbpf/src
LIBBPF_OUT     := $(abspath build/libbpf)
LIBBPF_A       := $(LIBBPF_OUT)/lib/libbpf.a

ifeq ($(LIBBPF_BUNDLED),1)
LIBBPF_INC  := -I$(LIBBPF_OUT)/include
LIBBPF_DEP  := $(LIBBPF_A)
CGO_CFLAGS  := $(LIBBPF_INC)
CGO_LDFLAGS := $(LIBBPF_A) -lelf -lz
endif

BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
              $(LIBBPF_INC) -I/usr/include/$(MULTIARCH) -Ibpf

export CGO_ENABLED := 1
export CGO_CFLAGS  ?= -I/usr/include
export CGO_LDFLAGS ?= -lbpf -lelf -lz

.PHONY: all bpf go-build libbpf clean test docker-build up down logs

all: bpf go-build

bpf: $(BPF_OBJ)

# --- bundled libbpf (LIBBPF_BUNDLED=1) ---------------------------------------

libbpf: $(LIBBPF_A)

$(LIBBPF_SRC)/Makefile:
	git submodule update --init libbpf

$(LIBBPF_A): $(LIBBPF_SRC)/Makefile
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=y OBJDIR=$(LIBBPF_OUT)/obj \
		PREFIX=$(LIBBPF_OUT) LIBDIR=$(LIBBPF_OUT)/lib \
		INCLUDEDIR=$(LIBBPF_OUT)/include UAPIDIR=$(LIBBPF_OUT)/include \
		install install_uapi_headers

# -----------------------------------------------------------------------------

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) | $(LIBBPF_DEP)
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	@llvm-strip -g $@ 2>/dev/null || true

go-build: | $(LIBBPF_DEP)
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
