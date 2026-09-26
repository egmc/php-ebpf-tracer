# syntax=docker/dockerfile:1
#
# Builds the eBPF object and the Go userspace agent.
#
FROM golang:1.25-bookworm AS build

ARG LIBBPF_VERSION=1.5.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libelf-dev zlib1g-dev make git pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# libbpf is linked statically into the agent so the runtime image only needs
# libelf/zlib. libbpfgo >= 0.10 requires libbpf 1.5.x.
RUN git clone --depth 1 -b "v${LIBBPF_VERSION}" https://github.com/libbpf/libbpf /tmp/libbpf \
    && make -C /tmp/libbpf/src BUILD_STATIC_ONLY=y PREFIX=/usr LIBDIR=/usr/lib install install_uapi_headers \
    && rm -rf /tmp/libbpf

WORKDIR /src

# Dependencies first so edits to the source do not invalidate the module cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN make bpf go-build BPF_OBJ=/out/php_tracer.bpf.o BIN=/out/php-ebpf-tracer

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/php-ebpf-tracer /usr/local/bin/php-ebpf-tracer
COPY --from=build /out/php_tracer.bpf.o /usr/local/lib/php-ebpf-tracer/php_tracer.bpf.o

ENV PHP_TRACER_BPF_OBJECT=/usr/local/lib/php-ebpf-tracer/php_tracer.bpf.o

ENTRYPOINT ["/usr/local/bin/php-ebpf-tracer"]
