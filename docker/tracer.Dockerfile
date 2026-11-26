# syntax=docker/dockerfile:1
#
# Builds the agent for the docker compose demo. The BPF object is embedded in
# the binary and libbpf comes from the git submodule, linked statically, so the
# runtime image only needs libelf and its compression libraries.
#
FROM golang:1.25-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libelf-dev zlib1g-dev make git pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first so edits to the source do not invalidate the module cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    make LIBBPF_BUNDLED=1 VERSION=docker BIN=/out/php-ebpf-tracer

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 zlib1g libzstd1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/php-ebpf-tracer /usr/local/bin/php-ebpf-tracer

ENTRYPOINT ["/usr/local/bin/php-ebpf-tracer"]
