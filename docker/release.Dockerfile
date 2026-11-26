# syntax=docker/dockerfile:1
#
# Static release build. musl lets everything, libc included, be linked
# statically, so the binary runs on any Linux distribution. `make release`
# drives it; the archives land in dist/<os>_<arch>/.
#
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

RUN apk add --no-cache \
        build-base clang llvm linux-headers pkgconf \
        elfutils-dev zlib-dev zlib-static zstd-dev zstd-static \
        curl tar bzip2 git file

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    make STATIC=1 VERSION="${VERSION}" test dist \
 && file build/php-ebpf-tracer \
 && ./build/php-ebpf-tracer -version

FROM scratch
COPY --from=build /src/dist/ /
