# No syntax directive: BuildKit's built-in frontend handles RUN --mount, and
# the build then pulls no frontend image from the registry.
#
# Static release build. musl lets everything, libc included, be linked
# statically, so the binary runs on any Linux distribution. `make release`
# drives it; the archives land in dist/<os>_<arch>/.
#
# The image is pinned by digest, as whatever it contains ends up in the
# released binary; Dependabot keeps the digest current. scripts/dist.sh takes
# the Alpine version, which selects the packaging it publishes, from the image.
FROM golang:1.26-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56 AS build

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
