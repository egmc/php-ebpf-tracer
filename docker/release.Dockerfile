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
FROM golang:1.25-alpine3.22@sha256:65b4400aee0927412e9ed791a11893273a49d55df24841f7599660fb80dae464 AS build

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
