# syntax=docker/dockerfile:1
#
# PHP built with --enable-dtrace, which is what emits the USDT/SDT notes
# (php:request__startup, php:function__entry, ...) this tracer attaches to.
# None of the distro packages ship that, so PHP is compiled from source.
#
FROM debian:bookworm-slim AS build

ARG PHP_VERSION=8.3.35

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config autoconf bison re2c \
        libxml2-dev libsqlite3-dev libssl-dev zlib1g-dev libonig-dev \
        systemtap-sdt-dev \
        ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL "https://www.php.net/distributions/php-${PHP_VERSION}.tar.gz" -o php.tar.gz \
    && tar -xf php.tar.gz \
    && rm php.tar.gz

# --enable-dtrace is the only option that really matters here; the rest keeps
# the build small and fast. Add extensions as your workload needs them.
RUN cd "php-${PHP_VERSION}" \
    && ./configure \
        --prefix=/usr/local \
        --enable-dtrace \
        --enable-cli \
        --enable-fpm \
        --with-openssl \
        --with-zlib \
        --enable-mbstring \
        --disable-cgi \
        --disable-phpdbg \
        --without-pear \
    && make -j"$(nproc)" \
    && make -j"$(nproc)" install

# Keep the SDT notes (.note.stapsdt) intact; only debug info is removed.
# Fail the build if the markers the tracer needs are missing.
RUN strip --strip-debug /usr/local/bin/php /usr/local/sbin/php-fpm \
    && for probe in request__startup request__shutdown function__entry function__return; do \
           readelf -n /usr/local/bin/php | grep -q "Name: $probe$" \
               || { echo "missing USDT probe php:$probe"; exit 1; }; \
       done \
    && echo "USDT probes present:" \
    && readelf -n /usr/local/bin/php | grep -c 'Provider: php'

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 libssl3 zlib1g libonig5 libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/php /usr/local/bin/php
COPY --from=build /usr/local/sbin/php-fpm /usr/local/sbin/php-fpm
COPY --from=build /usr/local/lib/php /usr/local/lib/php

COPY examples/ /app/

WORKDIR /app

# php:function__entry / php:function__return only fire when the dtrace variants
# of zend_execute_ex and zend_compile_file are installed, and PHP only does
# that when this variable is set at startup (Zend/zend.c). The request probes
# fire regardless.
ENV USE_ZEND_DTRACE=1

RUN php -v

EXPOSE 8080

# One HTTP request == one php:request__startup / php:request__shutdown pair.
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app", "/app/index.php"]
