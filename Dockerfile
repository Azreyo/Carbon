FROM alpine:edge AS builder

RUN apk add --no-cache \
    gcc \
    g++ \
    make \
    musl-dev \
    linux-headers \
    openssl-dev \
    file-dev \
    nghttp2-dev \
    zlib-dev \
    git \
    ca-certificates \
    && apk update \
    && apk upgrade --available

WORKDIR /build

RUN git clone --depth 1 --branch main https://github.com/Azreyo/Carbon.git . && \
    make clean && make release

FROM alpine:edge

RUN apk add --no-cache \
    libssl3 \
    libmagic \
    nghttp2-libs \
    zlib \
    ca-certificates \
    curl \
    && apk update \
    && apk upgrade --available \
    && rm -rf /tmp/* /var/cache/apk/*

RUN adduser -D -u 1000 -s /bin/sh carbon

WORKDIR /app
RUN mkdir -p /app/www /app/log /app/ssl/cert /app/ssl/key && \
    chown -R carbon:carbon /app && \
    chmod 755 /app && \
    chmod 750 /app/ssl

COPY --from=builder --chown=carbon:carbon /build/server /app/
COPY --from=builder --chown=carbon:carbon /build/www/ /app/www/
COPY --from=builder --chown=carbon:carbon /build/README.md /app/
COPY --from=builder --chown=carbon:carbon /build/DOCUMENTATION.md /app/
COPY --from=builder --chown=carbon:carbon /build/LICENSE /app/
COPY --chown=carbon:carbon entrypoint.sh /app/entrypoint.sh

RUN chmod 500 /app/server /app/entrypoint.sh

USER carbon

ENV SERVER_NAME=0.0.0.0 \
    PORT=8080 \
    USE_HTTPS=false \
    ENABLE_HTTP2=false \
    ENABLE_WEBSOCKET=false \
    MAX_THREADS=4 \
    VERBOSE=true

EXPOSE 8080 8443

ENTRYPOINT ["/app/entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f -s http://localhost:${PORT:-8080}/ || exit 1
