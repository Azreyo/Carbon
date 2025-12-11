FROM alpine:3.19 AS builder

# Install build dependencies
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
    && rm -rf /var/cache/apk/*

WORKDIR /build

COPY . .

RUN make clean && make release


FROM alpine:3.19

LABEL maintainer="Carbon Team" \
      version="1.0" \
      description="Carbon Web Server - High Performance HTTP Server"

RUN apk add --no-cache \
    libssl3 \
    libmagic \
    nghttp2-libs \
    zlib \
    ca-certificates \
    curl \
    && rm -rf /var/cache/apk/* /tmp/*

RUN addgroup -g 1000 carbon && \
    adduser -D -u 1000 -G carbon -s /sbin/nologin carbon

WORKDIR /app

RUN mkdir -p /app/www /app/log /app/ssl/cert /app/ssl/key && \
    chown -R carbon:carbon /app && \
    chmod 755 /app /app/www /app/log && \
    chmod 700 /app/ssl /app/ssl/cert /app/ssl/key

COPY --from=builder --chown=carbon:carbon /build/server /app/
COPY --from=builder --chown=carbon:carbon /build/www/ /app/www/
COPY --from=builder --chown=carbon:carbon /build/README.md /app/
COPY --from=builder --chown=carbon:carbon /build/DOCUMENTATION.md /app/
COPY --from=builder --chown=carbon:carbon /build/LICENSE /app/
COPY --chown=carbon:carbon entrypoint.sh /app/entrypoint.sh

RUN chmod 500 /app/server /app/entrypoint.sh && \
    chmod 644 /app/README.md /app/DOCUMENTATION.md /app/LICENSE 2>/dev/null || true

USER carbon

ENV SERVER_NAME=0.0.0.0 \
    PORT=8080 \
    USE_HTTPS=false \
    ENABLE_HTTP2=false \
    ENABLE_WEBSOCKET=false \
    MAX_THREADS=4 \
    MAX_CONNECTIONS=1024 \
    LOG_MODE=classic

EXPOSE 8080 8443



ENTRYPOINT ["/app/entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f -s http://localhost:${PORT:-8080}/ || exit 1
