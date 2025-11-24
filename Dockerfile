FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    libssl-dev \
    libmagic-dev \
    libnghttp2-dev \
    pkg-config \
    zlib1g-dev \
    build-essential \
    git \
    ca-certificates \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /build

RUN git clone --depth 1 --branch main https://github.com/Azreyo/Carbon.git . && \
    make clean && make release

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libmagic1 \
    libnghttp2-14 \
    zlib1g \
    ca-certificates \
    curl \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*


RUN useradd -m -u 1000 -s /bin/bash carbon

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

RUN chmod 500 /app/server

USER carbon

ENV SERVER_NAME=0.0.0.0 \
    PORT=8080 \
    USE_HTTPS=false \
    ENABLE_HTTP2=false \
    ENABLE_WEBSOCKET=false \
    MAX_THREADS=4 \
    VERBOSE=true

CMD echo "# Carbon Server Configuration (Generated from ENV)" > /app/server.conf && \
    echo "running = true" >> /app/server.conf && \
    echo "port = ${PORT}" >> /app/server.conf && \
    echo "use_https = ${USE_HTTPS}" >> /app/server.conf && \
    echo "enable_http2 = ${ENABLE_HTTP2}" >> /app/server.conf && \
    echo "enable_websocket = ${ENABLE_WEBSOCKET}" >> /app/server.conf && \
    echo "server_name = ${SERVER_NAME}" >> /app/server.conf && \
    echo "max_threads = ${MAX_THREADS}" >> /app/server.conf && \
    echo "max_connections = 1024" >> /app/server.conf && \
    echo "log_file = log/server.log" >> /app/server.conf && \
    echo "verbose = ${VERBOSE}" >> /app/server.conf && \
    echo "www_path = www" >> /app/server.conf && \
    echo "ssl_cert_path = ssl/cert/cert.pem" >> /app/server.conf && \
    echo "ssl_key_path = ssl/key/key.key" >> /app/server.conf && \
    ./server

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/ || exit 1
