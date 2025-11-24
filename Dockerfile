FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils \
    gcc \
    make \
    libssl-dev \
    libmagic-dev \
    libnghttp2-dev \
    pkg-config \
    build-essential \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /build

RUN git clone --depth 1 --branch main https://github.com/Azreyo/Carbon.git . && \
    make clean && make release

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils \
    libssl3 \
    libmagic1 \
    libnghttp2-14 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*


RUN useradd -m -u 1000 -s /bin/bash carbon

WORKDIR /app
RUN mkdir -p /app/www /app/log /app/ssl/cert && \
    chown -R carbon:carbon /app

COPY --from=builder /build/server /app/
COPY --from=builder /build/server.conf /app/
COPY --from=builder /build/www/ /app/www/
COPY --from=builder /build/README.md /app/
COPY --from=builder /build/DOCUMENTATION.md /app/
COPY --from=builder /build/LICENSE /app/

RUN chown -R carbon:carbon /app

USER carbon

EXPOSE 8080 443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

CMD ["./server"]