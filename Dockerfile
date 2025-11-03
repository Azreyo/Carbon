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
    && rm -rf /var/lib/apt/lists/*


WORKDIR /build

COPY src/ ./src/
COPY Makefile .
COPY server.conf .

RUN make clean && make release

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

COPY www/ ./www/

COPY README.md DOCUMENTATION.md LICENSE ./

RUN chown -R carbon:carbon /app

USER carbon

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

CMD ["./server"]