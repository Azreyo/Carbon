# Carbon HTTP Server - Complete Documentation
> ⚠️ Warning some features are not implemented yet in the documentation and can be broken. Work in progress

> ⚒️ Features that are WIP will be marked.
## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Installation & Setup](#installation--setup)
4. [Configuration Reference](#configuration-reference)
5. [API Reference](#api-reference)
6. [HTTP/2 Implementation](#http2-implementation)
7. [WebSocket Implementation](#websocket-implementation)
8. [Security Features](#security-features)
9. [Performance Tuning](#performance-tuning)
10. [Troubleshooting](#troubleshooting)
11. [Development Guide](#development-guide)

---

## Introduction

Carbon is a high-performance HTTP/HTTPS server written in C for Linux systems. It provides modern web server capabilities including HTTP/2, WebSocket support, SSL/TLS encryption, and advanced security features.

### Key Features

- **HTTP/2 Protocol**: Full implementation with ALPN negotiation, multiplexing, and HPACK compression
- **WebSocket Support**: RFC 6455 compliant with secure WebSocket (wss://) support
- **SSL/TLS Encryption**: OpenSSL integration with modern cipher suites
- **Asynchronous I/O**: Epoll-based event handling for high concurrency
- **Thread Pooling**: Efficient multi-threaded request handling
- **Security**: Rate limiting, security headers, input sanitization, memory safety

### System Requirements

- **Operating System**: Linux (kernel 2.6.27+)
- **Compiler**: GCC 4.8+ or Clang 3.4+
- **Dependencies**:
  - OpenSSL 1.1.0+ (libssl-dev)
  - libmagic (libmagic-dev)
  - nghttp2 1.0.0+ (libnghttp2-dev)
  - pthread (usually included)

---

## Architecture Overview

### Server Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Carbon HTTP Server                       │
├─────────────────────────────────────────────────────────────┤
│  Main Thread (Epoll Event Loop)                             │
│  ├─── Socket Management                                     │
│  ├─── Connection Acceptance                                 │
│  └─── Event Distribution                                    │
├─────────────────────────────────────────────────────────────┤
│  Worker Thread Pool                                         │
│  ├─── HTTP/1.1 Handler                                      │
│  ├─── HTTP/2 Handler (nghttp2)                              │
│  ├─── WebSocket Handler                                     │
│  └─── SSL/TLS Handler (OpenSSL)                             │
├─────────────────────────────────────────────────────────────┤
│  Core Services                                              │
│  ├─── Configuration Manager                                │
│  ├─── Logging System                                        │
│  ├─── Rate Limiter                                          │
│  ├─── File Cache                                            │
│  └─── MIME Type Detection                                   │
└─────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **Connection Acceptance**: Main thread accepts incoming connections via epoll
2. **SSL/TLS Handshake**: If HTTPS is enabled, OpenSSL performs handshake
3. **Protocol Negotiation**: ALPN determines HTTP/2 or HTTP/1.1
4. **Request Processing**: Worker thread handles the request
5. **Response Generation**: Content is prepared and sent to client
6. **Connection Management**: Keep-alive or close based on protocol

### File Structure

```
Carbon/
├── src/
│   ├── server.c           # Main server implementation
│   ├── server_config.h    # Configuration structures
│   ├── server_config.c    # Configuration management
│   ├── config_parser.c    # Config file parser
│   ├── http2.c            # HTTP/2 implementation
│   ├── http2.h            # HTTP/2 headers
│   ├── websocket.c        # WebSocket implementation
│   └── websocket.h        # WebSocket headers
├── www/                   # Web root directory
├── certs/                 # SSL certificates
├── log/                   # Log files
├── Makefile              # Build configuration
└── server.conf           # Server configuration
```

---

## Installation & Setup

### Quick Installation

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libmagic-dev libnghttp2-dev

# Clone and build
git clone https://github.com/Azreyo/Carbon.git
cd Carbon
make

# Setup directories
mkdir -p certs log www

# Generate test certificates
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Carbon/CN=localhost"

# Run server
sudo ./server
```

### Build Options

```bash
make           # Standard build (-O2 optimization)
make debug     # Debug build with symbols (-g -O0)
make release   # Release build with optimizations (-O3)
make clean     # Remove build artifacts
```

### Production Setup

For production environments:

1. **Use Let's Encrypt certificates** (see [LETSENCRYPT_SETUP.md](LETSENCRYPT_SETUP.md))
2. **Configure firewall rules**:
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```
3. **Set up as systemd service**:
   ```bash
   sudo cp carbon.service /etc/systemd/system/
   sudo systemctl enable carbon
   sudo systemctl start carbon
   ```
4. **Configure log rotation** (see [Logging](#logging) section)

---

## Configuration Reference

### Configuration File Format

Carbon uses a Linux-style configuration file (`server.conf`) with `key = value` pairs. Lines starting with `#` are comments.

### Configuration Options

#### Network Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | integer | 8080 | HTTP port to listen on |
| `https_port` | integer | 443 | HTTPS port to listen on |
| `use_https` | boolean | false | Enable HTTPS |
| `server_name` | string | localhost | Server hostname or IP |

#### Protocol Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_http2` | boolean | true | Enable HTTP/2 (requires HTTPS) |
| `enable_websocket` | boolean | true | Enable WebSocket support |

#### Performance Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_threads` | integer | 4 | Number of worker threads |
| `keep_alive_timeout` | integer | 60 | Keep-alive timeout in seconds |
| `max_connections` | integer | 1000 | Maximum concurrent connections |

#### Logging Settings

> ⚠️ Work in progress

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_file` | string | log/server.log | Path to log file |
| `verbose` | boolean | false | Enable verbose logging |

#### Security Settings

> ⚠️ Work in progress

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rate_limit` | integer | 100 | Requests per IP per minute |
| `enable_hsts` | boolean | true | Enable HSTS header |
| `enable_csp` | boolean | true | Enable CSP header |

### Boolean Value Formats

Boolean options accept multiple formats:
- **True**: `true`, `yes`, `on`, `1`
- **False**: `false`, `no`, `off`, `0`

Values can be quoted with single or double quotes.

### Example Configuration

```conf
# Carbon Web Server Configuration

# Network
port = 8080
https_port = 443
use_https = true
server_name = example.com

# Protocols
enable_http2 = true
enable_websocket = true

# Performance
max_threads = 8
keep_alive_timeout = 60
max_connections = 2000

# Logging
log_file = /var/log/carbon/server.log
verbose = false

# Security
rate_limit = 100
enable_hsts = true
enable_csp = true
```

---

## API Reference

### Configuration API
> ⚠️ Work in progress

#### `parse_config(const char *filename, server_config_t *config)`

Parse configuration file and populate config structure.

**Parameters:**
- `filename`: Path to configuration file
- `config`: Pointer to server_config_t structure

**Returns:** 0 on success, -1 on error

**Example:**
```c
server_config_t config;
if (parse_config("server.conf", &config) != 0) {
    fprintf(stderr, "Failed to parse configuration\n");
    return 1;
}
```

#### `parse_boolean(const char *value)`

Parse boolean value from configuration.

**Parameters:**
- `value`: String value to parse

**Returns:** 1 for true, 0 for false

**Accepted Values:**
- True: "true", "yes", "on", "1"
- False: "false", "no", "off", "0"

### HTTP/2 API

#### `http2_session_init(http2_session_t *session, int socket_fd, SSL *ssl)`

Initialize HTTP/2 session.

**Parameters:**
- `session`: Pointer to http2_session_t structure
- `socket_fd`: Socket file descriptor
- `ssl`: SSL connection (or NULL for plain HTTP)

**Returns:** 0 on success, -1 on error

#### `http2_handle_connection(http2_session_t *session)`

Handle HTTP/2 connection event loop.

**Parameters:**
- `session`: Pointer to initialized http2_session_t

**Returns:** 0 on completion, -1 on error

#### `http2_session_cleanup(http2_session_t *session)`

Clean up HTTP/2 session resources.

**Parameters:**
- `session`: Pointer to http2_session_t to clean up

### WebSocket API

#### `ws_handle_handshake(int socket_fd, SSL *ssl, const char *request)`

Handle WebSocket upgrade handshake.

**Parameters:**
- `socket_fd`: Socket file descriptor
- `ssl`: SSL connection (or NULL for plain WS)
- `request`: HTTP upgrade request

**Returns:** 0 on success, -1 on error

#### `ws_parse_frame(const uint8_t *data, size_t len, ws_frame_t *frame)`

Parse WebSocket frame from raw data.

**Parameters:**
- `data`: Raw frame data
- `len`: Length of data
- `frame`: Pointer to ws_frame_t structure to populate

**Returns:** Number of bytes parsed, -1 on error

#### `ws_send_frame(ws_connection_t *conn, uint8_t opcode, const uint8_t *payload, size_t payload_len)`

Send WebSocket frame to client.

**Parameters:**
- `conn`: WebSocket connection context
- `opcode`: Frame opcode (WS_OPCODE_TEXT, WS_OPCODE_BINARY, etc.)
- `payload`: Frame payload data
- `payload_len`: Length of payload

**Returns:** Number of bytes sent, -1 on error

**Opcodes:**
- `WS_OPCODE_CONTINUATION` (0x0): Continuation frame
- `WS_OPCODE_TEXT` (0x1): Text frame
- `WS_OPCODE_BINARY` (0x2): Binary frame
- `WS_OPCODE_CLOSE` (0x8): Close frame
- `WS_OPCODE_PING` (0x9): Ping frame
- `WS_OPCODE_PONG` (0xA): Pong frame

---

## HTTP/2 Implementation

### Protocol Features

Carbon's HTTP/2 implementation includes:

- **ALPN Negotiation**: Automatic protocol selection during TLS handshake
- **Binary Framing**: Efficient binary protocol implementation
- **Stream Multiplexing**: Multiple concurrent requests over single connection
- **HPACK Compression**: Header compression for reduced bandwidth
- **Server Push**: Proactive resource delivery (configurable)
- **Flow Control**: Per-stream and connection-level flow control
- **Priority**: Stream prioritization support

### HTTP/2 Connection Flow

1. **TLS Handshake**: Client and server negotiate TLS connection
2. **ALPN Negotiation**: Server advertises "h2" protocol support
3. **Connection Preface**: Client sends HTTP/2 connection preface
4. **Settings Exchange**: Both sides exchange SETTINGS frames
5. **Stream Creation**: Client opens streams with HEADERS frames
6. **Data Transfer**: DATA frames carry request/response bodies
7. **Stream Closure**: Streams closed with END_STREAM flag

### Configuration

Enable HTTP/2 in `server.conf`:

```conf
use_https = true
enable_http2 = true
https_port = 443
```

**Note**: HTTP/2 requires HTTPS and valid SSL certificates.

### Testing HTTP/2

```bash
# Test with curl
curl -v --http2 -k https://localhost:443/

# Verify ALPN negotiation
openssl s_client -connect localhost:443 -alpn h2 < /dev/null 2>&1 | grep "ALPN"

# Load testing with h2load
h2load -n 10000 -c 100 -m 10 https://localhost:443/

# Browser DevTools
# Open Chrome DevTools → Network → Protocol column should show "h2"
```

### Performance Tuning

Optimize HTTP/2 performance:

```conf
# Increase worker threads for concurrent streams
max_threads = 16

# Adjust keep-alive for persistent connections
keep_alive_timeout = 120

# Increase max connections
max_connections = 5000
```

### Common Issues

**Issue**: HTTP/2 not negotiated, falling back to HTTP/1.1
- **Solution**: Ensure HTTPS is enabled and SSL certificates are valid
- **Check**: `openssl s_client -connect host:443 -alpn h2`

**Issue**: Slow HTTP/2 performance
- **Solution**: Increase `max_threads` in configuration
- **Check**: Monitor CPU usage and adjust accordingly

---

## WebSocket Implementation

### Protocol Features

Carbon implements RFC 6455 WebSocket protocol:

- **Frame Types**: Text, binary, ping, pong, close frames
- **Masking**: Proper client-to-server masking validation
- **Fragmentation**: Support for fragmented messages
- **UTF-8 Validation**: Text frames validated for UTF-8 encoding
- **Secure WebSocket**: wss:// over TLS support
- **Control Frames**: Ping/pong for connection health checks

### WebSocket Handshake

1. **HTTP Upgrade**: Client sends HTTP upgrade request
2. **Key Exchange**: Server validates Sec-WebSocket-Key
3. **Accept Response**: Server sends Sec-WebSocket-Accept
4. **Protocol Switch**: Connection switches to WebSocket protocol
5. **Frame Exchange**: Binary frame-based communication begins

### Server-Side Implementation

```c
// Check for WebSocket upgrade
if (is_websocket_upgrade(request)) {
    // Perform handshake
    if (ws_handle_handshake(socket_fd, ssl, request) == 0) {
        // Create WebSocket connection
        ws_connection_t ws_conn = {
            .socket_fd = socket_fd,
            .ssl = ssl,
            .is_ssl = (ssl != NULL)
        };
        
        // Handle WebSocket frames
        handle_websocket(&ws_conn);
    }
}
```

### Client-Side Example (JavaScript)

```javascript
// Create WebSocket connection
const ws = new WebSocket('wss://example.com');

// Connection opened
ws.onopen = () => {
    console.log('Connected');
    ws.send('Hello Server!');
};

// Receive messages
ws.onmessage = (event) => {
    console.log('Received:', event.data);
};

// Handle errors
ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

// Connection closed
ws.onclose = (event) => {
    console.log('Disconnected:', event.code, event.reason);
};
```

### Frame Structure

WebSocket frames follow this structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

### Configuration

Enable WebSocket in `server.conf`:

```conf
enable_websocket = true
```

WebSocket works over both HTTP and HTTPS ports.

### Testing WebSocket

```bash
# Install wscat
npm install -g wscat

# Test WebSocket connection
wscat -c ws://localhost:8080

# Test secure WebSocket
wscat -c wss://localhost:443 --no-check

# Send message
> Hello Server

# Server echoes back
< Hello Server
```

### Common Issues

**Issue**: WebSocket connection fails with 400 Bad Request
- **Solution**: Ensure Upgrade and Connection headers are present
- **Check**: Request must include `Upgrade: websocket` and `Connection: Upgrade`

**Issue**: Connection closes immediately
- **Solution**: Check for proper masking in client frames
- **Debug**: Enable verbose logging to see frame details

---

## Security Features

### SSL/TLS Encryption

Carbon uses OpenSSL for SSL/TLS encryption:

- **Protocol Support**: TLS 1.2 and TLS 1.3
- **Cipher Suites**: Modern, secure ciphers only
- **Perfect Forward Secrecy**: ECDHE key exchange
- **Certificate Validation**: Proper certificate chain validation

### Security Headers

Automatically added security headers:

```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

### Rate Limiting

Per-IP rate limiting prevents abuse:

- **Default**: 100 requests per IP per minute
- **Configurable**: Adjust via `rate_limit` setting
- **Automatic Blocking**: Exceeding limit returns 429 Too Many Requests

### Input Sanitization

Protection against common attacks:

- **Path Traversal**: Validates and sanitizes file paths
- **Directory Escapes**: Blocks `..` sequences
- **Null Bytes**: Rejects null bytes in requests
- **Buffer Overflows**: Bounds checking on all buffers

### Memory Safety

Memory management practices:

- **Bounds Checking**: All buffer operations checked
- **Leak Prevention**: Proper resource cleanup
- **Use-After-Free**: Careful pointer management
- **Integer Overflow**: Validation of size calculations

### Best Practices

1. **Use Strong Certificates**: Let's Encrypt or commercial CA
2. **Keep Updated**: Regular security updates
3. **Monitor Logs**: Watch for suspicious activity
4. **Firewall Rules**: Restrict access to necessary ports
5. **Reverse Proxy**: Consider Nginx/Apache frontend
6. **Regular Audits**: Periodic security assessments

---

## Performance Tuning

### Thread Pool Optimization

```conf
# Adjust based on CPU cores
max_threads = <number_of_cores * 2>

# Example for 8-core system
max_threads = 16
```

### Connection Settings

```conf
# Increase for high-traffic sites
max_connections = 10000
keep_alive_timeout = 120
```

### System Limits

Increase system limits for high concurrency:

```bash
# /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536

# /etc/sysctl.conf
net.core.somaxconn = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.ip_local_port_range = 10000 65535
```

### File Caching

Enable file caching for static content:
- Frequently accessed files cached in memory
- Reduces disk I/O overhead
- Automatic cache invalidation

### Zero-Copy Transfers

Carbon uses `sendfile()` for efficient file transfers:
- Eliminates user-space copies
- Reduces CPU usage
- Improves throughput

### Benchmarking

```bash
# Apache Bench
ab -n 10000 -c 100 https://localhost/

# wrk
wrk -t 12 -c 400 -d 30s https://localhost/

# h2load (HTTP/2)
h2load -n 100000 -c 100 -m 100 https://localhost/
```

---

## Troubleshooting

### Common Issues

#### Server Won't Start

**Symptom**: Server exits immediately after starting

**Solutions**:
1. Check if port is already in use:
   ```bash
   sudo lsof -i :443
   ```
2. Verify SSL certificates exist:
   ```bash
   ls -la certs/
   ```
3. Check configuration syntax:
   ```bash
   grep -v '^#' server.conf | grep '='
   ```

#### High CPU Usage

**Symptom**: Server consuming excessive CPU

**Solutions**:
1. Increase thread pool size
2. Enable keep-alive connections
3. Check for infinite loops in logs
4. Monitor with `top -H -p <pid>`

#### Memory Leaks

**Symptom**: Memory usage continuously growing

**Solutions**:
1. Run with Valgrind:
   ```bash
   valgrind --leak-check=full ./server
   ```
2. Check error paths for missing `free()`
3. Verify WebSocket connections are properly closed

#### SSL Handshake Failures

**Symptom**: Clients can't establish SSL connection

**Solutions**:
1. Verify certificate validity:
   ```bash
   openssl x509 -in certs/cert.pem -text -noout
   ```
2. Check certificate chain:
   ```bash
   openssl verify -CAfile ca.pem certs/cert.pem
   ```
3. Test SSL configuration:
   ```bash
   openssl s_client -connect localhost:443
   ```

### Debug Mode

Enable debug mode for detailed logging:

```bash
make clean
make debug
./server
```

Debug mode includes:
- Detailed request/response logging
- Frame-level WebSocket logging
- HTTP/2 stream tracking
- Memory allocation tracking

### Log Analysis

Monitor logs in real-time:

```bash
tail -f log/server.log
```

Filter for errors:

```bash
grep ERROR log/server.log
```

Count requests by type:

```bash
grep "Request:" log/server.log | cut -d' ' -f4 | sort | uniq -c
```

---

## Development Guide

### Building from Source

```bash
# Clone repository
git clone https://github.com/Azreyo/Carbon.git
cd Carbon

# Install development dependencies
sudo apt-get install -y build-essential libssl-dev libmagic-dev libnghttp2-dev

# Build
make

# Run tests
make test
```

### Code Structure

#### Adding New Features

1. **Define interface** in appropriate header file
2. **Implement functionality** in corresponding .c file
3. **Update Makefile** if adding new source files
4. **Add configuration options** if needed
5. **Update documentation**

#### Example: Adding Custom Header

```c
// In server.c
void add_custom_header(char *response, const char *name, const char *value) {
    char header[256];
    snprintf(header, sizeof(header), "%s: %s\r\n", name, value);
    strcat(response, header);
}

// Usage
add_custom_header(response, "X-Custom-Header", "CustomValue");
```

### Contributing Guidelines

1. **Fork** the repository
2. **Create feature branch**: `git checkout -b feature/NewFeature`
3. **Follow code style**: 4-space indents, clear variable names
4. **Add comments**: Document complex logic
5. **Test thoroughly**: Ensure no regressions
6. **Update docs**: Keep documentation current
7. **Submit PR**: With clear description

### Code Style

```c
// Function naming: lowercase with underscores
int parse_request(const char *data, size_t len);

// Constants: uppercase with underscores
#define MAX_BUFFER_SIZE 4096

// Structs: lowercase with _t suffix
typedef struct {
    int socket_fd;
    SSL *ssl;
} connection_t;

// Error handling: always check return values
if (parse_config("server.conf", &config) != 0) {
    log_error("Failed to parse configuration");
    return -1;
}
```

### Testing

```bash
# Unit tests
make test

# Memory leak detection
valgrind --leak-check=full ./server

# Performance testing
h2load -n 10000 -c 100 https://localhost/

# Security scanning
nmap -sV -sC localhost
```

---

## Appendix

### Glossary

- **ALPN**: Application-Layer Protocol Negotiation
- **CSP**: Content Security Policy
- **HPACK**: Header Compression for HTTP/2
- **HSTS**: HTTP Strict Transport Security
- **TLS**: Transport Layer Security
- **WebSocket**: Full-duplex communication protocol

### References

- [RFC 7540](https://tools.ietf.org/html/rfc7540) - HTTP/2 Specification
- [RFC 6455](https://tools.ietf.org/html/rfc6455) - WebSocket Protocol
- [RFC 5246](https://tools.ietf.org/html/rfc5246) - TLS 1.2
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [nghttp2 Documentation](https://nghttp2.org/documentation/)

### Support

- **Issues**: [GitHub Issues](https://github.com/Azreyo/Carbon/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Azreyo/Carbon/discussions)
- **Security**: Report privately to maintainers

---

<div align="center">

**Carbon HTTP Server Documentation**

Version 0.3.1| October 2025

[GitHub](https://github.com/Azreyo/Carbon) • [Issues](https://github.com/Azreyo/Carbon/issues) • [Contributing](CONTRIBUTING.md)

</div>
