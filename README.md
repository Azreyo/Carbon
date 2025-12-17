<div align="center">

# 🔥 Carbon HTTP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/Language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
![HTTP/2](https://img.shields.io/badge/HTTP%2F2-✓-success)
![WebSocket](https://img.shields.io/badge/WebSocket-RFC%206455-success)
![SSL/TLS](https://img.shields.io/badge/SSL%2FTLS-OpenSSL-blue)
![Epoll](https://img.shields.io/badge/I%2FO-epoll-orange)

*Features HTTP/2, WebSocket, advanced security, caching, and asynchronous I/O capabilities*

> **⚠️ WORK IN PROGRESS**: This project is currently under active development and is not yet a full release. Features may be incomplete, APIs may change, and bugs may be present. Use in production environments at your own risk.

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Usage](#-usage) • [Contributing](#-contributing) • [License](#-license) •  [Documentation](DOCUMENTATION.md)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Security](#-security)
- [Documentation](DOCUMENTATION.md)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

## 🌟 Overview

Carbon is a modern, production-ready HTTP/HTTPS server implementation in C, designed for high performance and security. Built with modern Linux systems in mind, it features **full HTTP/2 support**, **RFC 6455 compliant WebSocket** implementation, epoll-based asynchronous I/O, thread pooling, and comprehensive security measures to deliver a robust web serving solution.

**Key Highlights:**
- 🚀 **HTTP/2 with ALPN** - Automatic protocol negotiation, multiplexing, and header compression
- 🔌 **WebSocket Support** - Real-time bidirectional communication (ws:// and wss://)
- 🔒 **Modern Security** - SSL/TLS, rate limiting, security headers, memory-safe operations
- ⚡ **High Performance** - Epoll-based I/O, thread pooling, zero-copy transfers
- 🛠️ **Easy Configuration** - Linux-style config files, comprehensive documentation

## ✨ Features

### 🚀 High Performance
- **Asynchronous I/O**: Epoll-based event handling for maximum efficiency
- **Thread Pool**: Efficient connection handling with configurable worker threads
- **Memory-Mapped Files**: mmap-based file caching for frequently accessed files (up to 10MB)
- **Buffer Pooling**: Reusable buffer pool to reduce memory allocations
- **Smart Caching**: Multi-level file caching system to reduce disk I/O
- **SendFile Optimization**: Zero-copy file transfers for better throughput
- **Gzip Compression**: Dynamic compression for text-based content
- **Keep-Alive Support**: Persistent connections to reduce overhead
- **TCP Optimization**: Fine-tuned NODELAY, TCP_QUICKACK, and buffer configurations
- **CPU Affinity**: Thread-to-core pinning for better cache utilization
- **Dynamic Rate Limiting**: CPU-based adaptive rate limiting

### 🔒 High Security
- **SSL/TLS Support**: Full HTTPS support with modern cipher suites
- **Auto HTTPS Redirect**: Automatic HTTP to HTTPS redirection
- **Rate Limiting**: Per-IP rate limiting and DDoS protection
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more
- **Input Sanitization**: Protection against path traversal and injection attacks
- **Buffer Overflow Prevention**: Memory-safe operations throughout
- **Memory Leak Prevention**: Comprehensive resource management and cleanup

### 🌐 Modern Web Features
- **HTTP/2 Support**: Full HTTP/2 implementation with ALPN negotiation
- **WebSocket Support**: Full RFC 6455 compliant WebSocket implementation
- **Secure WebSockets (wss://)**: Encrypted WebSocket connections over TLS
- **Protocol Negotiation**: Automatic HTTP/2 or HTTP/1.1 via ALPN
- **Real-time Communication**: Bidirectional messaging with WebSocket frames
- **Binary & Text Frames**: Support for all WebSocket frame types (text, binary, ping, pong, close)

### 🛠️ Developer Features
- **Linux-Style Configuration**: Easy-to-edit .conf files with comments
- **Comprehensive Logging**: Detailed logs with rotation support
- **MIME Type Detection**: Automatic content-type detection via libmagic
- **Debug Mode**: Built-in debugging support for development
- **Echo Server**: Built-in WebSocket echo server for testing


## 📦 Prerequisites

Before building Carbon, ensure you have the following dependencies installed:

```bash
# Update package lists
sudo apt-get update

# Install required dependencies
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    libmagic-dev \
    libnghttp2-dev \
    zlib1g-dev \
    pkg-config
```

## 🚀 Installation

### Using HTTP configuration

```bash
# Clone the repository
git clone https://github.com/Azreyo/Carbon.git
cd Carbon

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libmagic-dev libnghttp2-dev zlib1g-dev pkg-config

# Build the server
make

# Run the server
sudo ./server
```

### Build Options

Carbon provides multiple build configurations:

```bash
make              # Standard build
make debug        # Debug build with symbols
make release      # Optimized release build
make clean        # Clean build artifacts
make install-deps # Install all dependencies (Debian systems only)
```

### Using Docker

Carbon includes full Docker support for easy deployment:

```bash
# Using Docker Compose (recommended)
docker-compose up -d

# Or build and run manually
docker build -t carbon-server .
docker run -d -p 8080:8080 -p 8443:8443 \
  -e PORT=8080 \
  -e USE_HTTPS=false \
  -e ENABLE_HTTP2=false \
  -e ENABLE_WEBSOCKET=false \
  carbon-server

# Using the official image
docker pull azreyo/carbon:latest
docker run -d -p 8080:8080 azreyo/carbon:latest
```

**Docker Environment Variables:**
- `SERVER_NAME`: Server domain/IP (default: 0.0.0.0)
- `PORT`: Server port (default: 8080)
- `USE_HTTPS`: Enable HTTPS (default: false)
- `ENABLE_HTTP2`: Enable HTTP/2 (default: false)
- `ENABLE_WEBSOCKET`: Enable WebSocket (default: false)
- `MAX_THREADS`: Worker threads (default: 4)
- `VERBOSE`: Verbose logging (default: true)

### Manual Compilation

If you prefer manual compilation:

```bash
gcc src/server.c src/config_parser.c src/server_config.c src/websocket.c src/http2.c src/performance.c -o server \
    -D_GNU_SOURCE \
    -Wall -Wextra -O2 \
    -lssl -lcrypto -lpthread -lmagic -lnghttp2 -lz
```

## ⚙️ Configuration

### SSL/TLS Setup

> **⚠️ Important**: Self-signed certificates should only be used for testing purposes. For production, use certificates from a trusted Certificate Authority like [Let's Encrypt](https://letsencrypt.org/).

```bash
# Create certificates directory
mkdir -p ssl/cert ssl/key

# Generate self-signed certificate (for testing only)
openssl req -x509 -newkey rsa:2048 \
    -keyout ssl/key/key.key \
    -out ssl/cert/cert.pem \
    -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

### Server Configuration

Create or edit `server.conf` in the project root. Carbon uses a traditional Linux-style configuration format with `key = value` pairs:

```conf
# Carbon Web Server Configuration File
# Lines starting with # are comments

# Server running state
running = true

# ---Network configuration---
# Server listening port
port = 8080
# Enable HTTPS (requires valid certificates in certs/ directory)
use_https = false
# Enable HTTP/2 support (requires HTTPS)
enable_http2 = false
# Enable WebSocket support
enable_websocket = false
# Server name or IP address (used for logging and response headers)
server_name = Your_domain/IP

# ---Performance configuration---
# Maximum number of worker threads
max_threads = 4
max_connections = 1024

# ---Path configuration---
# Log file location
log_file = log/server.log
# Enable verbose logging
verbose = true
# Path to www directory
www_path = www
# Path to public ssl certificate
ssl_cert_path = ssl/cert/cert.pem
# Path to private ssl key
ssl_key_path = ssl/key/key.key
```

**Configuration Options:**
- `running`: Server running state (default: true)
- `port`: HTTP/HTTPS port (default: 8080)
- `use_https`: Enable HTTPS - accepts: true/false, yes/no, on/off, 1/0 (requires SSL certificates)
- `enable_http2`: Enable HTTP/2 support (requires HTTPS and ALPN, default: false)
- `enable_websocket`: Enable WebSocket support (default: false)
- `server_name`: Your domain or IP address
- `max_threads`: Number of worker threads (default: 4)
- `max_connections`: Maximum concurrent connections (default: 1024)
- `log_file`: Path to log file (default: log/server.log)
- `verbose`: Enable detailed logging - accepts: true/false, yes/no, on/off, 1/0
- `www_path`: Path to web root directory (default: www)
- `ssl_cert_path`: Path to SSL certificate file (default: ssl/cert/cert.pem)
- `ssl_key_path`: Path to SSL private key file (default: ssl/key/key.key)

**Note:** Boolean values are flexible and accept multiple formats:
- True: `true`, `yes`, `on`, `1`
- False: `false`, `no`, `off`, `0`

Values can optionally be quoted with single or double quotes.

### Directory Structure

Set up the required directory structure:

```bash
# Create web root and subdirectories
mkdir -p www/{css,js,images}

# Create logs directory
mkdir -p log
```

## 🎯 Usage

### Starting the Server

```bash
# Run the server
./server

# The server will start on the configured port (default: 8080)
# Access it at http://localhost:8080
```

### Firewall Configuration

If you're using UFW, allow the necessary ports:

```bash
# Allow HTTP port
sudo ufw allow 8080/tcp

# Allow HTTPS port (if using SSL)
sudo ufw allow 443/tcp

# Reload firewall
sudo ufw reload
```

### Testing

```bash
# Test HTTP endpoint
curl http://localhost:8080

# Test HTTPS endpoint (if enabled)
curl -k https://localhost:443

# Test HTTP/2 (requires HTTPS)
curl --http2 -k https://localhost:443

# Verify HTTP/2 negotiation
openssl s_client -connect localhost:443 -alpn h2 < /dev/null 2>&1 | grep "ALPN protocol"
```

### WebSocket Usage

Carbon includes full WebSocket support for real-time bidirectional communication.

**JavaScript Client Example:**
```javascript
// Connect to WebSocket server
const ws = new WebSocket('ws://localhost:8080');

// Connection opened
ws.addEventListener('open', (event) => {
    console.log('Connected to server');
    ws.send('Hello Server!');
});

// Listen for messages
ws.addEventListener('message', (event) => {
    console.log('Message from server:', event.data);
});

// Handle errors
ws.addEventListener('error', (error) => {
    console.error('WebSocket error:', error);
});

// Connection closed
ws.addEventListener('close', (event) => {
    console.log('Disconnected from server');
});
```

**Secure WebSocket (wss://):**
```javascript
const wss = new WebSocket('wss://your-domain.com');
// Same API as above
```

**Testing with wscat:**
```bash
# Install wscat
npm install -g wscat

# Connect to WebSocket server
wscat -c ws://localhost:8080

# Connect to secure WebSocket
wscat -c wss://localhost:443 --no-check

# Type messages and press Enter to send
# The server will echo them back
```

**Python Client Example:**
```python
import websocket

def on_message(ws, message):
    print(f"Received: {message}")

def on_open(ws):
    print("Connected")
    ws.send("Hello from Python!")

ws = websocket.WebSocketApp("ws://localhost:8080",
                           on_message=on_message,
                           on_open=on_open)
ws.run_forever()
```

### HTTP/2 Support

Carbon includes full HTTP/2 support with automatic protocol negotiation via ALPN.

**Features:**
- ✅ HTTP/2 server push (stream multiplexing)
- ✅ HPACK header compression
- ✅ Binary framing protocol
- ✅ Automatic fallback to HTTP/1.1
- ✅ ALPN protocol negotiation
- ✅ Server-side stream management

**Configuration:**

Enable HTTP/2 in `server.conf`:
```ini
use_https = true
enable_http2 = true
https_port = 443
```

**Testing HTTP/2:**

```bash
# Test with curl (verbose)
curl -v --http2 -k https://localhost:443/

# Check ALPN negotiation
openssl s_client -connect localhost:443 -alpn h2 < /dev/null 2>&1 | grep "ALPN protocol"

# Test with h2load (load testing)
h2load -n 1000 -c 10 https://localhost:443/

# Use the diagnostic script
./check-http2.sh
```

**Browser Support:**

All modern browsers support HTTP/2:
- ✅ Chrome/Chromium 40+
- ✅ Firefox 36+
- ✅ Safari 9+
- ✅ Edge (all versions)
- ✅ Opera 27+

Browsers automatically negotiate HTTP/2 when connecting to HTTPS sites that support it.

**Performance Benefits:**

HTTP/2 provides significant performance improvements:
- **Multiplexing**: Multiple requests over a single connection
- **Header Compression**: Reduced overhead with HPACK
- **Server Push**: Proactive resource delivery
- **Binary Protocol**: More efficient parsing
- **Stream Prioritization**: Better resource loading


## 📁 Project Structure

```
Carbon/
├── src/
│   ├── server.c          # Main server implementation
│   ├── server_config.c   # Configuration management
│   ├── server_config.h   # Configuration headers
│   ├── config_parser.c   # Configuration file parser
│   ├── websocket.c       # WebSocket implementation
│   ├── websocket.h       # WebSocket headers
│   ├── http2.c           # HTTP/2 implementation
│   ├── http2.h           # HTTP/2 headers
│   ├── performance.c     # Performance optimizations
│   ├── performance.h     # Performance headers
│   └── bin/              # Compiled object files
├── Makefile              # Build configuration
├── Dockerfile            # Docker container configuration
├── docker-compose.yml    # Docker Compose configuration
├── docker-push.sh        # Docker image push script
├── server.conf           # Server configuration file (Linux-style)
├── README.md             # This file
├── DOCUMENTATION.md      # Comprehensive documentation
├── LICENSE               # MIT License
├── ssl/                  # SSL certificates directory (create this)
│   ├── cert/
│   │   └── cert.pem      # SSL certificate
│   └── key/
│       └── key.key       # SSL private key
├── www/                  # Web root directory
│   ├── index.html
│   └── websocket-test.html  # WebSocket test client
└── log/                  # Log files
    └── server.log
```

## 🗺️ Roadmap

| Feature | Priority | Status |
|---------|----------|--------|
| HTTP/2 Support | High | ✅ Implemented |
| WebSocket Support | High | ✅ Implemented |
| Secure WebSocket (wss://) | High | ✅ Implemented |
| API Rate Limiting | High | ✅ Implemented |
| Security Headers | High | ✅ Implemented |
| Memory Leak Prevention | High | ✅ Implemented |
| Performance Optimizations | High | ✅ Implemented |
| File Caching (mmap) | High | ✅ Implemented |
| Buffer Pooling | High | ✅ Implemented |
| Docker Support | Medium | ✅ Implemented |
| Gzip Compression | Medium | ✅ Implemented |
| User Authentication | High | 📋 Planned |
| Reverse Proxy Mode | Medium | 📋 Planned |
| Load Balancing | Low | 📋 Planned |
| Comprehensive API Docs | Medium | 🔄 In Progress |

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

Please ensure your code:
- Follows the existing code style
- Includes appropriate comments
- Passes all tests
- Updates documentation as needed

## 🔐 Security

Carbon implements multiple security layers, but for production deployments:

- ✅ **Use a reverse proxy** (Nginx, Apache) for additional security
- ✅ **Obtain proper SSL certificates** from Let's Encrypt or another CA
- ✅ **Keep dependencies updated** regularly
- ✅ **Monitor server logs** for suspicious activity
- ✅ **Conduct regular security audits**
- ✅ **Implement firewall rules** to restrict access
- ✅ **Use strong passwords** and authentication mechanisms

**Reporting Security Issues**: Please report security vulnerabilities to the maintainers privately before public disclosure.

## 📚 Documentation

Detailed documentation on how to use carbon server - see the [Documentation](DOCUMENTATION.md) for more details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Carbon is built with these excellent open-source libraries:

- [OpenSSL](https://www.openssl.org/) - SSL/TLS cryptography and ALPN support
- [nghttp2](https://nghttp2.org/) - HTTP/2 protocol implementation
- [libmagic](https://www.darwinsys.com/file/) - MIME type detection

---

<div align="center">

**Made with ❤️ by [Azreyo](https://github.com/Azreyo)**

⭐ Star this repository if you find it helpful!

</div>

