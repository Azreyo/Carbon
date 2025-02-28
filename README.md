# Carbon HTTP Server

A high-performance HTTP/HTTPS server written in C for Linux systems, featuring advanced security, caching, and async I/O.

## Core Features

- ✅ Multi-threaded HTTP/HTTPS server with epoll-based async I/O
- ✅ SSL/TLS support with automatic HTTP to HTTPS redirection
- ✅ Advanced rate limiting and DDoS protection
- ✅ File caching system for improved performance
- ✅ Thread pooling for efficient connection handling
- ✅ Comprehensive security headers and MIME type detection
- ✅ JSON-based configuration
- ✅ Detailed logging system with rotation

## Security Features

- ✅ Buffer overflow prevention
- ✅ Path traversal protection
- ✅ Input sanitization
- ✅ SSL/TLS with modern cipher suites
- ✅ Security headers (CSP, HSTS, X-Frame-Options, etc.)
- ✅ Rate limiting per IP
- ✅ Automatic HTTPS redirection

## Performance Features

- ✅ Epoll-based asynchronous I/O
- ✅ Thread pool for connection handling
- ✅ File caching system
- ✅ SendFile() optimization for file transfers
- ✅ Keep-alive connection support
- ✅ TCP optimization (NODELAY, buffer sizes)

## Build Instructions

### Prerequisites

```bash
# Install required dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    libcjson-dev \
    libmagic-dev \
    pkg-config
```

### Compilation

```bash
# Using Make (recommended)
make        # Normal build
make debug  # Debug build
make release # Optimized release build

# Manual compilation
gcc server.c config_parser.c server_config.c -o server \
    -D_GNU_SOURCE \
    -Wall -Wextra -O2 \
    -lssl -lcrypto -lpthread -lmagic -lcjson
```

### SSL Certificate Setup

```bash
# Create certificates directory
mkdir -p certs

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 -nodes
```

### Configuration

Create `server.json`:

```json
{
    "port": 8080,
    "use_https": false,
	"server_path": "bin/server",
	"config_path": "sever.json",
    "log_file": "log/server.log",
    "max_threads": 4,
    "running": true,
	"server_name": "Your_domain/IP",
	"verbose": true
  }
```

### Directory Structure

```bash
mkdir -p www/{css,js,images}
```

## Running the Server

```bash
# Allow ports
sudo ufw allow 8080/tcp  # HTTP
sudo ufw allow 443/tcp   # HTTPS

# Run the server
./server
```

## Planned Features

| Feature | Priority | Status |
|---------|----------|--------|
| WebSocket Support | Medium | ❌ |
| User Authentication | High | ❌ |
| API Documentation | Medium | ❌ |
| Load Balancing | Low | ❌ |
| Security Audits | Medium | ❌ |

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [License](LICENSE) View our license terms
 file for details.

## Security

While this server implements various security measures, it's recommended to:
- Use a reverse proxy (like Nginx) in production
- Obtain proper SSL certificates (Let's Encrypt)
- Regularly update dependencies
- Monitor server logs
- Conduct security audits

## Acknowledgments

- OpenSSL for SSL/TLS support
- cJSON for configuration parsing
- libmagic for MIME type detection

