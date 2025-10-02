<div align="center">

# 🔥 Carbon HTTP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/Language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**A high-performance HTTP/HTTPS server written in C for Linux systems**

*Features advanced security, caching, and asynchronous I/O capabilities*

> **⚠️ WORK IN PROGRESS**: This project is currently under active development and is not yet a full release. Features may be incomplete, APIs may change, and bugs may be present. Use in production environments at your own risk.

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Usage](#-usage) • [Contributing](#-contributing) • [License](#-license)

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
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

## 🌟 Overview

Carbon is a production-ready HTTP/HTTPS server implementation in C, designed for high performance and security. Built with modern Linux systems in mind, it leverages epoll-based I/O, thread pooling, and comprehensive security measures to deliver a robust web serving solution.

## ✨ Features

### 🚀 Performance
- **Asynchronous I/O**: Epoll-based event handling for maximum efficiency
- **Thread Pool**: Efficient connection handling with configurable worker threads
- **Smart Caching**: File caching system to reduce disk I/O
- **SendFile Optimization**: Zero-copy file transfers for better throughput
- **Keep-Alive Support**: Persistent connections to reduce overhead
- **TCP Optimization**: Fine-tuned NODELAY and buffer configurations

### 🔒 Security
- **SSL/TLS Support**: Full HTTPS support with modern cipher suites
- **Auto HTTPS Redirect**: Automatic HTTP to HTTPS redirection
- **Rate Limiting**: Per-IP rate limiting and DDoS protection
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more
- **Input Sanitization**: Protection against path traversal and injection attacks
- **Buffer Overflow Prevention**: Memory-safe operations throughout

### 🛠️ Developer Features
- **JSON Configuration**: Easy-to-edit configuration files
- **Comprehensive Logging**: Detailed logs with rotation support
- **MIME Type Detection**: Automatic content-type detection via libmagic
- **Debug Mode**: Built-in debugging support for development

## 📦 Prerequisites

Before building Carbon, ensure you have the following dependencies installed:

```bash
# Update package lists
sudo apt-get update

# Install required dependencies
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    libcjson-dev \
    libmagic-dev \
    pkg-config
```

## 🚀 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Azreyo/Carbon.git
cd Carbon

# Build the server
make

# Run the server
./server
```

### Build Options

Carbon provides multiple build configurations:

```bash
make              # Standard build
make debug        # Debug build with symbols
make release      # Optimized release build
make clean        # Clean build artifacts
```

### Manual Compilation

If you prefer manual compilation:

```bash
gcc server.c config_parser.c server_config.c -o server \
    -D_GNU_SOURCE \
    -Wall -Wextra -O2 \
    -lssl -lcrypto -lpthread -lmagic -lcjson
```

## ⚙️ Configuration

### SSL/TLS Setup

> **⚠️ Important**: Self-signed certificates should only be used for testing purposes. For production, use certificates from a trusted Certificate Authority like [Let's Encrypt](https://letsencrypt.org/).

```bash
# Create certificates directory
mkdir -p certs

# Generate self-signed certificate (for testing only)
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

### Server Configuration

Create or edit `server.json` in the project root:

```json
{
    "port": 8080,
    "use_https": false,
    "log_file": "log/server.log",
    "max_threads": 4,
    "running": true,
    "server_name": "localhost",
    "verbose": true
}
```

**Configuration Options:**
- `port`: HTTP port (default: 8080)
- `use_https`: Enable HTTPS (requires SSL certificates)
- `log_file`: Path to log file
- `max_threads`: Number of worker threads
- `server_name`: Your domain or IP address
- `verbose`: Enable detailed logging

### Directory Structure

Set up the required directory structure:

```bash
# Create web root and subdirectories
mkdir -p www/{css,js,images}

# Create logs directory
mkdir -p log

# Place your web files in www/
# Example: www/index.html, www/css/style.css, etc.
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
```

## 📁 Project Structure

```
Carbon/
├── server.c              # Main server implementation
├── server_config.c       # Configuration management
├── server_config.h       # Configuration headers
├── config_parser.c       # JSON configuration parser
├── Makefile              # Build configuration
├── server.json           # Server configuration file
├── README.md             # This file
├── LICENSE               # MIT License
├── certs/                # SSL certificates (create this)
│   ├── cert.pem
│   └── key.pem
├── www/                  # Web root directory
│   ├── index.html
│   ├── css/
│   ├── js/
│   └── images/
└── log/                  # Log files
    └── server.log
```

## 🗺️ Roadmap

| Feature | Priority | Status |
|---------|----------|--------|
| HTTP/2 Support | High | 📋 Planned |
| WebSocket Support | Medium | 📋 Planned |
| User Authentication | High | 📋 Planned |
| API Rate Limiting | High | ✅ Implemented |
| Reverse Proxy Mode | Medium | 📋 Planned |
| Load Balancing | Low | 📋 Planned |
| Docker Support | Medium | 📋 Planned |
| Comprehensive API Docs | Medium | 📋 Planned |

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Carbon is built with these excellent open-source libraries:

- [OpenSSL](https://www.openssl.org/) - SSL/TLS cryptography
- [cJSON](https://github.com/DaveGamble/cJSON) - Lightweight JSON parser
- [libmagic](https://www.darwinsys.com/file/) - MIME type detection

---

<div align="center">

**Made with ❤️ by [Azreyo](https://github.com/Azreyo)**

⭐ Star this repository if you find it helpful!

</div>

