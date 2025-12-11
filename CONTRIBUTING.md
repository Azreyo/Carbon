# Contributing to Carbon HTTP Server

Thank you for your interest in contributing to Carbon! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [License](#license)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please:

- Be respectful and considerate in all interactions
- Accept constructive criticism gracefully
- Focus on what is best for the project and community
- Show empathy towards other contributors

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- Linux operating system (kernel 2.6.27+)
- GCC 4.8+ or Clang 3.4+
- Make build system
- Required dependencies installed

### Installing Dependencies

```bash
# Debian/Ubuntu/Raspberry Pi OS
make install-deps

# Or manually:
sudo apt-get install -y \
    libssl-dev \
    libmagic-dev \
    libnghttp2-dev \
    build-essential \
    pkg-config \
    zlib1g-dev
```

## Development Setup

1. **Fork the repository**

   Click the "Fork" button on GitHub to create your own copy.

2. **Clone your fork**

   ```bash
   git clone https://github.com/YOUR_USERNAME/Carbon.git
   cd Carbon
   ```

3. **Add upstream remote**

   ```bash
   git remote add upstream https://github.com/Azreyo/Carbon.git
   ```

4. **Build the project**

   ```bash
   # Standard build
   make

   # Debug build (with symbols, no optimization)
   make debug

   # Release build (maximum optimization)
   make release
   ```

5. **Run the server**

   ```bash
   ./server
   # Or with a custom config
   ./server server.conf
   ```

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template if available
3. Include:
   - Clear description of the issue
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, compiler version)
   - Relevant log output

### Suggesting Features

1. Check existing issues and discussions
2. Describe the feature and its use case
3. Explain why it would benefit the project
4. Consider implementation complexity

### Submitting Code

1. **Create a feature branch**

   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```

2. **Make your changes**

   - Follow the [coding standards](#coding-standards)
   - Keep commits focused and atomic
   - Write meaningful commit messages

3. **Test your changes**

   ```bash
   # Build and test
   make clean && make
   ./server

   # Test with Docker
   docker-compose up --build
   ```

4. **Submit a pull request**

## Coding Standards

### C Code Style

- **Indentation**: 4 spaces (no tabs)
- **Brace style**: Allman style (braces on new lines)
- **Line length**: Maximum 100 characters
- **Naming conventions**:
  - Functions: `snake_case`
  - Variables: `snake_case`
  - Constants/Macros: `UPPER_SNAKE_CASE`
  - Types/Structs: `snake_case_t` suffix

### Example Code Style

```c
// Good example
typedef struct
{
    int socket_fd;
    SSL *ssl;
    bool is_https;
} connection_t;

static int handle_connection(connection_t *conn)
{
    if (!conn)
    {
        return -1;
    }

    // Process connection
    return 0;
}

#define MAX_BUFFER_SIZE 8192
```

### Documentation

- Add comments for complex logic
- Document public functions with purpose and parameters
- Update `DOCUMENTATION.md` for new features
- Keep `README.md` current

### Security Considerations

When contributing code:

- Validate all input
- Use bounded string operations (`snprintf`, not `sprintf`)
- Check return values
- Avoid buffer overflows
- Handle errors gracefully
- Don't log sensitive information

### Compiler Warnings

All code must compile without warnings using:

```bash
gcc -Wall -Wextra -Werror
```

## Project Structure

```
Carbon/
├── src/
│   ├── server.c          # Main server implementation
│   ├── config_parser.c   # Configuration file parser
│   ├── server_config.c   # Server configuration defaults
│   ├── server_config.h   # Configuration structures
│   ├── http2.c           # HTTP/2 implementation
│   ├── http2.h           # HTTP/2 headers
│   ├── websocket.c       # WebSocket implementation
│   ├── websocket.h       # WebSocket headers
│   ├── performance.c     # Performance optimizations
│   ├── performance.h     # Performance headers
│   ├── logging.c         # Logging system
│   └── logging.h         # Logging headers
├── www/                  # Static web files
├── server.conf           # Default configuration
├── Makefile              # Build system
├── Dockerfile            # Container build
├── docker-compose.yml    # Container orchestration
├── README.md             # Project overview
├── DOCUMENTATION.md      # Detailed documentation
├── SECURITY.md           # Security policy
├── CONTRIBUTING.md       # This file
└── LICENSE               # License terms
```

## Testing

### Manual Testing

```bash
# Basic HTTP test
curl http://localhost:8080/

# HTTPS test (if enabled)
curl -k https://localhost:8443/

# WebSocket test
# Open www/websocket-test.html in browser

# HTTP/2 test
curl --http2 -k https://localhost:8443/
```

### Docker Testing

```bash
# Build and run
docker-compose up --build

# Check logs
docker logs carbon-http-server

# Health check
curl http://localhost:8080/
```

### Performance Testing

```bash
# Using Apache Benchmark
ab -n 10000 -c 100 http://localhost:8080/

# Using wrk
wrk -t4 -c100 -d30s http://localhost:8080/
```

## Pull Request Process

1. **Ensure your code**:
   - Compiles without warnings
   - Follows coding standards
   - Is properly documented
   - Doesn't break existing functionality

2. **Update documentation** if needed:
   - `README.md` for user-facing changes
   - `DOCUMENTATION.md` for technical details
   - Code comments for complex logic

3. **Create the pull request**:
   - Use a clear, descriptive title
   - Reference any related issues
   - Describe what changes were made and why
   - Include testing steps

4. **Review process**:
   - Maintainers will review your PR
   - Address any requested changes
   - Be patient and responsive

### PR Title Format

```
feat: Add new feature description
fix: Fix bug description
docs: Update documentation
refactor: Code refactoring
perf: Performance improvement
security: Security fix
```

## Areas for Contribution

Current areas where contributions are welcome:

- [ ] Unit test implementation
- [ ] Additional HTTP/2 features
- [ ] Performance optimizations
- [ ] Documentation improvements
- [ ] Bug fixes
- [ ] Security enhancements
- [ ] Cross-platform support research
- [ ] CI/CD pipeline improvements

## Questions?

If you have questions about contributing:

1. Check existing documentation
2. Search closed issues
3. Open a discussion or issue

## License

By contributing to Carbon, you agree that your contributions will be licensed under the same [MIT License (Modified - Non-Commercial)](LICENSE) that covers the project.

**Important**: Commercial use of contributions requires explicit permission from the copyright holders. See the LICENSE file for full terms.

---

Thank you for contributing to Carbon HTTP Server! 🔥
