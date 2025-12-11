# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Carbon HTTP Server, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email your findings to the maintainers privately
3. Include detailed steps to reproduce the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Security Features

Carbon HTTP Server implements multiple layers of security:

### SSL/TLS Encryption

- Full HTTPS support with OpenSSL integration
- Modern cipher suites with TLS 1.2+ support
- ALPN (Application-Layer Protocol Negotiation) for HTTP/2
- Configurable certificate and key paths

```conf
use_https = true
ssl_cert_path = ssl/cert/cert.pem
ssl_key_path = ssl/key/key.key
```

### Security Headers

All responses include security headers by default:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Clickjacking protection |
| `X-XSS-Protection` | `1; mode=block` | XSS filter protection |
| `Content-Security-Policy` | `default-src 'self'` | CSP protection |
| `Strict-Transport-Security` | `max-age=31536000` | HTTPS enforcement (when enabled) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer information control |

### Rate Limiting

Dynamic rate limiting protects against abuse and DDoS attacks:

- Configurable request limits per time window
- CPU-based adaptive rate limiting
- Per-IP tracking with automatic cleanup
- Returns `429 Too Many Requests` when limits exceeded

### Input Validation & Sanitization

- URL sanitization to prevent path traversal attacks
- Request size limits (`MAX_REQUEST_SIZE = 16384`)
- Filename and path validation
- Buffer overflow protection with bounded string operations

### Memory Safety

- Stack protector enabled (`-fstack-protector-strong`)
- FORTIFY_SOURCE level 2
- Position Independent Executable (PIE)
- RELRO (Relocation Read-Only) linking
- No strict overflow (`-fno-strict-overflow`)

### Docker Security

When running in Docker, additional security measures are applied:

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
```

- Non-root user execution (`carbon:carbon`)
- Dropped capabilities
- Read-only root filesystem
- Temporary filesystem for `/tmp`
- No privilege escalation

## Secure Configuration Recommendations

### Production Checklist

1. **Enable HTTPS**
   ```conf
   use_https = true
   ```

2. **Use valid SSL certificates**
   - Obtain certificates from a trusted CA (e.g., Let's Encrypt)
   - Keep private keys secure with proper file permissions

3. **Set appropriate log mode**
   ```conf
   log_mode = classic  # Avoid debug/advanced in production
   ```

4. **Limit connections and threads**
   ```conf
   max_threads = 4
   max_connections = 1024
   ```

5. **Restrict network binding**
   ```conf
   server_name = 127.0.0.1  # Or specific interface
   ```

### File Permissions

```bash
# Server binary
chmod 500 server

# Configuration files
chmod 600 server.conf

# SSL certificates
chmod 600 ssl/cert/cert.pem
chmod 600 ssl/key/key.key

# WWW directory (read-only)
chmod -R 444 www/
chmod 555 www/
```

### Firewall Rules

```bash
# Allow HTTP (if needed)
sudo ufw allow 8080/tcp

# Allow HTTPS
sudo ufw allow 8443/tcp

# Deny all other incoming
sudo ufw default deny incoming
```

## Known Security Considerations

### WebSocket Security

When enabling WebSocket support:

- WebSocket connections validate the `Sec-WebSocket-Key` header
- Frame masking is enforced per RFC 6455
- UTF-8 validation for text frames
- Proper close frame handling

```conf
enable_websocket = true  # Only enable if needed
```

### HTTP/2 Security

HTTP/2 is only available over HTTPS (h2), not cleartext (h2c):

```conf
use_https = true
enable_http2 = true
```

### Logging Security

- Sensitive data is sanitized in log output
- Log files should have restricted permissions
- Consider log rotation to prevent disk exhaustion

```conf
log_file = log/server.log
log_mode = classic
```

## Build Security

The Makefile includes security-focused compiler flags:

```makefile
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -D_FORTIFY_SOURCE=2
CFLAGS += -Wformat -Wformat-security -Werror=format-security
LDFLAGS = -Wl,-z,relro,-z,now -pie
```

## Security Updates

- Monitor the repository for security updates
- Keep dependencies (OpenSSL, nghttp2, zlib) updated
- Rebuild after dependency updates

## Disclaimer

Carbon HTTP Server is provided for educational and testing purposes. While security measures are implemented, the software:

- Has not undergone formal security audit
- May contain undiscovered vulnerabilities
- Should be thoroughly tested before production use

**Always perform your own security assessment before deploying in production environments.**

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [RFC 6455 - WebSocket Protocol](https://tools.ietf.org/html/rfc6455)
- [RFC 7540 - HTTP/2](https://tools.ietf.org/html/rfc7540)
- [OpenSSL Security](https://www.openssl.org/policies/secpolicy.html)
