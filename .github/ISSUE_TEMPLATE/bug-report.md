---
name: Bug Report
about: Report a bug or issue with Carbon HTTP Server
title: ''
labels: bug
assignees: ''

---

## Bug Description
 A clear and concise description of what the bug is

## Environment
- **Carbon Version:** <!-- e.g., commit hash or version -->
- **OS:** <!-- e.g., Ubuntu 22.04, Debian 11 -->
- **Architecture:** <!-- e.g., x86_64, ARM64 -->
- **Compiler Version:** <!-- e.g., gcc 11. 4. 0 -->

## 🔧 Configuration
Provide relevant sections from your server. conf
```conf
port = 
use_https = 
enable_http2 = 
enable_websocket = 
max_threads = 
```

## Steps to Reproduce
1. Start the Carbon server with HTTPS enabled (`use_https = true`)
2. Configure HTTP/2 in server.conf (`enable_http2 = true`)
3. Send 100 concurrent requests using:  `h2load -n 100 -c 10 https://localhost:8080/`
4. Server crashes after approximately 50 requests

## Expected Behavior
What you expected to happened

## Actual Behavior
What actually happened

## Logs
Paste relevant log output from log/server.log
```
[Paste logs here]
```

## Additional Context

### Protocol Information
- **Protocol Used:** <!-- HTTP/1.1, HTTP/2, WebSocket, etc. -->
- **Connection Type:** <!-- HTTP, HTTPS, WS, WSS -->
- **Browser/Client:** <!-- e.g., curl, Chrome 120, Firefox 121, wscat -->

### Performance Impact
- [ ] Server crashes
- [ ] Memory leak observed
- [ ] High CPU usage
- [ ] Connection timeouts
- [ ] Slow response times
- [ ] Other:  

### Component Affected
- [ ] Core HTTP server
- [ ] SSL/TLS handling
- [ ] HTTP/2 implementation
- [ ] WebSocket implementation
- [ ] Configuration parser
- [ ] File caching
- [ ] Logging system
- [ ] Other: 

## Screenshots/Output
If applicable, add screenshots or command output

## Possible Solution
Optional: suggest a fix or workaround if you have one

## Related Issues
Link to any related issues or PRs
