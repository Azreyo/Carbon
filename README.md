# Carbon HTTP Server

This is a simple HTTP server for linux operating system written in C. It supports basic HTTP requests, logging, etc.
NOTE: This program is being used as a fun projects to see limits of C. I'll be not responsible for any vulnerabilities.
If you find vulnerabilities please report them.

## Features

*   Handles GET requests for static files.
*   Supports a control menu for managing server status, logging, and configuration (currently basic).
*   Uses pthreads for concurrent client handling.
*   Includes basic logging functionality with timestamps.
*   Configuration is loaded from a JSON file (`server.json`).

## Future development

This section outlines potential features and improvements planned for future releases of the server.

### Prioraty features

| Enhancement                 | Description                                      | Priority  | Completion |
|-----------------------------|--------------------------------------------------|-----------|----------------------|
| **Basic HTTP and HTTPS server Functionality**        | Switching from HTTP to HTTPS | Medium      | ✅		|
| **Logging Mechanism**        | Add logging mechanism for better error handleling | Low      | ✅		|
| **SSL/TLS Support**          | Implement SSL/TLS Support for HTTP/s   | High      | ✅		|

### Planned Features

| Enhancement                 | Description                                      | Priority  | Completion |
|-----------------------------|--------------------------------------------------|-----------|----------------------|
| **WebSocket Support**        | Implement WebSocket protocol for real-time communication. | Medium      | ❌		|
| **Rate Limiting**        | Add rate limiting to prevent abuse and DDoS attacks. | High      | ❌		|
| **User Authentication**          | Implement user authentication for secure access to certain endpoints.   | High      | ❌|
| **API Documentation**         | Create comprehensive API documentation using Swagger or similar tools. | Medium    | ❌		|
| **Load Balancing**         | Support for load balancing across multiple server instances. | Low    | ❌		|

### Performance Improvements

| Enhancement                 | Description                                      | Priority  | Completion |
|-----------------------------|--------------------------------------------------|-----------|----------------------|
| **Connecting Pooling**        | Implement connection pooling to improve performance under load. | High      | ❌		|
| **Asynchronous I/O**          | Use asynchronous I/O to handle more connections efficiently.   | Medium      | ❌|
| **Caching Mechanism**         | Introduce caching for static resources to reduce server load. | Medium    | ❌		|

### Security Enhancements

| Enhancement                 | Description                                      | Priority  | Completion |
|-----------------------------|--------------------------------------------------|-----------|----------------------|
| **Buffer Overflow Prevention**        | Implement comprehensive input validation to prevent injection attacks. | High      | ❌		|
| **HTTPS Redirect**          | Automatically redirect HTTP traffic to HTTPS.   | High      | ✅|
| **Security Audits**         | Conduct regular security audits and vulnerability assessments. | Medium    | ❌		|

### Community Contributions

| Contribution Area           | Description                                      | Priority  | Notes                |
|-----------------------------|--------------------------------------------------|-----------|----------------------|
| **Documentation**           | Improve and expand documentation for developers and users. | Medium    | Open for contributions |
| **Testing**                 | Create unit tests and integration tests for better coverage. | High      | Contributions welcome  |
| **Feature Requests**        | Encourage users to submit feature requests and suggestions. | Low       | Use GitHub Issues     |

## Build Instructions

1.  **Prerequisites:**
    *   GCC compiler
    *   Make (recommended)
    *   OpenSSL libraries (`libssl`, `libcrypto`)
    *   pthreads library
    *   cJSON library

2.  **Clone the repository (optional):**

    ```bash
    git clone https://github.com/Azreyo/Carbon  
    cd Carbon/
    ```

3.  **Compile:**

	```bash
	gcc server.c config_parser.c server_config.c -o server -lssl -lcrypto -lpthread -pthread -lcjson -lcjson -I/usr/include/cjson
	```
	Compile it in gcc


    ```bash
    make
    ```

    This command will use the provided `Makefile` to compile the source files, link the necessary libraries, and create the executable in the `bin` directory.

	```bash
	make clean
	```

	Cleanup of the unnecessary files after compiling.

4.  **Create `www` directory:**

    ```bash
    mkdir www
    ```

    Place your HTML files (e.g., `index.html`) inside the `www` directory.

5.  **Create `server.json`:**

    Create a `server.json` file in the same directory as the executable with the following structure:

    ```json
    {
      "port": 8080,
      "use_https": false,
      "log_file": "server.log",
      "max_threads": 4,
      "running": true
    }
    ```

    Adjust the values as needed.  `use_https` is not yet implemented.

5.  **Create systemd automatic startup**

```bash
#!/bin/bash

server_path=$(jq -r '.server_path' server.json)
config_path=$(jq -r 'config_path' server.json)

if [ ! -x "$server_path" ]; then
	echo "Error: Server executable not found or not executable: $server_path"
	exit 1
fi

if [ ! -f "$config_path" ]; then
	echo "Error: Config file not found $config_path"
	exit 1
fi

nohup "$server_path" --config "$config_path" &> server.log &

echo "Server started in the background. Check server.log for output"

exit 0
```
Code for automatic startup.

```bash
chmod +x start_server.sh
./start_server.sh
```

Permissions `+x`.


## Run Instructions

1.  **Get IP address of your device that the program will run on:**
```bash
ip address
```

2.  **Enable port 8080 for ufw**

```bash
sudo ufw allow 8080 # 8080 is the default port
```

3.  **Run it and enjoy**

```bash
./bin/server  # Run the executable from the bin directory
```


## For using HTTP/s

```bash
mkdir certs # Create certs folder
cd certs
```

Create certs folder to create certificates to it.

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Generating pairs of keys `key.pem and` and `cert.pem` for 365 days.
Note: its only self-signed browser may get Potential Security Risk.
For further use on domains is recommended Let's encrypt.

