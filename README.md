# HTTP Server

This is a simple HTTP server for linux operating system written in C. It supports basic HTTP requests, logging, etc.

## Features

*   Handles GET requests for static files.
*   Supports a control menu for managing server status, logging, and configuration (currently basic).
*   Uses pthreads for concurrent client handling.
*   Includes basic logging functionality with timestamps.
*   Configuration is loaded from a JSON file (`server.json`).

## Build Instructions

1.  **Prerequisites:**
    *   GCC compiler
    *   Make (recommended)
    *   OpenSSL libraries (`libssl`, `libcrypto`)
    *   pthreads library
    *   cJSON library

2.  **Clone the repository (optional):**

    ```bash
    git clone https://github.com/Azreyo/Http-server  
    cd Http-server/
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

	Cleanup of the unnecessary files after compiling

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

