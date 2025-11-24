#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <magic.h>
#include <ctype.h>
#include <time.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <zlib.h>

#include "server_config.h"
#include "websocket.h"
#include "http2.h"
#include "performance.h"

#define MAX_REQUEST_SIZE 16384
#define MAX_LOG_SIZE 2048
#define MAX_EVENTS 1024

#define BOLD "\x1b[1m"
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define RESET "\x1b[0m"

#define HANDLE_ERROR(msg)             \
    do                                \
    {                                 \
        log_event(msg ": " BOLD RED); \
        log_event(strerror(errno));   \
        goto cleanup;                 \
    } while (0)

// Use larger buffer for file operations
#define FILE_BUFFER_SIZE 65536

#define SECURITY_HEADERS                                                                                           \
    "X-Content-Type-Options: nosniff\r\n"                                                                          \
    "X-Frame-Options: SAMEORIGIN\r\n"                                                                              \
    "X-XSS-Protection: 1; mode=block\r\n"                                                                          \
    "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " \
    "font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline';\r\n"

#define RATE_LIMIT_WINDOW 60 // 60 seconds
#define MAX_REQUESTS 500     // max requests per window

#define LOG_BUFFER_SIZE 4096
#define MAX_LOG_FILE_SIZE (100 * 1024 * 1024) // 100MB max log file size

#define SOCKET_SEND_BUFFER_SIZE (512 * 1024) // 512KB for faster throughput
#define SOCKET_RECV_BUFFER_SIZE (512 * 1024) // 512KB
#define SOCKET_BACKLOG 256                   
#define EPOLL_TIMEOUT 50                     // 50ms timeout for faster polling

#define MAX_THREAD_POOL_SIZE 64
#define WORKER_QUEUE_SIZE 2048

#define MAX_CACHE_SIZE 100
#define MAX_CACHE_FILE_SIZE (1024 * 1024)     // 1MB
#define MAX_MMAP_FILE_SIZE (10 * 1024 * 1024) // 10MB

typedef struct
{
    pthread_t thread;
    int busy;
    int cpu_core;
} ThreadInfo;

ThreadInfo *thread_pool;
int thread_pool_size = 0;
pthread_mutex_t thread_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t thread_pool_cond = PTHREAD_COND_INITIALIZER;

// Worker thread queue
task_queue_t worker_queue;
pthread_t *worker_threads = NULL;
int num_worker_threads = 0;
volatile int workers_running = 1;

typedef struct
{
    char ip[INET_ADDRSTRLEN];
    time_t window_start;
    int request_count;
} RateLimit;

typedef struct
{
    char *path;
    char *data;
    size_t size;
    time_t last_access;
    char *mime_type;
} CacheEntry;

CacheEntry *file_cache = NULL;
int cache_size = 0;
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

ServerConfig config;
char server_log[MAX_LOG_SIZE];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t *client_threads = NULL;
int num_client_threads = 0;
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
SSL_CTX *ssl_ctx = NULL;
volatile sig_atomic_t server_running = 1;
int http_socket = -1;
int https_socket = -1;
int epoll_fd;

RateLimit *rate_limits = NULL;
int rate_limit_count = 0;
pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

void cleanup_thread_pool(void);
void *handle_http_client(void *arg);
void *handle_https_client(void *arg);
void *worker_thread(void *arg);
void set_cpu_affinity(int thread_id);
void optimize_socket_for_send(int socket_fd);
void log_event(const char *message);
void initialize_openssl();
void cleanup_openssl();
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);
void *start_http_server(void *arg);
void *start_https_server(void *arg);
void shutdown_server();
int parse_request_line(char *request_buffer, char *method, char *url, char *protocol);
char *get_mime_type(const char *filepath);
char *sanitize_url(const char *url);
int check_rate_limit(const char *ip);
int should_compress(const char *mime_type);
unsigned char *gzip_compress(const unsigned char *data, size_t size, size_t *compressed_size);
char *stristr(const char *haystack, const char *needle);

void initialize_openssl()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
}

void cleanup_openssl()
{
    if (ssl_ctx)
    {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
#endif
}

SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror(BOLD RED "Unable to create SSL context" RESET);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_file(ctx, config.ssl_cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, config.ssl_key_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Security hardening
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION); // Disable compression (CRIME attack)
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    
    // Use secure ciphers only - TLS 1.3 and strong TLS 1.2 ciphers
    const char *cipher_list = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                              "TLS_AES_128_GCM_SHA256:"  // TLS 1.3
                              "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                              "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
                              "!aNULL:!eNULL:!EXPORT:!DES:!3DES:!RC4:!MD5:!PSK:!CBC";
    
    if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Enable HTTP/2 ALPN if configured
    if (config.enable_http2)
    {
        SSL_CTX_set_alpn_select_cb(ctx, alpn_select_proto_cb, NULL);
        log_event("HTTP/2 ALPN enabled");
    }
}

void optimize_socket_for_send(int socket_fd)
{
    int flag = 1;
    // Enable TCP_NODELAY to disable Nagle's algorithm for low latency
    setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
#ifdef TCP_QUICKACK
    // Enable quick ACK for faster response
    setsockopt(socket_fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
#endif
}

void set_socket_options(int socket_fd)
{
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL");
        return;
    }
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl F_SETFL");
    }

    int reuse = 1;
    int keepalive = 1;
    int keepidle = 60;
    int keepintvl = 10;
    int keepcnt = 5;
    int nodelay = 1;

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
    setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    int sendbuf = SOCKET_SEND_BUFFER_SIZE;
    int recvbuf = SOCKET_RECV_BUFFER_SIZE;
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
}

void *start_http_server(void *arg)
{
    (void)arg;
    http_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket < 0)
    {
        perror(BOLD RED "Error creating HTTP socket" RESET);
        pthread_exit(NULL);
    }

    set_socket_options(http_socket);

    struct sockaddr_in http_address = {0};
    http_address.sin_family = AF_INET;
    http_address.sin_addr.s_addr = INADDR_ANY;
    http_address.sin_port = htons(config.port);

    if (bind(http_socket, (struct sockaddr *)&http_address, sizeof(http_address)) < 0)
    {
        perror(BOLD RED "Error binding HTTP socket" RESET);
        close(http_socket);
        pthread_exit(NULL);
    }

    if (listen(http_socket, SOCKET_BACKLOG) < 0)
    {
        perror(BOLD RED "Error listening on HTTP socket" RESET);
        close(http_socket);
        pthread_exit(NULL);
    }

    epoll_fd = epoll_create1(0); // Create epoll instance
    if (epoll_fd == -1)
    {
        perror("epoll_create1");
        close(http_socket); // Close the socket before exiting
        pthread_exit(NULL);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = http_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http_socket, &ev) == -1)
    {
        perror("epoll_ctl: http_socket");
        close(http_socket);
        close(epoll_fd); // Close epoll fd
        pthread_exit(NULL);
    }

    log_event("HTTP server started.");

    struct epoll_event events[MAX_EVENTS];
    while (config.running && server_running)
    {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT); // 100ms timeout
        if (nfds == -1)
        {
            if (errno != EINTR)
            { // Ignore interrupts for shutdown
                perror("epoll_wait");
                break; // Exit loop on error
            }
            continue; // Continue if it was an interrupt
        }

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd == http_socket)
            {
                // New connection
                struct sockaddr_in client_addr;
                socklen_t addr_size = sizeof(client_addr);
                int client_socket = accept(http_socket, (struct sockaddr *)&client_addr, &addr_size);
                if (client_socket < 0)
                {
                    perror("accept");
                    continue;
                }

                // Enqueue task to worker thread pool instead of creating new thread
                if (worker_queue.count < WORKER_QUEUE_SIZE)
                {
                    enqueue_task(&worker_queue, client_socket, NULL, false);
                }
                else
                {
                    log_event("Worker queue full, rejecting connection.");
                    const char *overload_response = "HTTP/1.1 503 Service Unavailable\r\n\r\nServer overloaded";
                    send(client_socket, overload_response, strlen(overload_response), 0);
                    close(client_socket);
                }
            }
        }
    }

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, http_socket, NULL);
    close(http_socket);
    close(epoll_fd);
    log_event("HTTP server stopped.");
    pthread_exit(NULL);
}

void *start_https_server(void *arg)
{
    (void)arg;
    https_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (https_socket < 0)
    {
        perror(BOLD RED "Error creating HTTPS socket" RESET);
        pthread_exit(NULL);
    }

    set_socket_options(https_socket);

    struct sockaddr_in https_address;
    memset(&https_address, 0, sizeof(https_address));
    https_address.sin_family = AF_INET;
    https_address.sin_addr.s_addr = INADDR_ANY;
    https_address.sin_port = htons(443);

    if (bind(https_socket, (struct sockaddr *)&https_address, sizeof(https_address)) < 0)
    {
        perror(BOLD RED "Error binding HTTPS socket" RESET);
        close(https_socket);
        pthread_exit(NULL);
    }

    if (listen(https_socket, SOCKET_BACKLOG) < 0)
    {
        perror(BOLD RED "Error listening on HTTPS socket" RESET);
        close(https_socket);
        pthread_exit(NULL);
    }

    log_event("HTTPS server started.");

    while (config.running && server_running)
    {
        int client_socket = accept(https_socket, NULL, NULL);
        if (client_socket < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                usleep(10000);
                continue;
            }
            perror("Error accepting HTTPS connection");
            break;
        }

        // Enqueue task to worker thread pool instead of creating new thread
        if (worker_queue.count < WORKER_QUEUE_SIZE)
        {
            enqueue_task(&worker_queue, client_socket, NULL, true);
        }
        else
        {
            log_event("Worker queue full (HTTPS), rejecting connection.");
            const char *overload_response = "HTTP/1.1 503 Service Unavailable\r\n\r\nServer overloaded";
            send(client_socket, overload_response, strlen(overload_response), 0);
            close(client_socket);
        }
    }

    close(https_socket);
    pthread_exit(NULL);
}

// Check if request is a WebSocket upgrade request
static int is_websocket_upgrade(const char *request)
{
    // Make a lowercase copy for case-insensitive comparison
    char *request_lower = strdup(request);
    if (!request_lower)
        return 0;

    for (char *p = request_lower; *p; p++)
    {
        *p = tolower((unsigned char)*p);
    }

    // Check for "upgrade: websocket" and "connection:" containing "upgrade"
    int has_upgrade = strstr(request_lower, "upgrade: websocket") != NULL;
    int has_connection = strstr(request_lower, "connection:") != NULL &&
                         strstr(request_lower, "upgrade") != NULL;

    free(request_lower);
    return has_upgrade && has_connection;
}

// Handle WebSocket connection
static void *handle_websocket(void *arg)
{
    ws_connection_t *conn = (ws_connection_t *)arg;
    
    if (!conn)
    {
        pthread_exit(NULL);
    }

    log_event("WebSocket connection established");

    uint8_t buffer[65536];
    while (server_running && config.running)
    {
        ssize_t bytes_received;

        if (conn->is_ssl)
        {
            bytes_received = SSL_read(conn->ssl, buffer, sizeof(buffer));
        }
        else
        {
            bytes_received = recv(conn->socket_fd, buffer, sizeof(buffer), 0);
        }

        if (bytes_received <= 0)
        {
            ws_close_connection(conn, 1000);
            free(conn);
            pthread_exit(NULL);
        }

        ws_frame_header_t header;
        uint8_t *payload = NULL;
        int parsed = ws_parse_frame(buffer, bytes_received, &header, &payload);

        if (parsed < 0)
        {
            log_event("Failed to parse WebSocket frame");
            free(payload);
            ws_close_connection(conn, 1002);
            free(conn);
            pthread_exit(NULL);
        }

        switch (header.opcode)
        {
        case WS_OPCODE_TEXT:
            if (ws_is_valid_utf8(payload, header.payload_length))
            {
                // Echo back the text message
                ws_send_text(conn, (const char *)payload);
                log_event("WebSocket text frame received and echoed");
            }
            else
            {
                log_event("Invalid UTF-8 in text frame");
            }
            break;

        case WS_OPCODE_BINARY:
            // Echo back binary data
            ws_send_frame(conn, WS_OPCODE_BINARY, payload, header.payload_length);
            log_event("WebSocket binary frame received and echoed");
            break;

        case WS_OPCODE_PING:
            ws_send_pong(conn, payload, header.payload_length);
            log_event("WebSocket ping received, pong sent");
            break;

        case WS_OPCODE_CLOSE:
            log_event("WebSocket close frame received");
            free(payload);
            ws_close_connection(conn, 1000);
            free(conn);
            pthread_exit(NULL);

        default:
            break;
        }

        free(payload);
    }

    ws_close_connection(conn, 1000);
    free(conn);
    pthread_exit(NULL);
}

void *handle_http_client(void *arg)
{
    int client_socket = *((int *)arg);
    free(arg);

    if (!server_running)
    {
        close(client_socket);
        pthread_exit(NULL);
    }

    char request_buffer[MAX_REQUEST_SIZE];
    memset(request_buffer, 0, MAX_REQUEST_SIZE);
    ssize_t bytes_received = recv(client_socket, request_buffer, MAX_REQUEST_SIZE - 1, 0);

    if (bytes_received > 0)
    {
        request_buffer[bytes_received] = '\0';
        log_event("Received HTTP request");

        // Check if client accepts gzip BEFORE parsing (parse modifies buffer!)
        int accepts_gzip = (stristr(request_buffer, "accept-encoding:") && 
                           stristr(request_buffer, "gzip")) ? 1 : 0;

        // Check for WebSocket upgrade request
        if (config.enable_websocket && is_websocket_upgrade(request_buffer))
        {
            log_event("WebSocket upgrade request detected");

            char response[512];
            if (ws_handle_handshake(client_socket, request_buffer, response, sizeof(response)) == 0)
            {
                send(client_socket, response, strlen(response), 0);

                // Create WebSocket connection context
                ws_connection_t *ws_conn = malloc(sizeof(ws_connection_t));
                if (ws_conn)
                {
                    ws_conn->socket_fd = client_socket;
                    ws_conn->ssl = NULL;
                    ws_conn->is_ssl = false;
                    ws_conn->handshake_complete = true;

                    // Handle WebSocket connection in this thread
                    handle_websocket(ws_conn);
                }
                else
                {
                    close(client_socket);
                }
            }
            else
            {
                log_event("WebSocket handshake failed");
                close(client_socket);
            }
            pthread_exit(NULL);
        }

        char method[8], url[256], protocol[16];
        if (parse_request_line(request_buffer, method, url, protocol) != 0)
        {
            log_event("Invalid request line.");
            const char *bad_request_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request";
            send(client_socket, bad_request_response, strlen(bad_request_response), 0);
            close(client_socket);
            pthread_exit(NULL);
        }

        if (config.use_https)
        { // Check if HTTPS is enabled
            size_t needed = snprintf(NULL, 0,
                                     "HTTP/1.1 301 Moved Permanently\r\n"
                                     "Location: https://%s%s\r\n\r\n",
                                     config.server_name, url) +
                            1;

            char *redirect_response = malloc(needed);
            if (redirect_response)
            {
                snprintf(redirect_response, needed,
                         "HTTP/1.1 301 Moved Permanently\r\n"
                         "Location: https://%s%s\r\n\r\n",
                         config.server_name, url);
                send(client_socket, redirect_response, strlen(redirect_response), 0);
                free(redirect_response);
            }
            log_event("Redirecting to HTTPS");
            close(client_socket);
            return NULL;
        }

        char *sanitized_url = sanitize_url(url);
        if (!sanitized_url)
        {
            log_event("Blocked malicious URL");
            const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
            send(client_socket, forbidden_response, strlen(forbidden_response), 0);
            close(client_socket);
            pthread_exit(NULL);
        }

        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        getpeername(client_socket, (struct sockaddr *)&addr, &addr_len);
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

        if (!check_rate_limit(client_ip))
        {
            log_event("Rate limit exceeded for IP:");
            log_event(client_ip);
            const char *rate_limit_response = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded";
            send(client_socket, rate_limit_response, strlen(rate_limit_response), 0);
            close(client_socket);
            return NULL;
        }

        char filepath[512];
        int written = snprintf(filepath, sizeof(filepath), "%s%s", config.www_path,
                 (*sanitized_url == '/' && sanitized_url[1] == '\0') ? "/index.html" : sanitized_url);
        free(sanitized_url);
        
        if (written < 0 || written >= (int)sizeof(filepath))
        {
            log_event("Path too long, potential buffer overflow attempt");
            const char *error_response = "HTTP/1.1 414 URI Too Long\r\n\r\n";
            send(client_socket, error_response, strlen(error_response), 0);
            close(client_socket);
            pthread_exit(NULL);
        }

        // Get MIME type
        char *mime_type = get_mime_type(filepath);

        // Try cache first
        mmap_cache_entry_t *cached = get_cached_file(filepath);

        if (cached)
        {
            // Check if we should compress
            unsigned char *compressed_data = NULL;
            size_t compressed_size = 0;
            int using_compression = 0;
            
            char debug_msg[256];
            snprintf(debug_msg, sizeof(debug_msg), "accepts_gzip=%d, should_compress=%d, size=%zu", 
                    accepts_gzip, should_compress(cached->mime_type), cached->size);
            log_event(debug_msg);
            
            if (accepts_gzip && should_compress(cached->mime_type) && cached->size > 1024)
            {
                compressed_data = gzip_compress((unsigned char *)cached->mmap_data, cached->size, &compressed_size);
                if (compressed_data && compressed_size < cached->size * 0.9) // Only use if 10%+ savings
                {
                    using_compression = 1;
                    snprintf(debug_msg, sizeof(debug_msg), "Compression: %zu -> %zu bytes (%.1f%%)", 
                            cached->size, compressed_size, (compressed_size * 100.0) / cached->size);
                    log_event(debug_msg);
                }
                else if (compressed_data)
                {
                    log_event("Compression not efficient enough, skipping");
                    free(compressed_data);
                    compressed_data = NULL;
                }
            }

            // Serve from cache with optional compression
            char response_header[2048];
            int header_len = snprintf(response_header, sizeof(response_header),
                                      "HTTP/1.1 200 OK\r\n"
                                      "Content-Length: %zu\r\n"
                                      "Content-Type: %s\r\n"
                                      "Cache-Control: public, max-age=86400, immutable\r\n"
                                      "ETag: \"%zu-%ld%s\"\r\n"
                                      "%s"
                                      "%s"
                                      "Keep-Alive: timeout=5, max=100\r\n"
                                      "Connection: Keep-Alive\r\n"
                                      "\r\n",
                                      using_compression ? compressed_size : cached->size,
                                      cached->mime_type,
                                      cached->size,
                                      cached->last_access,
                                      using_compression ? "-gzip" : "",
                                      using_compression ? "Content-Encoding: gzip\r\n" : "",
                                      SECURITY_HEADERS);

            void *data_to_send = using_compression ? compressed_data : cached->mmap_data;
            size_t size_to_send = using_compression ? compressed_size : cached->size;

            // Use writev to send header + content in one syscall (for small files)
            if (size_to_send < 65536) // Files < 64KB
            {
                struct iovec iov[2];
                iov[0].iov_base = response_header;
                iov[0].iov_len = header_len;
                iov[1].iov_base = data_to_send;
                iov[1].iov_len = size_to_send;
                ssize_t written = writev(client_socket, iov, 2);
                (void)written;
            }
            else
            {
                send(client_socket, response_header, header_len, 0);
                
                size_t total_sent = 0;
                while (total_sent < size_to_send)
                {
                    ssize_t sent = send(client_socket, (char *)data_to_send + total_sent,
                                        size_to_send - total_sent, 0);
                    if (sent <= 0)
                        break;
                    total_sent += sent;
                }
            }

            if (compressed_data)
                free(compressed_data);
            release_cached_file(cached);
            free(mime_type);
            log_event(using_compression ? "Served file from cache (gzip)" : "Served file from cache");
            goto done_serving;
        }

        int fd = open(filepath, O_RDONLY);
        if (fd == -1)
        {
            const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
            send(client_socket, not_found_response, strlen(not_found_response), 0);
            free(mime_type);
            log_event("File not found, sent 404.");
        }
        else
        {
            struct stat st;
            if (fstat(fd, &st) == -1)
            {
                log_event("Error getting file size.");
                const char *internal_server_error =
                    "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";
                send(client_socket, internal_server_error, strlen(internal_server_error), 0);
                close(fd);
                free(mime_type);
                goto cleanup;
            }

            // Cache if eligible
            if (st.st_size > 0 && st.st_size < MAX_MMAP_FILE_SIZE)
            {
                cache_file_mmap(filepath, st.st_size, mime_type);
            }

            char response_header[2048];
            int header_len = snprintf(response_header, sizeof(response_header),
                                      "HTTP/1.1 200 OK\r\n"
                                      "Content-Length: %ld\r\n"
                                      "Content-Type: %s\r\n"
                                      "Cache-Control: public, max-age=86400\r\n"
                                      "ETag: \"%ld-%ld\"\r\n"
                                      "%s"
                                      "\r\n",
                                      (long)st.st_size,
                                      mime_type,
                                      (long)st.st_size,
                                      (long)st.st_mtime,
                                      SECURITY_HEADERS);

            free(mime_type);

            send(client_socket, response_header, header_len, 0);

            // Use sendfile for zero-copy transfer
            off_t offset = 0;
            ssize_t sent = sendfile(client_socket, fd, &offset, st.st_size);
            if (sent != st.st_size)
            {
                log_event("Error sending file with sendfile()");
            }

            close(fd);
            log_event("Served requested file successfully.");
        }

    done_serving:
    }
    else if (bytes_received < 0)
    {
        HANDLE_ERROR("Error receiving request");
    }

    close(client_socket);
    pthread_exit(NULL);

cleanup:
    close(client_socket);
    pthread_exit(NULL);
}

void *handle_https_client(void *arg)
{
    int client_socket = *((int *)arg);
    free(arg);

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl)
    {
        log_event("SSL_new failed");
        close(client_socket);
        pthread_exit(NULL);
    }
    SSL_set_fd(ssl, client_socket);

    if (!server_running)
    {
        SSL_free(ssl); // Free SSL context if server is not running
        close(client_socket);
        pthread_exit(NULL);
    }

    if (SSL_accept(ssl) <= 0)
    {
        int ssl_error = SSL_get_error(ssl, -1);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                 "SSL handshake failed. SSL error code: %d", ssl_error);
        log_event(error_msg);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        pthread_exit(NULL);
    }

    log_event("SSL handshake successful!");

    // Check if HTTP/2 was negotiated via ALPN
    if (config.enable_http2)
    {
        const unsigned char *alpn_data = NULL;
        unsigned int alpn_len = 0;

        SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);

        if (alpn_data && alpn_len == 2 && memcmp(alpn_data, "h2", 2) == 0)
        {
            log_event("HTTP/2 protocol negotiated via ALPN");

            // Set socket to non-blocking mode for HTTP/2
            int flags = fcntl(client_socket, F_GETFL, 0);
            if (flags != -1)
            {
                fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
            }

            // Initialize HTTP/2 session
            http2_session_t h2_session;
            if (http2_session_init(&h2_session, client_socket, ssl) == 0)
            {
                // Handle HTTP/2 connection
                while (server_running)
                {
                    int result = http2_handle_connection(&h2_session);
                    if (result <= 0)
                    {
                        break; // Connection closed or error
                    }

                    // Small delay to avoid busy loop
                    usleep(1000); // 1ms
                }

                http2_session_cleanup(&h2_session);
            }
            else
            {
                log_event("Failed to initialize HTTP/2 session");
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            pthread_exit(NULL);
        }
    }

    char buffer[MAX_REQUEST_SIZE];
    memset(buffer, 0, MAX_REQUEST_SIZE);
    ssize_t bytes_received = SSL_read(ssl, buffer, MAX_REQUEST_SIZE - 1);

    if (bytes_received < 0)
    {
        perror("SSL_read error");
        ERR_print_errors_fp(stderr);
        log_event("SSL_read failed");
        goto cleanup;
    }
    else if (bytes_received == 0)
    {
        log_event("Client closed connection");
        goto cleanup;
    }
    else
    {
        buffer[bytes_received] = '\0';
        log_event("Received HTTPS request:");
        log_event(buffer);
    }

    // Check for WebSocket upgrade request on HTTPS
    if (config.enable_websocket && is_websocket_upgrade(buffer))
    {
        log_event("Secure WebSocket upgrade request detected");

        char response[512];
        if (ws_handle_handshake_ssl(ssl, buffer, response, sizeof(response)) == 0)
        {
            SSL_write(ssl, response, strlen(response));

            // Create WebSocket connection context
            ws_connection_t *ws_conn = malloc(sizeof(ws_connection_t));
            if (ws_conn)
            {
                ws_conn->socket_fd = client_socket;
                ws_conn->ssl = ssl;
                ws_conn->is_ssl = true;
                ws_conn->handshake_complete = true;

                // Handle WebSocket connection in this thread
                handle_websocket(ws_conn);
                pthread_exit(NULL);
            }
            else
            {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_socket);
                pthread_exit(NULL);
            }
        }
        else
        {
            log_event("Secure WebSocket handshake failed");
            goto cleanup;
        }
    }

    char method[8], url[256], protocol[16];
    if (parse_request_line(buffer, method, url, protocol) != 0)
    {
        log_event("Invalid request line.");
        const char *bad_request_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request";
        SSL_write(ssl, bad_request_response, strlen(bad_request_response));
        goto cleanup;
    }
    else
    {
        log_event("Method:");
        log_event(method);
        log_event("URL:");
        log_event(url);
        log_event("Protocol:");
        log_event(protocol);
    }

    // Check if client accepts gzip (case-insensitive)
    int accepts_gzip = (stristr(buffer, "accept-encoding:") && 
                       stristr(buffer, "gzip")) ? 1 : 0;

    char *sanitized_url = sanitize_url(url);
    if (!sanitized_url)
    {
        log_event("Blocked malicious URL");
        const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
        SSL_write(ssl, forbidden_response, strlen(forbidden_response));
        goto cleanup;
    }

    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_socket, (struct sockaddr *)&addr, &addr_len);
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    if (!check_rate_limit(client_ip))
    {
        log_event("Rate limit exceeded for IP:");
        log_event(client_ip);
        const char *rate_limit_response = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded";
        SSL_write(ssl, rate_limit_response, strlen(rate_limit_response));
        goto cleanup;
    }

    char filepath[512];
    int written = snprintf(filepath, sizeof(filepath), "%s%s", config.www_path,
             (*sanitized_url == '/' && sanitized_url[1] == '\0') ? "/index.html" : sanitized_url);
    free(sanitized_url);
    
    if (written < 0 || written >= (int)sizeof(filepath))
    {
        log_event("Path too long, potential buffer overflow attempt (HTTPS)");
        const char *error_response = "HTTP/1.1 414 URI Too Long\r\n\r\n";
        SSL_write(ssl, error_response, strlen(error_response));
        goto cleanup;
    }
    log_event("Filepath:");
    log_event(filepath);

    // Get MIME type
    char *mime_type = get_mime_type(filepath);

    // Try to get file from cache first
    mmap_cache_entry_t *cached = get_cached_file(filepath);

    if (cached)
    {
        // Check if we should compress
        unsigned char *compressed_data = NULL;
        size_t compressed_size = 0;
        int using_compression = 0;
        
        if (accepts_gzip && should_compress(cached->mime_type) && cached->size > 1024)
        {
            compressed_data = gzip_compress((unsigned char *)cached->mmap_data, cached->size, &compressed_size);
            if (compressed_data && compressed_size < cached->size * 0.9)
            {
                using_compression = 1;
            }
            else if (compressed_data)
            {
                free(compressed_data);
                compressed_data = NULL;
            }
        }

        // Serve from cache with optional compression
        char response_header[2048];
        int header_len = snprintf(response_header, sizeof(response_header),
                                  "HTTP/1.1 200 OK\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Content-Type: %s\r\n"
                                  "Cache-Control: public, max-age=86400, immutable\r\n"
                                  "ETag: \"%zu-%ld%s\"\r\n"
                                  "%s"
                                  "%s"
                                  "Keep-Alive: timeout=5, max=100\r\n"
                                  "Connection: Keep-Alive\r\n"
                                  "\r\n",
                                  using_compression ? compressed_size : cached->size,
                                  cached->mime_type,
                                  cached->size,
                                  cached->last_access,
                                  using_compression ? "-gzip" : "",
                                  using_compression ? "Content-Encoding: gzip\r\n" : "",
                                  SECURITY_HEADERS);

        SSL_write(ssl, response_header, header_len);

        // Send compressed or uncompressed data
        void *data_to_send = using_compression ? compressed_data : cached->mmap_data;
        size_t size_to_send = using_compression ? compressed_size : cached->size;
        
        size_t total_sent = 0;
        while (total_sent < size_to_send)
        {
            int to_send = (size_to_send - total_sent > 65536) ? 65536 : (size_to_send - total_sent);
            int sent = SSL_write(ssl, (char *)data_to_send + total_sent, to_send);
            if (sent <= 0)
                break;
            total_sent += sent;
        }

        if (compressed_data)
            free(compressed_data);
        release_cached_file(cached);
        free(mime_type);
        log_event(using_compression ? "Served file from cache (gzip)" : "Served file from cache (mmap)");
        goto cleanup;
    }

    // Not in cache - load from disk
    int fd = open(filepath, O_RDONLY);
    if (fd == -1)
    {
        log_event("File open failed");
        const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
        SSL_write(ssl, not_found_response, strlen(not_found_response));
        free(mime_type);
        goto cleanup;
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        log_event("Error getting file size.");
        const char *internal_server_error =
            "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";
        SSL_write(ssl, internal_server_error, strlen(internal_server_error));
        close(fd);
        free(mime_type);
        goto cleanup;
    }

    // Cache file if it's small enough
    if (st.st_size > 0 && st.st_size < MAX_MMAP_FILE_SIZE)
    {
        cache_file_mmap(filepath, st.st_size, mime_type);
    }

    char response_header[2048];
    int header_len = snprintf(response_header, sizeof(response_header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Length: %ld\r\n"
                              "Content-Type: %s\r\n"
                              "Cache-Control: public, max-age=86400\r\n"
                              "ETag: \"%ld-%ld\"\r\n"
                              "%s"
                              "\r\n",
                              (long)st.st_size,
                              mime_type,
                              (long)st.st_size,
                              (long)st.st_mtime,
                              SECURITY_HEADERS);

    free(mime_type);

    SSL_write(ssl, response_header, header_len);

    // Use larger buffer for better performance
    char *file_buffer = get_buffer_from_pool(16384);
    ssize_t bytes_read;
    while ((bytes_read = read(fd, file_buffer, 16384)) > 0)
    {
        if (SSL_write(ssl, file_buffer, bytes_read) <= 0)
        {
            log_event("Error sending file content.");
            break;
        }
    }
    return_buffer_to_pool(file_buffer);
    close(fd);
    log_event("Served requested file successfully.");

cleanup:
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(client_socket);
    pthread_exit(NULL);
}

void shutdown_server()
{
    log_event("Initiating server shutdown...");

    // Set shutdown flags atomically
    __atomic_store_n(&server_running, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&config.running, 0, __ATOMIC_SEQ_CST);

    // Close all sockets
    if (http_socket != -1)
    {
        shutdown(http_socket, SHUT_RDWR);
        close(http_socket);
        http_socket = -1;
    }

    if (https_socket != -1)
    {
        shutdown(https_socket, SHUT_RDWR);
        close(https_socket);
        https_socket = -1;
    }

    if (epoll_fd != -1)
    {
        close(epoll_fd);
        epoll_fd = -1;
    }

    // Wait for all threads with timeout
    time_t start_time = time(NULL);

    pthread_mutex_lock(&thread_count_mutex);
    while (num_client_threads > 0 && (time(NULL) - start_time) < 5)
    {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000; // 100ms
        pthread_cond_timedwait(&thread_pool_cond, &thread_count_mutex, &ts);
    }

    // Force kill remaining threads
    for (int i = 0; i < num_client_threads; i++)
    {
        if (client_threads[i] != 0)
        {
            pthread_cancel(client_threads[i]);
            pthread_join(client_threads[i], NULL);
            client_threads[i] = 0;
        }
    }
    pthread_mutex_unlock(&thread_count_mutex);

    // Cleanup resources
    cleanup_openssl();
    cleanup_thread_pool();
    cleanup_mmap_cache();
    cleanup_buffer_pool();

    if (rate_limits)
    {
        free(rate_limits);
        rate_limits = NULL;
    }

    if (file_cache)
    {
        for (int i = 0; i < cache_size; i++)
        {
            free(file_cache[i].path);
            free(file_cache[i].data);
            free(file_cache[i].mime_type);
        }
        free(file_cache);
        file_cache = NULL;
    }

    if (client_threads)
    {
        free(client_threads);
        client_threads = NULL;
    }

    log_event("Server shutdown completed.");
}

int parse_request_line(char *request_buffer, char *method, char *url, char *protocol)
{
    if (!request_buffer || !method || !url || !protocol)
        return -1;

    method[0] = '\0';
    url[0] = '\0';
    protocol[0] = '\0';

    char *saveptr1, *saveptr2;
    char *line = strtok_r(request_buffer, "\r\n", &saveptr1);

    if (line == NULL || strlen(line) == 0)
        return -1;

    char *token = strtok_r(line, " ", &saveptr2);
    if (token == NULL || strlen(token) > 7)
        return -1;
    strncpy(method, token, 7);
    method[7] = '\0';

    token = strtok_r(NULL, " ", &saveptr2);
    if (token == NULL || strlen(token) > 255)
        return -1;
    strncpy(url, token, 255);
    url[255] = '\0';

    token = strtok_r(NULL, " ", &saveptr2);
    if (token == NULL || strlen(token) > 15)
        return -1;
    strncpy(protocol, token, 15);
    protocol[15] = '\0';

    return 0;
}

void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
    {
        server_running = 0;
        config.running = 0;
        if (config.use_https && config.running == 0 && server_running == 0)
        {
            if (https_socket != -1)
            {
                shutdown(https_socket, SHUT_RDWR);
                close(https_socket);
                https_socket = -1;
                exit(EXIT_SUCCESS);
            }
        }
        else
        {
            if (http_socket != -1)
            {
                shutdown(http_socket, SHUT_RDWR);
                close(http_socket);
                http_socket = -1;
                exit(EXIT_SUCCESS);
            }
        }

        printf("\nReceived signal %d, initiating shutdown...\n", sig);

        if (epoll_fd != -1)
        {
            close(epoll_fd);
            epoll_fd = -1;
        }

        log_event("Signal received, initiating shutdown...");
    }
}

void set_cpu_affinity(int thread_id)
{
#ifdef __linux__
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus > 0)
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(thread_id % num_cpus, &cpuset);
        
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
        {
            log_event("Warning: Failed to set CPU affinity");
        }
    }
#endif
}

void *worker_thread(void *arg)
{
    int thread_id = *((int *)arg);
    free(arg);
    
    // Set CPU affinity for this worker thread
    set_cpu_affinity(thread_id);
    
    char log_msg[256];
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    snprintf(log_msg, sizeof(log_msg), "Worker thread %d started on CPU %d", thread_id, thread_id % num_cpus);
    log_event(log_msg);
    
    while (workers_running)
    {
        connection_task_t *task = dequeue_task(&worker_queue);
        
        if (!task || !workers_running)
        {
            break;
        }
        
        // Optimize socket before handling
        optimize_socket_for_send(task->socket_fd);
        
        // Handle the connection based on type
        if (task->is_https)
        {
            int *socket_ptr = malloc(sizeof(int));
            if (socket_ptr)
            {
                *socket_ptr = task->socket_fd;
                handle_https_client(socket_ptr);
            }
        }
        else
        {
            int *socket_ptr = malloc(sizeof(int));
            if (socket_ptr)
            {
                *socket_ptr = task->socket_fd;
                handle_http_client(socket_ptr);
            }
        }
        
        free(task);
    }
    
    return NULL;
}

void initialize_thread_pool()
{
    thread_pool_size = config.max_threads;
    thread_pool = calloc(thread_pool_size, sizeof(ThreadInfo));
    if (!thread_pool)
    {
        log_event("Failed to allocate thread pool");
    }
    
    // Initialize worker queue
    init_task_queue(&worker_queue);
    
    // Create worker threads
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    num_worker_threads = (num_cpus > 0) ? num_cpus * 2 : 8;
    if (num_worker_threads > MAX_THREAD_POOL_SIZE)
    {
        num_worker_threads = MAX_THREAD_POOL_SIZE;
    }
    
    worker_threads = calloc(num_worker_threads, sizeof(pthread_t));
    if (!worker_threads)
    {
        log_event("Failed to allocate worker threads");
        return;
    }
    
    for (int i = 0; i < num_worker_threads; i++)
    {
        int *thread_id = malloc(sizeof(int));
        if (thread_id)
        {
            *thread_id = i;
            if (pthread_create(&worker_threads[i], NULL, worker_thread, thread_id) != 0)
            {
                log_event("Failed to create worker thread");
                free(thread_id);
            }
        }
    }
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Initialized %d worker threads on %d CPUs", num_worker_threads, num_cpus);
    log_event(msg);
}

// Case-insensitive strstr
char *stristr(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return NULL;
    
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return (char *)haystack;
    
    for (const char *p = haystack; *p; p++)
    {
        if (tolower(*p) == tolower(*needle))
        {
            size_t i;
            for (i = 1; i < needle_len && p[i]; i++)
            {
                if (tolower(p[i]) != tolower(needle[i]))
                    break;
            }
            if (i == needle_len)
                return (char *)p;
        }
    }
    return NULL;
}

// Check if MIME type should be compressed
int should_compress(const char *mime_type)
{
    return (strstr(mime_type, "text/") != NULL ||
            strstr(mime_type, "application/javascript") != NULL ||
            strstr(mime_type, "application/json") != NULL ||
            strstr(mime_type, "application/xml") != NULL);
}

// Gzip compress data
unsigned char *gzip_compress(const unsigned char *data, size_t size, size_t *compressed_size)
{
    z_stream stream = {0};
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        return NULL;
    }

    size_t max_compressed = deflateBound(&stream, size);
    unsigned char *compressed = malloc(max_compressed);
    if (!compressed)
    {
        deflateEnd(&stream);
        return NULL;
    }

    stream.avail_in = size;
    stream.next_in = (unsigned char *)data;
    stream.avail_out = max_compressed;
    stream.next_out = compressed;

    if (deflate(&stream, Z_FINISH) != Z_STREAM_END)
    {
        free(compressed);
        deflateEnd(&stream);
        return NULL;
    }

    *compressed_size = stream.total_out;
    deflateEnd(&stream);

    return compressed;
}

int main()
{
    if (load_config("server.conf", &config) != 0)
    {
        printf("Using default configuration.\n");
    }

    config.running = 1;

    // Allocate client threads array
    client_threads = calloc(config.max_connections, sizeof(pthread_t));
    if (!client_threads)
    {
        perror("Failed to allocate client threads array");
        exit(EXIT_FAILURE);
    }

    // Initialize thread pool
    initialize_thread_pool();

    // Initialize performance optimizations
    init_mmap_cache();
    init_buffer_pool();
    log_event("Performance optimizations initialized");

    if (config.use_https)
    {
        initialize_openssl();
        ssl_ctx = create_ssl_context();
        configure_ssl_context(ssl_ctx);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart interrupted system calls

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("Failed to set up signal handlers");
        exit(EXIT_FAILURE);
    }

    pthread_t http_thread;
    if (pthread_create(&http_thread, NULL, start_http_server, NULL) != 0)
    {
        perror("Failed to create HTTP server thread");
        exit(EXIT_FAILURE);
    }

    pthread_t https_thread;
    if (config.use_https)
    {
        if (pthread_create(&https_thread, NULL, start_https_server, NULL) != 0)
        {
            perror("Failed to create HTTPS server thread");
            exit(EXIT_FAILURE);
        }
    }

    while (config.running)
    {
        sleep(1);
    }

    shutdown_server();
    pthread_join(http_thread, NULL);
    if (config.use_https)
    {
        pthread_join(https_thread, NULL);
    }

    return 0;
}

void log_event(const char *message)
{
    pthread_mutex_lock(&log_mutex);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    // Create log directory if it doesn't exist
    char log_dir[512];
    strncpy(log_dir, config.log_file, sizeof(log_dir) - 1);
    log_dir[sizeof(log_dir) - 1] = '\0';
    char *dir_path = dirname(log_dir);

    struct stat st;
    if (stat(dir_path, &st) != 0)
    {
        if (mkdir(dir_path, 0755) != 0)
        {
            fprintf(stderr, "Error creating log directory (%s): %s\n", dir_path, strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            return;
        }
    }
    else if (!S_ISDIR(st.st_mode))
    {
        fprintf(stderr, "Log path (%s) exists but is not a directory\n", dir_path);
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    // Check log file size and rotate if necessary
    if (stat(config.log_file, &st) == 0)
    {
        if (st.st_size > MAX_LOG_FILE_SIZE)
        {
            char backup_log[512];
            snprintf(backup_log, sizeof(backup_log), "%s.old", config.log_file);
            rename(config.log_file, backup_log);
        }
    }

    FILE *logfile = fopen(config.log_file, "a");
    if (!logfile)
    {
        fprintf(stderr, "Error opening log file (%s): %s\n", config.log_file, strerror(errno));
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    // Format log entry with timestamp, process ID, and thread ID
    char log_entry[LOG_BUFFER_SIZE];
    snprintf(log_entry, sizeof(log_entry), "[%s] [PID:%d] [TID:%lu] %s\n",
             timestamp,
             getpid(),
             pthread_self(),
             message);

    // Write to log file
    if (fputs(log_entry, logfile) == EOF)
    {
        fprintf(stderr, "Error writing to log file: %s\n", strerror(errno));
    }

    // Ensure log is written immediately
    fflush(logfile);
    fclose(logfile);

    // Also print to stdout for debugging if verbose mode is enabled
    if (config.verbose)
    {
        printf("%s", log_entry);
        fflush(stdout);
    }

    pthread_mutex_unlock(&log_mutex);
}

char *get_mime_type(const char *filepath)
{
    const char *ext = strrchr(filepath, '.');
    if (!ext)
        return strdup("application/octet-stream");

    ext++; // Skip the dot

    if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0)
        return strdup("text/html");
    if (strcasecmp(ext, "css") == 0)
        return strdup("text/css");
    if (strcasecmp(ext, "js") == 0)
        return strdup("application/javascript");
    if (strcasecmp(ext, "png") == 0)
        return strdup("image/png");
    if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
        return strdup("image/jpeg");
    if (strcasecmp(ext, "gif") == 0)
        return strdup("image/gif");
    if (strcasecmp(ext, "svg") == 0)
        return strdup("image/svg+xml");
    if (strcasecmp(ext, "ico") == 0)
        return strdup("image/x-icon");
    if (strcasecmp(ext, "woff") == 0)
        return strdup("font/woff");
    if (strcasecmp(ext, "woff2") == 0)
        return strdup("font/woff2");
    if (strcasecmp(ext, "ttf") == 0)
        return strdup("font/ttf");
    if (strcasecmp(ext, "otf") == 0)
        return strdup("font/otf");

    // Fallback to using libmagic for unknown types
    magic_t magic = magic_open(MAGIC_MIME_TYPE);
    if (magic == NULL)
    {
        return strdup("application/octet-stream");
    }

    if (magic_load(magic, NULL) != 0)
    {
        magic_close(magic);
        return strdup("application/octet-stream");
    }

    const char *mime = magic_file(magic, filepath);
    char *result = mime ? strdup(mime) : strdup("application/octet-stream");

    magic_close(magic);
    return result;
}

char *sanitize_url(const char *url)
{
    if (!url)
        return NULL;

    size_t url_len = strlen(url);
    if (url_len == 0 || url_len > 2048)
        return NULL;

    char *sanitized = calloc(1, url_len + 2);
    if (!sanitized)
    {
        log_event("Memory allocation failed in sanitize_url");
        return NULL;
    }

    int j = 0;
    int slash_count = 0;
    int consecutive_dots = 0;
    bool last_was_slash = false;

    // Must start with '/'
    if (url[0] != '/')
    {
        sanitized[j++] = '/';
    }

    for (size_t i = 0; i < url_len && j < (int)url_len; i++)
    {
        char c = url[i];

        // Check for null bytes (security)
        if (c == '\0')
            break;

        // Handle slashes
        if (c == '/')
        {
            if (last_was_slash)
                continue;
            last_was_slash = true;
            consecutive_dots = 0;
            slash_count++;

            if (slash_count > 20)
            {
                free(sanitized);
                return NULL;
            }

            sanitized[j++] = c;
            continue;
        }

        last_was_slash = false;

        // Handle dots (prevent traversal)
        if (c == '.')
        {
            consecutive_dots++;
            if (consecutive_dots > 2)
            { // Too many dots
                free(sanitized);
                return NULL;
            }
            // Check for path traversal patterns
            if (consecutive_dots == 2 && (i == 0 || url[i - 1] == '/'))
            {
                free(sanitized);
                return NULL;
            }
        }
        else
        {
            consecutive_dots = 0;
        }

        // Only allow safe characters (alphanumeric, dash, underscore, dot)
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.')
        {
            sanitized[j++] = c;
        }
        else if (c == '%')
        {
            // URL encoding - decode and validate the character
            if (i + 2 < url_len && isxdigit(url[i + 1]) && isxdigit(url[i + 2]))
            {
                char hex[3] = {url[i + 1], url[i + 2], 0};
                int decoded = (int)strtol(hex, NULL, 16);
                
                // Block encoded directory traversal characters and control characters
                if (decoded == '.' || decoded == '/' || decoded == '\\' || 
                    decoded == 0x00 || decoded < 0x20 || decoded > 0x7E)
                {
                    free(sanitized);
                    return NULL;
                }
                
                sanitized[j++] = (char)decoded;
                i += 2;
            }
            else
            {
                free(sanitized);
                return NULL;
            }
        }
        // Skip other characters silently
    }

    sanitized[j] = '\0';

    // Final security checks
    if (j == 0 || j > 2048)
    {
        free(sanitized);
        return NULL;
    }

    // Check for dangerous patterns
    if (strstr(sanitized, "/../") ||
        strstr(sanitized, "/./") ||
        strstr(sanitized, "//") ||
        (strlen(sanitized) >= 3 && strcmp(sanitized + strlen(sanitized) - 3, "/..") == 0))
    {
        free(sanitized);
        return NULL;
    }

    return sanitized;
}

int check_rate_limit(const char *ip)
{
    pthread_mutex_lock(&rate_limit_mutex);

    time_t now = time(NULL);
    int i;

    // Clean up expired entries
    for (i = 0; i < rate_limit_count; i++)
    {
        if (now - rate_limits[i].window_start >= RATE_LIMIT_WINDOW)
        {
            if (i < rate_limit_count - 1)
            {
                memcpy(&rate_limits[i], &rate_limits[rate_limit_count - 1], sizeof(RateLimit));
            }
            rate_limit_count--;
            i--;
        }
    }

    // Find or create entry for this IP
    for (i = 0; i < rate_limit_count; i++)
    {
        if (strcmp(rate_limits[i].ip, ip) == 0)
        {
            if (now - rate_limits[i].window_start >= RATE_LIMIT_WINDOW)
            {
                rate_limits[i].window_start = now;
                rate_limits[i].request_count = 1;
            }
            else if (rate_limits[i].request_count >= MAX_REQUESTS)
            {
                pthread_mutex_unlock(&rate_limit_mutex);
                return 0; // Rate limit exceeded
            }
            else
            {
                rate_limits[i].request_count++;
            }
            pthread_mutex_unlock(&rate_limit_mutex);
            return 1; // Request allowed
        }
    }

    // Add new entry
    RateLimit *new_limits = realloc(rate_limits, (rate_limit_count + 1) * sizeof(RateLimit));
    if (!new_limits)
    {
        pthread_mutex_unlock(&rate_limit_mutex);
        return 0; // Memory allocation failed, deny request
    }
    rate_limits = new_limits;

    size_t ip_len = strlen(ip);
    if (ip_len >= INET_ADDRSTRLEN)
    {
        ip_len = INET_ADDRSTRLEN - 1;
    }
    memcpy(rate_limits[rate_limit_count].ip, ip, ip_len);
    rate_limits[rate_limit_count].ip[ip_len] = '\0';
    rate_limits[rate_limit_count].window_start = now;
    rate_limits[rate_limit_count].request_count = 1;
    rate_limit_count++;

    pthread_mutex_unlock(&rate_limit_mutex);
    return 1; // Request allowed
}

void cleanup_thread_pool()
{
    // Signal worker threads to stop
    workers_running = 0;
    
    // Wake up all waiting workers
    pthread_mutex_lock(&worker_queue.mutex);
    pthread_cond_broadcast(&worker_queue.cond);
    pthread_mutex_unlock(&worker_queue.mutex);
    
    // Join all worker threads
    if (worker_threads)
    {
        for (int i = 0; i < num_worker_threads; i++)
        {
            pthread_join(worker_threads[i], NULL);
        }
        free(worker_threads);
        worker_threads = NULL;
    }
    
    // Cleanup worker queue
    destroy_task_queue(&worker_queue);
    
    // Cleanup old thread pool structure if exists
    if (!thread_pool)
    {
        return;
    }

    pthread_mutex_lock(&thread_pool_mutex);
    
    ThreadInfo *temp = thread_pool;
    thread_pool = NULL;
    thread_pool_size = 0;
    
    pthread_mutex_unlock(&thread_pool_mutex);
    
    // Free after releasing lock and nullifying pointer
    free(temp);
}

void cache_file(const char *path, const char *data, size_t size, const char *mime_type)
{
    pthread_mutex_lock(&cache_mutex);

    if (cache_size >= MAX_CACHE_SIZE)
    {
        // Remove least recently used entry
        int lru_index = 0;
        time_t oldest = file_cache[0].last_access;

        for (int i = 1; i < cache_size; i++)
        {
            if (file_cache[i].last_access < oldest)
            {
                oldest = file_cache[i].last_access;
                lru_index = i;
            }
        }

        free(file_cache[lru_index].path);
        free(file_cache[lru_index].data);
        free(file_cache[lru_index].mime_type);

        // Move last entry to this position
        if (lru_index < cache_size - 1)
        {
            memmove(&file_cache[lru_index], &file_cache[cache_size - 1], sizeof(CacheEntry));
        }
        cache_size--;
    }

    file_cache = realloc(file_cache, (cache_size + 1) * sizeof(CacheEntry));
    file_cache[cache_size].path = strdup(path);
    file_cache[cache_size].data = malloc(size);
    memcpy(file_cache[cache_size].data, data, size);
    file_cache[cache_size].size = size;
    file_cache[cache_size].last_access = time(NULL);
    file_cache[cache_size].mime_type = strdup(mime_type);
    cache_size++;

    pthread_mutex_unlock(&cache_mutex);
}
