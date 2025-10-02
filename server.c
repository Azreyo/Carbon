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
#include <cJSON.h>
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

#include "server_config.h"

#define MAX_REQUEST_SIZE 8192
#define MAX_LOG_SIZE 2048
#define MAX_CLIENTS 1024
#define MAX_EVENTS 1024

#define BOLD    "\x1b[1m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define RESET   "\x1b[0m"

#define HANDLE_ERROR(msg) do { \
    log_event(msg ": " BOLD RED); \
    log_event(strerror(errno)); \
    goto cleanup; \
} while(0)

// Use larger buffer for file operations
#define FILE_BUFFER_SIZE 65536

#define SECURITY_HEADERS \
    "X-Content-Type-Options: nosniff\r\n" \
    "X-Frame-Options: SAMEORIGIN\r\n" \
    "X-XSS-Protection: 1; mode=block\r\n" \
    "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " \
    "font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline';\r\n"

#define RATE_LIMIT_WINDOW 60  // 60 seconds
#define MAX_REQUESTS 100      // max requests per window

#define LOG_BUFFER_SIZE 4096
#define MAX_LOG_FILE_SIZE (100 * 1024 * 1024)  // 100MB max log file size

#define SOCKET_SEND_BUFFER_SIZE (256 * 1024)  // 256KB
#define SOCKET_RECV_BUFFER_SIZE (256 * 1024)  // 256KB
#define SOCKET_BACKLOG 128  // Increased from 50
#define EPOLL_TIMEOUT 100   // 100ms timeout

#define MAX_THREAD_POOL_SIZE 32

#define MAX_CACHE_SIZE 100
#define MAX_CACHE_FILE_SIZE (1024 * 1024)  // 1MB

typedef struct {
    pthread_t thread;
    int busy;
} ThreadInfo;

ThreadInfo *thread_pool;
int thread_pool_size = 0;
pthread_mutex_t thread_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t thread_pool_cond = PTHREAD_COND_INITIALIZER;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t window_start;
    int request_count;
} RateLimit;

typedef struct {
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
pthread_t client_threads[MAX_CLIENTS];
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
void log_event(const char *message);
void initialize_openssl();
void cleanup_openssl();
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);
void *start_http_server(void *arg);
void *start_https_server(void *arg);
void shutdown_server();
int parse_request_line(char *request_buffer, char *method, char *url, char *protocol);
char* get_mime_type(const char *filepath);
char* sanitize_url(const char *url);
int check_rate_limit(const char *ip);

void initialize_openssl() {
    if (!SSL_library_init()) {
        perror(BOLD RED "Error initializing OpenSSL library" RESET);
        exit(EXIT_FAILURE);
    }
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}


void cleanup_openssl() {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
    EVP_cleanup();
}


SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror(BOLD RED "Unable to create SSL context" RESET);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (SSL_CTX_set_cipher_list(ctx, "HIGH: !aNULL: !MD5") != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

void set_socket_options(int socket_fd) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);  // Make socket non-blocking

    int reuse = 1;
    int keepalive = 1;
    int keepidle = 60;
    int keepintvl = 10;
    int keepcnt = 5;
    int nodelay = 1;

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
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

void *start_http_server(void *arg) {
	(void)arg;
    http_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket < 0) {
        perror(BOLD RED "Error creating HTTP socket" RESET);
        pthread_exit(NULL);
    }

    set_socket_options(http_socket);

    struct sockaddr_in http_address = {0};
    http_address.sin_family = AF_INET;
    http_address.sin_addr.s_addr = INADDR_ANY;
    http_address.sin_port = htons(config.port);

    if (bind(http_socket, (struct sockaddr *)&http_address, sizeof(http_address)) < 0) {
        perror(BOLD RED "Error binding HTTP socket" RESET);
        close(http_socket);
        pthread_exit(NULL);
    }

    if (listen(http_socket, SOCKET_BACKLOG) < 0) {
        perror(BOLD RED "Error listening on HTTP socket" RESET);
        close(http_socket);
        pthread_exit(NULL);
    }

    epoll_fd = epoll_create1(0);  // Create epoll instance
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(http_socket); // Close the socket before exiting
        pthread_exit(NULL);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = http_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http_socket, &ev) == -1) {
        perror("epoll_ctl: http_socket");
        close(http_socket);
        close(epoll_fd); // Close epoll fd
        pthread_exit(NULL);
    }

    log_event("HTTP server started.");

    struct epoll_event events[MAX_EVENTS];
    while (config.running && server_running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT); // 100ms timeout
        if (nfds == -1) {
            if (errno != EINTR) { // Ignore interrupts for shutdown
                perror("epoll_wait");
                break; // Exit loop on error
            }
            continue; // Continue if it was an interrupt
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == http_socket) {
                // New connection
                struct sockaddr_in client_addr;
                socklen_t addr_size = sizeof(client_addr);
                int client_socket = accept(http_socket, (struct sockaddr *)&client_addr, &addr_size);
                if (client_socket < 0) {
                    perror("accept");
                    continue;
                }

                pthread_mutex_lock(&thread_count_mutex);
                if (num_client_threads < MAX_CLIENTS) {
                    pthread_t client_thread;
                    int *client_socket_ptr = malloc(sizeof(int));
                    *client_socket_ptr = client_socket;

                    if (pthread_create(&client_thread, NULL, handle_http_client, client_socket_ptr) == 0) {
                        client_threads[num_client_threads++] = client_thread;
                    } else {
                        perror("Error creating HTTP client thread");
                        close(client_socket);
                        free(client_socket_ptr);
                    }
                } else {
                    log_event("Max client threads reached, rejecting connection.");
                    close(client_socket);
                }
                pthread_mutex_unlock(&thread_count_mutex);
            }
        }
    }

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, http_socket, NULL);
    close(http_socket);
    close(epoll_fd);
    log_event("HTTP server stopped.");
    pthread_exit(NULL);
}



void *start_https_server(void *arg) {
	(void)arg;
    https_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (https_socket < 0) {
        perror(BOLD RED "Error creating HTTPS socket" RESET);
        pthread_exit(NULL);
    }

    set_socket_options(https_socket);

    struct sockaddr_in https_address;
    memset(&https_address, 0, sizeof(https_address));
    https_address.sin_family = AF_INET;
    https_address.sin_addr.s_addr = INADDR_ANY;
    https_address.sin_port = htons(443);

    if (bind(https_socket, (struct sockaddr *)&https_address, sizeof(https_address)) < 0) {
        perror(BOLD RED "Error binding HTTPS socket" RESET);
        close(https_socket);
        pthread_exit(NULL);
    }

    if (listen(https_socket, SOCKET_BACKLOG) < 0) {
        perror(BOLD RED "Error listening on HTTPS socket" RESET);
        close(https_socket);
        pthread_exit(NULL);
    }

    log_event("HTTPS server started.");

    while (config.running && server_running) {
        int client_socket = accept(https_socket, NULL, NULL);
        if (client_socket < 0) {
            perror("Error accepting HTTPS connection");
            continue;
        }

        pthread_mutex_lock(&thread_count_mutex);
        if (num_client_threads < MAX_CLIENTS) {
            pthread_t client_thread;
            int *client_socket_ptr = malloc(sizeof(int));
            *client_socket_ptr = client_socket;

            if (pthread_create(&client_thread, NULL, handle_https_client, client_socket_ptr) == 0) {
                client_threads[num_client_threads++] = client_thread;
            } else {
                perror("Error creating HTTPS client thread");
                close(client_socket);
                free(client_socket_ptr);
            }
        } else {
            log_event("Max client threads reached, rejecting connection.");
            close(client_socket);
        }
        pthread_mutex_unlock(&thread_count_mutex);
    }

    close(https_socket);
    pthread_exit(NULL);
}


void *handle_http_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);

    char request_buffer[MAX_REQUEST_SIZE];
    ssize_t bytes_received = recv(client_socket, request_buffer, MAX_REQUEST_SIZE - 1, 0);

    if (!server_running) {
        close(client_socket); // Close socket before exiting
        pthread_exit(NULL);
    }

    if (bytes_received > 0) {
        request_buffer[bytes_received] = '\0';
        log_event("Received HTTP request");

        char method[8], url[256], protocol[16];
        if (parse_request_line(request_buffer, method, url, protocol) != 0) {
            log_event("Invalid request line.");
            const char *bad_request_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request";
            send(client_socket, bad_request_response, strlen(bad_request_response), 0);
            close(client_socket);
            return NULL;
        }

        if (config.use_https) {  // Check if HTTPS is enabled
            char redirect_response[512];
            snprintf(redirect_response, sizeof(redirect_response),
                     "HTTP/1.1 301 Moved Permanently\r\n"
                     "Location: https://%.255s%.255s\r\n\r\n", config.server_name, url);
            send(client_socket, redirect_response, strlen(redirect_response), 0);
            log_event("Redirecting to HTTPS"); // Log the redirection
            close(client_socket);
            return NULL;
        }

        char *sanitized_url = sanitize_url(url);
        if (!sanitized_url) {
            log_event("Blocked malicious URL");
            const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
            send(client_socket, forbidden_response, strlen(forbidden_response), 0);
            return NULL;
        }

        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        getpeername(client_socket, (struct sockaddr *)&addr, &addr_len);
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

        if (!check_rate_limit(client_ip)) {
            log_event("Rate limit exceeded for IP:");
            log_event(client_ip);
            const char *rate_limit_response = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded";
            send(client_socket, rate_limit_response, strlen(rate_limit_response), 0);
            close(client_socket);
            return NULL;
        }

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "www%s", 
                 (*sanitized_url == '/' && sanitized_url[1] == '\0') ? "/index.html" : sanitized_url);
        free(sanitized_url);

        // Get MIME type
        char *mime_type = get_mime_type(filepath);

        int fd = open(filepath, O_RDONLY);
        if (fd == -1) {
            const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
            send(client_socket, not_found_response, strlen(not_found_response), 0);
            free(mime_type);
            log_event("File not found, sent 404.");
        } else {
            struct stat st;
            if (fstat(fd, &st) == -1) {
                log_event("Error getting file size.");
                const char *internal_server_error = 
                    "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";
                send(client_socket, internal_server_error, strlen(internal_server_error), 0);
                close(fd);
                free(mime_type);
                goto cleanup;
            }

            char response_header[512];
            snprintf(response_header, sizeof(response_header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Type: %s\r\n"
                     "%s"
                     "\r\n",
                     (long)st.st_size,
                     mime_type,
                     SECURITY_HEADERS);

            free(mime_type);

            send(client_socket, response_header, strlen(response_header), 0);

            off_t offset = 0;
            ssize_t sent = sendfile(client_socket, fd, &offset, st.st_size);
            if (sent != st.st_size) {
                log_event("Error sending file with sendfile()");
            }

            close(fd);
            log_event("Served requested file successfully.");
        }
    } else if (bytes_received < 0) {
        HANDLE_ERROR("Error receiving request");
    }

	close(client_socket);
    pthread_exit(NULL);

cleanup:
    close(client_socket);
    pthread_exit(NULL);
}



void *handle_https_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        log_event("SSL_new failed");
        close(client_socket);
        pthread_exit(NULL);
    }
    SSL_set_fd(ssl, client_socket);

    if (!server_running) {
        SSL_free(ssl); // Free SSL context if server is not running
        close(client_socket);
        pthread_exit(NULL);
    }

    if (SSL_accept(ssl) <= 0) {
        perror("SSL_accept error");
        ERR_print_errors_fp(stderr);
        log_event("SSL handshake failed.");
        SSL_free(ssl); // Free SSL context on failure
        close(client_socket);
        pthread_exit(NULL);
    }

    log_event("SSL handshake successful!");

    char buffer[MAX_REQUEST_SIZE];
    ssize_t bytes_received = SSL_read(ssl, buffer, MAX_REQUEST_SIZE - 1);

    if (bytes_received < 0) {
        perror("SSL_read error");
        ERR_print_errors_fp(stderr);
        log_event("SSL_read failed");
        goto cleanup;
    } else if (bytes_received == 0) {
        log_event("Client closed connection");
        goto cleanup;
    } else {
        buffer[bytes_received] = '\0';
        log_event("Received HTTPS request:");
        log_event(buffer);
    }

    char method[8], url[256], protocol[16];
    if (parse_request_line(buffer, method, url, protocol) != 0) {
        log_event("Invalid request line.");
        const char *bad_request_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request";
        SSL_write(ssl, bad_request_response, strlen(bad_request_response));
        goto cleanup;
    } else {
        log_event("Method:");
        log_event(method);
        log_event("URL:");
        log_event(url);
        log_event("Protocol:");
        log_event(protocol);
    }

    char *sanitized_url = sanitize_url(url);
    if (!sanitized_url) {
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

    if (!check_rate_limit(client_ip)) {
        log_event("Rate limit exceeded for IP:");
        log_event(client_ip);
        const char *rate_limit_response = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded";
        SSL_write(ssl, rate_limit_response, strlen(rate_limit_response));
        goto cleanup;
    }

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "www%s", 
             (*sanitized_url == '/' && sanitized_url[1] == '\0') ? "/index.html" : sanitized_url);
    free(sanitized_url);
    log_event("Filepath:");
    log_event(filepath);

    // Get MIME type
    char *mime_type = get_mime_type(filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        perror("open error");
        log_event("File open failed");
        const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
        SSL_write(ssl, not_found_response, strlen(not_found_response));
        free(mime_type);
        goto cleanup;
    } else {
        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat error");
            log_event("Error getting file size.");
            const char *internal_server_error = 
                "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";
            SSL_write(ssl, internal_server_error, strlen(internal_server_error));
            close(fd);
            free(mime_type);
            goto cleanup;
        }

        char response_header[512];
        snprintf(response_header, sizeof(response_header),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Length: %ld\r\n"
                 "Content-Type: %s\r\n"
                 "%s"
                 "\r\n",
                 (long)st.st_size,
                 mime_type,
                 SECURITY_HEADERS);

        free(mime_type);

        SSL_write(ssl, response_header, strlen(response_header));

        char file_buffer[1024];
        ssize_t bytes_read;
        while ((bytes_read = read(fd, file_buffer, sizeof(file_buffer))) > 0) {
            if (SSL_write(ssl, file_buffer, bytes_read) <= 0) {
                perror("SSL_write error");
                log_event("Error sending file content.");
                break;
            }
        }
        close(fd);
        log_event("Served requested file successfully.");
    }

cleanup:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(client_socket);
    pthread_exit(NULL);
}


void shutdown_server() {
    log_event("Initiating server shutdown...");
    
    // Set shutdown flags atomically
    __atomic_store_n(&server_running, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&config.running, 0, __ATOMIC_SEQ_CST);
    
    // Close all sockets
    if (http_socket != -1) {
        shutdown(http_socket, SHUT_RDWR);
        close(http_socket);
        http_socket = -1;
    }
    
    if (https_socket != -1) {
        shutdown(https_socket, SHUT_RDWR);
        close(https_socket);
        https_socket = -1;
    }
    
    if (epoll_fd != -1) {
        close(epoll_fd);
        epoll_fd = -1;
    }

    // Wait for all threads with timeout
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;  // 5 second timeout

    pthread_mutex_lock(&thread_count_mutex);
    while (num_client_threads > 0 && clock_gettime(CLOCK_REALTIME, &ts) < 5) {
        pthread_cond_timedwait(&thread_pool_cond, &thread_count_mutex, &ts);
    }
    
    // Force kill remaining threads
    for (int i = 0; i < num_client_threads; i++) {
        if (client_threads[i] != 0) {
            pthread_cancel(client_threads[i]);
            pthread_join(client_threads[i], NULL);
            client_threads[i] = 0;
        }
    }
    pthread_mutex_unlock(&thread_count_mutex);

    // Cleanup resources
    cleanup_openssl();
    cleanup_thread_pool();
    
    if (rate_limits) {
        free(rate_limits);
        rate_limits = NULL;
    }
    
    if (file_cache) {
        for (int i = 0; i < cache_size; i++) {
            free(file_cache[i].path);
            free(file_cache[i].data);
            free(file_cache[i].mime_type);
        }
        free(file_cache);
        file_cache = NULL;
    }
    
    log_event("Server shutdown completed.");
}


int parse_request_line(char *request_buffer, char *method, char *url, char *protocol) {
    char *saveptr1, *saveptr2;
    char *line = strtok_r(request_buffer, "\r\n", &saveptr1);

    if (line == NULL) return -1;

    char *token = strtok_r(line, " ", &saveptr2);
    if (token == NULL) return -1;
    strncpy(method, token, 7); method[7] = '\0';

    token = strtok_r(NULL, " ", &saveptr2);
    if (token == NULL) return -1;
    strncpy(url, token, 255); url[255] = '\0';

    token = strtok_r(NULL, " ", &saveptr2);
    if (token == NULL) return -1;
    strncpy(protocol, token, 15); protocol[15] = '\0';

    return 0;
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nReceived signal %d, initiating shutdown...\n", sig);
        
        // Set shutdown flags first
        server_running = 0;
        config.running = 0;
        
        // Force close listening sockets to unblock accept()
        if (http_socket != -1) {
            shutdown(http_socket, SHUT_RDWR);
            close(http_socket);
            http_socket = -1;
        }
        
        if (https_socket != -1) {
            shutdown(https_socket, SHUT_RDWR);
            close(https_socket);
            https_socket = -1;
        }
        
        // Close epoll fd to unblock epoll_wait
        if (epoll_fd != -1) {
            close(epoll_fd);
            epoll_fd = -1;
        }
        
        log_event("Signal received, initiating shutdown...");
    }
}

int main() {
    if (load_config("server.json", &config) != 0) {
        printf("Using default configuration.\n");
    }

    config.running = 1;

    if (config.use_https) {
        initialize_openssl();
        ssl_ctx = create_ssl_context();
        configure_ssl_context(ssl_ctx);
    }

	struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;  // Restart interrupted system calls

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Failed to set up signal handlers");
        exit(EXIT_FAILURE);
    }

	pthread_t http_thread;
    if (pthread_create(&http_thread, NULL, start_http_server, NULL) != 0) {
        perror("Failed to create HTTP server thread");
        exit(EXIT_FAILURE);
    }

    pthread_t https_thread;
    if (config.use_https) {
        if (pthread_create(&https_thread, NULL, start_https_server, NULL) != 0) {
            perror("Failed to create HTTPS server thread");
            exit(EXIT_FAILURE);
        }
    }

    while (config.running) {
        sleep(1);
    }

    shutdown_server();
    pthread_join(http_thread, NULL);
    if (config.use_https) {
        pthread_join(https_thread, NULL);
    }

    return 0;
}

void log_event(const char *message) {
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
    if (stat(dir_path, &st) != 0) {
        if (mkdir(dir_path, 0755) != 0) {
            fprintf(stderr, "Error creating log directory (%s): %s\n", dir_path, strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            return;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Log path (%s) exists but is not a directory\n", dir_path);
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    // Check log file size and rotate if necessary
    if (stat(config.log_file, &st) == 0) {
        if (st.st_size > MAX_LOG_FILE_SIZE) {
            char backup_log[512];
            snprintf(backup_log, sizeof(backup_log), "%s.old", config.log_file);
            rename(config.log_file, backup_log);
        }
    }

    FILE *logfile = fopen(config.log_file, "a");
    if (!logfile) {
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
    if (fputs(log_entry, logfile) == EOF) {
        fprintf(stderr, "Error writing to log file: %s\n", strerror(errno));
    }

    // Ensure log is written immediately
    fflush(logfile);
    fclose(logfile);

    // Also print to stdout for debugging if verbose mode is enabled
    if (config.verbose) {
        printf("%s", log_entry);
        fflush(stdout);
    }

    pthread_mutex_unlock(&log_mutex);
}

char* get_mime_type(const char *filepath) {
    const char *ext = strrchr(filepath, '.');
    if (!ext) return strdup("application/octet-stream");
    
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
    if (magic == NULL) {
        return strdup("application/octet-stream");
    }
    
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return strdup("application/octet-stream");
    }
    
    const char *mime = magic_file(magic, filepath);
    char *result = mime ? strdup(mime) : strdup("application/octet-stream");
    
    magic_close(magic);
    return result;
}

char* sanitize_url(const char *url) {
    if (!url) return NULL;
    
    size_t url_len = strlen(url);
    if (url_len == 0 || url_len > 255) return NULL;
    
    char *sanitized = malloc(url_len + 1);
    if (!sanitized) {
        log_event("Memory allocation failed in sanitize_url");
        return NULL;
    }
    
    int i, j = 0;
    int slash_count = 0;
    int dot_count = 0;
    
    // Must start with '/'
    if (url[0] != '/') {
        sanitized[j++] = '/';
    }
    
    for (i = 0; url[i]; i++) {
        if (j >= 255) { // Prevent buffer overflow
            free(sanitized);
            return NULL;
        }
        
        // Reset dot count on directory change
        if (url[i] == '/') {
            dot_count = 0;
            slash_count++;
            if (slash_count > 10) { // Limit directory depth
                free(sanitized);
                return NULL;
            }
        }
        
        // Count consecutive dots
        if (url[i] == '.') {
            dot_count++;
            if (dot_count > 1) { // Prevent directory traversal
                free(sanitized);
                return NULL;
            }
        } else {
            dot_count = 0;
        }
        
        // Only allow safe characters
        if (isalnum((unsigned char)url[i]) || 
            url[i] == '/' || 
            url[i] == '.' || 
            url[i] == '-' || 
            url[i] == '_') {
            sanitized[j++] = url[i];
        }
    }
    
    // Ensure proper termination
    sanitized[j] = '\0';
    
    // Additional security checks
    if (strstr(sanitized, "//") || // No double slashes
        strstr(sanitized, "./") || // No current directory
        strstr(sanitized, "..") || // No parent directory
        strstr(sanitized, "/.") || // No hidden files
        strlen(sanitized) < 1) {   // Must have content
        free(sanitized);
        return NULL;
    }
    
    return sanitized;
}

int check_rate_limit(const char *ip) {
    pthread_mutex_lock(&rate_limit_mutex);
    
    time_t now = time(NULL);
    int i;
    
    // Clean up expired entries
    for (i = 0; i < rate_limit_count; i++) {
        if (now - rate_limits[i].window_start >= RATE_LIMIT_WINDOW) {
            if (i < rate_limit_count - 1) {
                memcpy(&rate_limits[i], &rate_limits[rate_limit_count-1], sizeof(RateLimit));
            }
            rate_limit_count--;
            i--;
        }
    }
    
    // Find or create entry for this IP
    for (i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            if (now - rate_limits[i].window_start >= RATE_LIMIT_WINDOW) {
                rate_limits[i].window_start = now;
                rate_limits[i].request_count = 1;
            } else if (rate_limits[i].request_count >= MAX_REQUESTS) {
                pthread_mutex_unlock(&rate_limit_mutex);
                return 0;  // Rate limit exceeded
            } else {
                rate_limits[i].request_count++;
            }
            pthread_mutex_unlock(&rate_limit_mutex);
            return 1;  // Request allowed
        }
    }
    
    // Add new entry
    rate_limits = realloc(rate_limits, (rate_limit_count + 1) * sizeof(RateLimit));
    strncpy(rate_limits[rate_limit_count].ip, ip, INET_ADDRSTRLEN);
    rate_limits[rate_limit_count].window_start = now;
    rate_limits[rate_limit_count].request_count = 1;
    rate_limit_count++;
    
    pthread_mutex_unlock(&rate_limit_mutex);
    return 1;  // Request allowed
}

void initialize_thread_pool() {
    thread_pool = calloc(MAX_THREAD_POOL_SIZE, sizeof(ThreadInfo));
    if (!thread_pool) {
        perror("Failed to allocate thread pool");
        exit(EXIT_FAILURE);
    }
}

void cleanup_thread_pool() {
    for (int i = 0; i < thread_pool_size; i++) {
        if (thread_pool[i].busy) {
            pthread_cancel(thread_pool[i].thread);
            pthread_join(thread_pool[i].thread, NULL);
        }
    }
    free(thread_pool);
}

void cache_file(const char *path, const char *data, size_t size, const char *mime_type) {
    pthread_mutex_lock(&cache_mutex);
    
    if (cache_size >= MAX_CACHE_SIZE) {
        // Remove least recently used entry
        int lru_index = 0;
        time_t oldest = file_cache[0].last_access;
        
        for (int i = 1; i < cache_size; i++) {
            if (file_cache[i].last_access < oldest) {
                oldest = file_cache[i].last_access;
                lru_index = i;
            }
        }
        
        free(file_cache[lru_index].path);
        free(file_cache[lru_index].data);
        free(file_cache[lru_index].mime_type);
        
        // Move last entry to this position
        if (lru_index < cache_size - 1) {
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
