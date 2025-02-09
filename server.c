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

void *start_http_server(void *arg) {
    http_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket < 0) {
        perror(BOLD RED "Error creating HTTP socket" RESET);
        pthread_exit(NULL);
    }

    int reuse = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror(BOLD RED "Error setting SO_REUSEADDR" RESET);
        close(http_socket);
        pthread_exit(NULL);
    }

    struct sockaddr_in http_address = {0};
    http_address.sin_family = AF_INET;
    http_address.sin_addr.s_addr = INADDR_ANY;
    http_address.sin_port = htons(config.port);

    if (bind(http_socket, (struct sockaddr *)&http_address, sizeof(http_address)) < 0) {
        perror(BOLD RED "Error binding HTTP socket" RESET);
        close(http_socket);
        pthread_exit(NULL);
    }

    if (listen(http_socket, 50) < 0) {
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
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100); // 100ms timeout
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
    https_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (https_socket < 0) {
        perror(BOLD RED "Error creating HTTPS socket" RESET);
        pthread_exit(NULL);
    }

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

    if (listen(https_socket, 50) < 0) {
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
                     "Location: https://%s%s\r\n\r\n", config.server_name, url);
            send(client_socket, redirect_response, strlen(redirect_response), 0);
            log_event("Redirecting to HTTPS"); // Log the redirection
            close(client_socket);
            return NULL;
        }

        if (strstr(url, "..") || strstr(url, "//")) {
            log_event("Blocked potential directory traversal attempt.");
            const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
            send(client_socket, forbidden_response, strlen(forbidden_response), 0);
            close(client_socket);
            return NULL;
        }

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "www%s", (*url == '/' && url[1] == '\0') ? "/index.html" : url);

        int fd = open(filepath, O_RDONLY);
        if (fd == -1) {
            const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
            send(client_socket, not_found_response, strlen(not_found_response), 0);
            log_event("File not found, sent 404.");
        } else {
            struct stat st;
            if (fstat(fd, &st) == -1) {
                log_event("Error getting file size.");
                const char *internal_server_error = "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";
                send(client_socket, internal_server_error, strlen(internal_server_error), 0);
                close(fd);
                goto cleanup;
            }

            off_t file_size = st.st_size;

            char response_header[256];
            snprintf(response_header, sizeof(response_header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Type: text/html\r\n"
                     "\r\n",
                     file_size);

            send(client_socket, response_header, strlen(response_header), 0);

            char file_buffer[1024];
            ssize_t bytes_read;
            while ((bytes_read = read(fd, file_buffer, sizeof(file_buffer))) > 0) {
                if (send(client_socket, file_buffer, bytes_read, 0) < 0) {
                    log_event("Error sending file content.");
                    break;
                }
            }
            close(fd);
            log_event("Served requested file successfully.");
        }
    } else if (bytes_received < 0) {
        perror("Error receiving request");
        log_event("Error receiving request");
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

    if (strstr(url, "..") || strstr(url, "//")) {
        log_event("Blocked potential directory traversal attempt.");
        const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
        SSL_write(ssl, forbidden_response, strlen(forbidden_response));
        goto cleanup;
    }

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "www%s", (*url == '/' && url[1] == '\0') ? "/index.html" : url);
    log_event("Filepath:");
    log_event(filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        perror("open error");
        log_event("File open failed");
        const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
        SSL_write(ssl, not_found_response, strlen(not_found_response));
        goto cleanup;
    } else {
        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat error");
            log_event("Error getting file size.");
            const char *internal_server_error = "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";
            SSL_write(ssl, internal_server_error, strlen(internal_server_error));
            close(fd);
            goto cleanup;
        }

        off_t file_size = st.st_size;

        char response_header[256];
        snprintf(response_header, sizeof(response_header),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Length: %ld\r\n"
                 "Content-Type: text/html\r\n"
                 "\r\n",
                 file_size);

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
    log_event("Shutting down server...");

    config.running = 0;
    server_running = 0;

    if (http_socket != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, http_socket, NULL);
        close(http_socket);
        http_socket = -1;
    }

    if (config.use_https && https_socket != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, https_socket, NULL);
        close(https_socket);
        https_socket = -1;
    }

    close(epoll_fd);

    pthread_mutex_lock(&thread_count_mutex);
    for (int i = 0; i < num_client_threads; i++) {
        if (client_threads[i] != 0) {
            pthread_join(client_threads[i], NULL);
            client_threads[i] = 0;
        }
    }
    num_client_threads = 0;
    pthread_mutex_unlock(&thread_count_mutex);

    cleanup_openssl();

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
        server_running = 0;
        log_event("Signal received, shutting down...");
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
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction (SIGINT)");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction (SIGTERM)");
        exit(EXIT_FAILURE);
    }

	pthread_t http_thread, https_thread;
    pthread_create(&http_thread, NULL, start_http_server, NULL);
    if (config.use_https) {
        pthread_create(&https_thread, NULL, start_https_server, NULL);
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

    char log_dir[512];
    strncpy(log_dir, config.log_file, sizeof(log_dir) - 1);
    log_dir[sizeof(log_dir) - 1] = '\0';
    char *dir_path = dirname(log_dir);

    struct stat st;
    if (stat(dir_path, &st) != 0) {
        if (mkdir(dir_path, 0777) != 0) {
            fprintf(stderr, "Error creating log directory (%s): %s\n", dir_path, strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            return;
        }
    }

    FILE *logfile = fopen(config.log_file, "a");
    if (!logfile) {
        fprintf(stderr, "Error opening log file (%s): %s\n", config.log_file, strerror(errno));
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    if (fprintf(logfile, "%s: %s\n", timestamp, message) < 0) {
        fprintf(stderr, "Error writing to log file: %s\n", strerror(errno));
    }
    fclose(logfile);

    pthread_mutex_unlock(&log_mutex);
}
