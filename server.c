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
#include <stdio_ext.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "server_config.h"

#define MAX_REQUEST_SIZE 8192
#define MAX_LOG_SIZE 2048
#define MAX_CLIENT_THREADS 100

#define BOLD    "\x1b[1m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define RESET   "\x1b[0m"

ServerConfig config;
char server_log[MAX_LOG_SIZE];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t client_threads[MAX_CLIENT_THREADS];
int num_client_threads = 0;
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
SSL_CTX *ssl_ctx = NULL;

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

void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
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
    int http_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket < 0) {
        perror(BOLD RED "Error: "RESET"creating HTTP socket");
        pthread_exit(NULL);
    }

    struct sockaddr_in http_address;
    memset(&http_address, 0, sizeof(http_address));
    http_address.sin_family = AF_INET;
	AF_INET;
    http_address.sin_addr.s_addr = INADDR_ANY;
    http_address.sin_port = htons(config.port);

    if (bind(http_socket, (struct sockaddr *)&http_address, sizeof(http_address)) < 0) {
        perror(BOLD RED "Error: "RESET" binding HTTP socket");
        close(http_socket);
        pthread_exit(NULL);
    }

    if (listen(http_socket, 50) < 0) {
        perror(BOLD RED"Error: "RESET"listening on HTTP socket");
        close(http_socket);
        pthread_exit(NULL);
    }

    log_event( "HTTP server started.");

    while (config.running) {
        int client_socket = accept(http_socket, NULL, NULL);
        if (client_socket < 0) {
            perror(BOLD RED"Error: "RESET"accepting HTTP connection");
            continue;
        }

        pthread_mutex_lock(&thread_count_mutex);
        if (num_client_threads < MAX_CLIENT_THREADS) {
            pthread_t client_thread;
            int *client_socket_ptr = malloc(sizeof(int));
            *client_socket_ptr = client_socket;

            if (pthread_create(&client_thread, NULL, handle_http_client, client_socket_ptr) == 0) {
                client_threads[num_client_threads++] = client_thread;
            } else {
                perror(BOLD RED "Error: " RESET "creating HTTP client thread");
                close(client_socket);
                free(client_socket_ptr);
            }
        } else {
            log_event("Max client threads reached, rejecting connection.");
            close(client_socket);
        }
        pthread_mutex_unlock(&thread_count_mutex);
    }

    close(http_socket);
    pthread_exit(NULL);
}

void *start_https_server(void *arg) {
    int https_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (https_socket < 0) {
        perror(BOLD RED"Error: "RESET"creating HTTPS socket");
        pthread_exit(NULL);
    }

    struct sockaddr_in https_address;
    memset(&https_address, 0, sizeof(https_address));
    https_address.sin_family = AF_INET;
    https_address.sin_addr.s_addr = INADDR_ANY;
    https_address.sin_port = htons(443);

    if (bind(https_socket, (struct sockaddr *)&https_address, sizeof(https_address)) < 0) {
        perror(BOLD RED"Error: "RESET"binding HTTPS socket");
        close(https_socket);
        pthread_exit(NULL);
    }

    if (listen(https_socket, 50) < 0) {
        perror(BOLD RED"Error: "RESET"listening on HTTPS socket");
        close(https_socket);
        pthread_exit(NULL);
    }

    log_event("HTTPS server started.");

    while (config.running) {
        int client_socket = accept(https_socket, NULL, NULL);
        if (client_socket < 0) {
            perror("Error accepting HTTPS connection");
            continue;
        }

        pthread_mutex_lock(&thread_count_mutex);
        if (num_client_threads < MAX_CLIENT_THREADS) {
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

    char buffer[MAX_REQUEST_SIZE];
    ssize_t bytes_received = recv(client_socket, buffer, MAX_REQUEST_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        log_event("Received HTTP request");
        send(client_socket, "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, HTTP!", 48, 0);
    }

    close(client_socket);
    pthread_exit(NULL);
}

void *handle_https_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);

    if (SSL_accept(ssl) > 0) {
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "www/%s", "index.html");

        int fd = open(filepath, O_RDONLY);

		if (strstr(filepath, "..")) {
			const char *forbiden_access = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
			SSL_write(ssl, forbiden_access, strlen(forbiden_access));
			log_event("Potential directory traversal attempt detected.");
		}

        if (fd == -1) {
            const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
            SSL_write(ssl, not_found_response, strlen(not_found_response));
            log_event("File not found, sent 404.");
        } else {
            struct stat st;
            fstat(fd, &st);
            off_t file_size = st.st_size;

            char response_header[256];
            snprintf(response_header, sizeof(response_header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Type: text/html\r\n"
                     "\r\n",
                     file_size);


            ssize_t total_sent = 0, bytes_sent;
            size_t header_len = strlen(response_header);

            while (total_sent < header_len) {
                bytes_sent = SSL_write(ssl, response_header + total_sent, header_len - total_sent);
                if (bytes_sent <= 0) {
                    log_event("Failed to send HTTPS header.");
                    goto cleanup; 
                }
                total_sent += bytes_sent;
            }


            char buffer[1024];
            ssize_t bytes_read;
            total_sent = 0; 

            while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
                size_t body_len = bytes_read; 
                while (total_sent < body_len) {
                bytes_sent = SSL_write(ssl, buffer + total_sent, body_len - total_sent);

                    if (bytes_sent <= 0) {
                        log_event("Failed to send HTTPS body.");
                        goto cleanup; 
                    }
                    total_sent += bytes_sent;
                }
                
            }
            if (bytes_read < 0) {
                log_event("Error reading from file.");
                goto cleanup;
            }


            log_event("Sent HTTPS response successfully.");
            close(fd);
        }
    } else {
        log_event("SSL handshake failed.");
    }

cleanup: 
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    pthread_exit(NULL);
}

void shutdown_server() {
    config.running = 0;

    int dummy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dummy_socket >= 0) {
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        server_addr.sin_port = htons(config.port);

        if (connect(dummy_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Failed to connect to the server");
        }
        close(dummy_socket);
    } else {
        perror("Failed to create dummy socket");
    }

    pthread_mutex_lock(&thread_count_mutex);
    for (int i = 0; i < num_client_threads; i++) {
        if (client_threads[i] != 0) {
            pthread_cancel(client_threads[i]);
            pthread_join(client_threads[i], NULL); 
        }
    }
    num_client_threads = 0; 
    pthread_mutex_unlock(&thread_count_mutex);

    cleanup_openssl();
    log_event("Server shutdown completed.");
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

    pthread_t http_thread, https_thread;
    pthread_create(&http_thread, NULL, start_http_server, NULL);
    if (config.use_https) {
        pthread_create(&https_thread, NULL, start_https_server, NULL);
    }

    pthread_join(http_thread, NULL);
    if (config.use_https) {
        pthread_join(https_thread, NULL);
    }

    shutdown_server();

    return 0;
}

void log_event(const char *message) {
    pthread_mutex_lock(&log_mutex);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char timestamp[64];

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    size_t remaining_size = MAX_LOG_SIZE - strlen(server_log) - 2;
    if (remaining_size > 0) {
        snprintf(server_log + strlen(server_log), remaining_size, "%s: %s\n", timestamp, message);
    }

    FILE *logfile = fopen(config.log_file, "a");
    if (logfile) {
        fprintf(logfile, "%s: %s\n", timestamp, message);
        fclose(logfile);
    } else {
        perror("Error opening log file");
    }

    pthread_mutex_unlock(&log_mutex);
}

