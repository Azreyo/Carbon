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
#include "server_config.h"

#define MAX_REQUEST_SIZE 8192
#define MAX_LOG_SIZE 2048
#define MAX_CLIENT_THREADS 100

// Global variables
ServerConfig config;
char server_log[MAX_LOG_SIZE];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t client_threads[MAX_CLIENT_THREADS];
int num_client_threads = 0;

// Function declarations
void *handle_client(void *arg);
void log_event(const char *message);
void display_menu();
void handle_menu_option(int option);

void shutdown_server() {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    config.running = 0;
    close(server_socket);  
    for (int i = 0; i < num_client_threads; i++) {
        pthread_cancel(client_threads[i]);  
    }
}


int main() { 
    ServerConfig config;

    if (load_config("server.json", &config) != 0) {
        printf("Using default configuration.\n");
    }

    config.running = 1;

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating socket");
        exit(1);
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(config.port);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Error binding socket");
        exit(1);
    }

    if (listen(server_socket, 5) < 0) {
        perror("Error listening for connections");
        exit(1);
    }

    log_event("Server started.");




    while (config.running) {
        int client_socket;
        struct sockaddr_in client_address;
        socklen_t client_address_len = sizeof(client_address);
        pthread_mutex_t client_count_mutex = PTHREAD_MUTEX_INITIALIZER;

        client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_address_len);
        if (client_socket < 0) {
            perror("Error accepting connection");
            continue;
        }
        log_event("Client connected.");
        setbuf(stdin, NULL);
        pthread_t client_thread;
        int *client_socket_ptr = malloc(sizeof(int));
        *client_socket_ptr = client_socket;

        if (pthread_create(&client_thread, NULL, handle_client, (void *)client_socket_ptr) != 0) {
            perror("Error creating thread");
            close(client_socket);
            free(client_socket_ptr);
            continue;
        }
        
        pthread_mutex_lock(&client_count_mutex);
        if (num_client_threads < MAX_CLIENT_THREADS) {
         client_threads[num_client_threads++] = client_thread;
        } else {
            fprintf(stderr, "Maximum number of client threads reached.\n");
             close(client_socket);
             free(client_socket_ptr);
        }
         pthread_mutex_unlock(&client_count_mutex);
    }

    for(int i = 0; i < num_client_threads; i++) {
        pthread_join(client_threads[i], NULL);
    }

    close(server_socket);
    pthread_mutex_destroy(&log_mutex); 
    log_event("Server stopped.");
    return 0;
}



void cleanup_handler(void *arg) {
    int client_socket = *((int *)arg);
    close(client_socket);
    printf("handle_client: Client socket closed.\n"); // debug
}

void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);

    printf("handle_client: Client connected. client_socket = %d\n", client_socket); // debug

    char request_buffer[MAX_REQUEST_SIZE];
    ssize_t bytes_received = recv(client_socket, request_buffer, MAX_REQUEST_SIZE - 1, 0);

    printf("handle_client: bytes_received = %ld\n", bytes_received); // debug

    // Push cleanup handler with the correct argument
    pthread_cleanup_push(cleanup_handler, (void *)&client_socket); // Pass the address of client_socket

    if (bytes_received < 0) {
        perror("handle_client: Error receiving data");
        log_event("Error receiving data"); // Log the error
    } else if (bytes_received == 0) {
        log_event("Client disconnected.");
    } else {
        request_buffer[bytes_received] = '\0';
        log_event("Received request:");
        log_event(request_buffer);

        char filepath[256];
        strcpy(filepath, "www/");
        strcat(filepath, "index.html"); // Default file

        int fd = open(filepath, O_RDONLY);
        printf("handle_client: File descriptor (fd) = %d\n", fd);

        if (fd == -1) {
            const char *not_found_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
            send(client_socket, not_found_response, strlen(not_found_response), 0);
        } else {
            struct stat st;
            fstat(fd, &st);
            off_t file_size = st.st_size;

            printf("handle_client: File size = %ld\n", file_size); // debug

            char headers[512];
            snprintf(headers, sizeof(headers), "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", file_size);
            send(client_socket, headers, strlen(headers), 0);

            char buffer[1024];
            ssize_t bytes_read;
            while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
                printf("handle_client: bytes_read = %ld\n", bytes_read); // debug
                send(client_socket, buffer, bytes_read, 0);
            }

            close(fd);
        }
    }

    pthread_cleanup_pop(1); // Pop and execute cleanup handler
    pthread_exit(NULL);
}

void log_event(const char *message) {
    pthread_mutex_lock(&log_mutex);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char timestamp[64];

    // Format timestamp
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    // Append new log entry safely
    size_t remaining_size = MAX_LOG_SIZE - strlen(server_log) - 2;
    if (remaining_size > 0) {
        snprintf(server_log + strlen(server_log), remaining_size, "%s: %s\n", timestamp, message);
    }

    pthread_mutex_unlock(&log_mutex);
}

void print_log() {
    pthread_mutex_lock(&log_mutex);
    printf("Server Log:\n%s", server_log);
    pthread_mutex_unlock(&log_mutex);
}



void display_menu() {
    printf("\nServer Menu:\n");
    printf("1. Status\n");
    printf("2. Logging\n");
    printf("3. Config\n");
    printf("4. Switch HTTP/HTTPS\n");
    printf("5. Troubleshooting\n");
    printf("6. Exit\n");
    printf("Enter your choice: ");

    char input[10];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        int choice = atoi(input);
        handle_menu_option(choice);
    }
}


void handle_menu_option(int option) {
    switch (option) {
        case 1:
            printf("Server Status:\n");
            printf("Running: %s\n", config.running ? "Yes" : "No");
            printf("Port: %d\n", config.port);
            break;
        case 2:
            pthread_mutex_lock(&log_mutex);
            printf("Server Log:\n%s\n", server_log);
            pthread_mutex_unlock(&log_mutex);
            break;
        case 3:
            printf("Config Options:\n");
            break;
        case 4:
            printf("Switching HTTP/HTTPS:\n");
            break;
        case 5:
            printf("Troubleshooting:\n");
            break;
        case 6:
            printf("Exiting...\n");
            shutdown_server();
            break;
        default:
            printf("Invalid option.\n");
    }
}
