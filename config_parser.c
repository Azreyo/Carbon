#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "server_config.h"
#include <cJSON.h>

int load_config(const char *filename, ServerConfig *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening config file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Error allocating memory for config file");
        fclose(fp);
        return 1;
    }

    size_t items_read = fread(buffer, file_size, 1, fp);
    fclose(fp);  // Close file immediately after reading
    
    if (items_read != 1) {
        perror("Error reading config file");
        free(buffer);
        return 1;
    }

    buffer[file_size] = '\0';

    cJSON *root = cJSON_Parse(buffer);
    free(buffer);  // Free buffer after parsing

    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return 1;
    }

    cJSON *port = cJSON_GetObjectItemCaseSensitive(root, "port");
    if (cJSON_IsNumber(port)) {
        config->port = port->valueint;
        printf("load_config: port = %d\n", config->port);
    } else {
        fprintf(stderr, "load_config: port not found or not a number. Using default.\n");
        config->port = 80; 
    }

    cJSON *use_https = cJSON_GetObjectItemCaseSensitive(root, "use_https");
    if (cJSON_IsBool(use_https)) {
        config->use_https = cJSON_IsTrue(use_https);
        printf("load_config: use_https = %d\n", config->use_https);
    } else {
        fprintf(stderr, "load_config: use_https not found or not a boolean. Using default.\n");
        config->use_https = false; 
    }

    cJSON *log_file = cJSON_GetObjectItemCaseSensitive(root, "log_file");
    if (cJSON_IsString(log_file) && (log_file->valuestring != NULL)) {
        strncpy(config->log_file, log_file->valuestring, sizeof(config->log_file) - 1);
        config->log_file[sizeof(config->log_file) - 1] = '\0'; 
        printf("load_config: log_file = %s\n", config->log_file); 
    } else {
        fprintf(stderr, "load_config: log_file not found or not a string. Using default.\n");
        strcpy(config->log_file, "server.log"); 
    }

    cJSON *max_threads = cJSON_GetObjectItemCaseSensitive(root, "max_threads");
    if (cJSON_IsNumber(max_threads)) {
        config->max_threads = max_threads->valueint;
        printf("load_config: max_threads = %d\n", config->max_threads); 
    } else {
        fprintf(stderr, "load_config: max_threads not found or not a number. Using default.\n");
        config->max_threads = 4; 
    }

    cJSON *running = cJSON_GetObjectItemCaseSensitive(root, "running");
    if (cJSON_IsBool(running)) {
        config->running = cJSON_IsTrue(running);
        printf("load_config: running = %d\n", config->running); 
    } else {
        fprintf(stderr, "load_config: running not found or not a boolean. Using default.\n");
        config->running = true; 
	}

    cJSON *server_name = cJSON_GetObjectItemCaseSensitive(root, "server_name");
    if (cJSON_IsString(server_name) && (server_name->valuestring != NULL)) {
        strncpy(config->server_name, server_name->valuestring, sizeof(config->server_name) - 1);
        config->server_name[sizeof(config->server_name) - 1] = '\0';
        printf("load_config: server_name = %s\n", config->server_name);
        if (strcmp(config->server_name, "Your_domain/IP") == 0) {
            fprintf(stderr, "WARNING: server_name is set to 127.0.0.1\nPlease set server_name in server.json to the server's IP address or domain name for proper operation.\n");
        }
    } else {
        fprintf(stderr, "load_config: server_name not found or not a string. Using default.\n");
        strcpy(config->server_name, "127.0.0.1");
    }
    cJSON_Delete(root);
    return 0;
}
