#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "server_config.h"

typedef enum {
    CONFIG_PORT,
    CONFIG_USE_HTTPS,
    CONFIG_LOG_FILE,
    CONFIG_MAX_THREADS,
    CONFIG_RUNNING,
    CONFIG_SERVER_NAME,
    CONFIG_VERBOSE,
    CONFIG_ENABLE_HTTP2,
    CONFIG_ENABLE_WEBSOCKET,
    CONFIG_WWW_PATH,
    CONFIG_UNKNOWN

} ConfigKey;

// Trim whitespace from both ends of a string
static char* trim_whitespace(char *str) {
    char *end;
    
    // Trim leading space
    while(isspace((unsigned char)*str)) str++;
    
    if(*str == 0) return str;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    end[1] = '\0';
    return str;
}

// Parse a boolean value (true/false, yes/no, on/off, 1/0)
static bool parse_bool(const char *value) {
    if (strcasecmp(value, "true") == 0 || 
        strcasecmp(value, "yes") == 0 || 
        strcasecmp(value, "on") == 0 ||
        strcmp(value, "1") == 0) {
        return true;
    }
    return false;
}
// Map string to enum
static ConfigKey get_config_key(const char *key) {
    static const struct 
    {
        const char *name;
        ConfigKey key;
    } key_map[] = {
        {"port", CONFIG_PORT},
        {"use_https", CONFIG_USE_HTTPS},
        {"log_file", CONFIG_LOG_FILE},
        {"max_threads", CONFIG_MAX_THREADS},
        {"running", CONFIG_RUNNING},
        {"server_name", CONFIG_SERVER_NAME},
        {"verbose", CONFIG_VERBOSE},
        {"enable_http2", CONFIG_ENABLE_HTTP2},
        {"enable_websocket",CONFIG_ENABLE_WEBSOCKET},
        {"www_path", CONFIG_WWW_PATH},
        {NULL, CONFIG_UNKNOWN}
        
    };
    for (int i = 0;key_map[i].name != NULL; i++) {
        if (strcasecmp(key, key_map[i].name) == 0) {
            return key_map[i].key;
        }
    }
    return CONFIG_UNKNOWN;
}

int load_config(const char *filename, ServerConfig *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening config file");
        return 1;
    }

    char line[512];
    int line_number = 0;

    while (fgets(line, sizeof(line), fp)) {
            line_number++;
            
            // Remove newline
            line[strcspn(line, "\r\n")] = 0;
            
            // Trim whitespace
            char *trimmed = trim_whitespace(line);
            
            // Skip empty lines and comments
            if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
                continue;
            }
            
            // Find the delimiter (= or space)
            char *delim = strchr(trimmed, '=');
            if (!delim) {
                // Try space as delimiter
                delim = strchr(trimmed, ' ');
            }
            
            if (!delim) {
                fprintf(stderr, "Warning: Invalid config line %d: %s\n", line_number, trimmed);
                continue;
            }
            
            // Split into key and value
            *delim = '\0';
            char *key = trim_whitespace(trimmed);
            char *value = trim_whitespace(delim + 1);
            
            // Remove quotes from value if present
            if ((value[0] == '"' || value[0] == '\'') && 
                value[strlen(value) - 1] == value[0]) {
                value[strlen(value) - 1] = '\0';
                value++;
            }
            // Parse configuration options
            switch (get_config_key(key)) {
            case CONFIG_PORT:
                config->port = atoi(value);
                printf("load_config: port = %d\n", config->port);
            break;

            case CONFIG_USE_HTTPS:
                config->use_https = parse_bool(value);
                printf("load_config: use_https = %d\n", config->use_https);
            break;

            case CONFIG_LOG_FILE:
            strncpy(config->log_file, value, sizeof(config->log_file) - 1);
                config->log_file[sizeof(config->log_file) - 1] = '\0';
                printf("load_config: log_file = %s\n", config->log_file);
            break;

            case CONFIG_MAX_THREADS:
                config->max_threads = atoi(value);
                printf("load_config: max_threads = %d\n", config->max_threads);
            break;

            case CONFIG_RUNNING:
                config->running = parse_bool(value);
                printf("load_config: running = %d\n", config->running);
            break;

            case CONFIG_SERVER_NAME:
                strncpy(config->server_name, value, sizeof(config->server_name) - 1);
                    config->server_name[sizeof(config->server_name) - 1] = '\0';
                    printf("load_config: server_name = %s\n", config->server_name);
                    if (strcmp(config->server_name, "Your_domain/IP") == 0) {
                        fprintf(stderr, "WARNING: server_name is set to default\n"
                            "Please set server_name in server.conf to the server's IP address or domain name for proper operation.\n");
                    }
            break;

            case CONFIG_VERBOSE:
                config->verbose = parse_bool(value);
                printf("load_config: verbose = %d\n", config->verbose);
            break;

            case CONFIG_ENABLE_HTTP2:
                config->enable_http2 = parse_bool(value);
                printf("load_config: enable_http2 = %d\n", config->enable_http2);
            break;

            case CONFIG_ENABLE_WEBSOCKET:
                config->enable_websocket = parse_bool(value);
                printf("load_config: enable_websocket = %d\n", config->enable_websocket);
            break;

            case CONFIG_WWW_PATH:
                strncpy(config->www_path, value, sizeof(config->www_path) - 1);
                config->www_path[sizeof(config->www_path) - 1] = '\0';
                printf("load_config: www_path = %s\n", config->www_path);
            break;

            case CONFIG_UNKNOWN:
            default:
                fprintf(stderr, "Warning: Unknown config option '%s' on line %d\n", key, line_number);
            break;
        }
    }
    fclose(fp);
    return 0;
}