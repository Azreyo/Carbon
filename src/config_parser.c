#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "server_config.h"

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
        if (strcasecmp(key, "port") == 0) {
            config->port = atoi(value);
            printf("load_config: port = %d\n", config->port);
        } 
        else if (strcasecmp(key, "use_https") == 0) {
            config->use_https = parse_bool(value);
            printf("load_config: use_https = %d\n", config->use_https);
        }
        else if (strcasecmp(key, "log_file") == 0) {
            strncpy(config->log_file, value, sizeof(config->log_file) - 1);
            config->log_file[sizeof(config->log_file) - 1] = '\0';
            printf("load_config: log_file = %s\n", config->log_file);
        }
        else if (strcasecmp(key, "max_threads") == 0) {
            config->max_threads = atoi(value);
            printf("load_config: max_threads = %d\n", config->max_threads);
        }
        else if (strcasecmp(key, "running") == 0) {
            config->running = parse_bool(value);
            printf("load_config: running = %d\n", config->running);
        }
        else if (strcasecmp(key, "server_name") == 0) {
            strncpy(config->server_name, value, sizeof(config->server_name) - 1);
            config->server_name[sizeof(config->server_name) - 1] = '\0';
            printf("load_config: server_name = %s\n", config->server_name);
            if (strcmp(config->server_name, "Your_domain/IP") == 0) {
                fprintf(stderr, "WARNING: server_name is set to default\nPlease set server_name in server.conf to the server's IP address or domain name for proper operation.\n");
            }
        }
        else if (strcasecmp(key, "verbose") == 0) {
            config->verbose = parse_bool(value);
            printf("load_config: verbose = %d\n", config->verbose);
        }
        else if (strcasecmp(key, "enable_http2") == 0) {
            config->enable_http2 = parse_bool(value);
            printf("load_config: enable_http2 = %d\n", config->enable_http2);
        }
        else if (strcasecmp(key, "enable_websocket") == 0) {
            config->enable_websocket = parse_bool(value);
            printf("load_config: enable_websocket = %d\n", config->enable_websocket);
        }
        else {
            fprintf(stderr, "Warning: Unknown config option '%s' on line %d\n", key, line_number);
        }
    }

    fclose(fp);
    return 0;
}
