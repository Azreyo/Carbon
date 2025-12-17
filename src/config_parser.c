#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <ctype.h>
#include "server_config.h"

typedef enum
{
    CONFIG_PORT,
    CONFIG_USE_HTTPS,
    CONFIG_LOG_FILE,
    CONFIG_MAX_THREADS,
    CONFIG_RUNNING,
    CONFIG_SERVER_NAME,
    CONFIG_LOG_MODE,
    CONFIG_VERBOSE, // Keep for backwards compatibility
    CONFIG_ENABLE_HTTP2,
    CONFIG_ENABLE_WEBSOCKET,
    CONFIG_WWW_PATH,
    CONFIG_MAX_CONNECTIONS,
    CONFIG_SSL_CERT_PATH,
    CONFIG_SSL_KEY_PATH,
    CONFIG_UNKNOWN
} ConfigKey;

// Trim whitespace from both ends of a string
static char* trim_whitespace(char* str)
{
    // Trim leading space
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)
        return str;

    // Trim trailing space
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    end[1] = '\0';
    return str;
}

// Parse a boolean value (true/false, yes/no, on/off, 1/0)
static bool parse_bool(const char* value)
{
    if (strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "on") == 0 ||
        strcmp(value, "1") == 0)
    {
        return true;
    }
    return false;
}

// Parse log mode value (off/classic/debug/advanced)
static LogMode parse_log_mode(const char* value)
{
    if (strcasecmp(value, "off") == 0 || strcmp(value, "0") == 0)
        return LOG_MODE_OFF;
    if (strcasecmp(value, "classic") == 0 || strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 || strcmp(value, "1") == 0)
        return LOG_MODE_CLASSIC;
    if (strcasecmp(value, "debug") == 0)
        return LOG_MODE_DEBUG;
    if (strcasecmp(value, "advanced") == 0)
        return LOG_MODE_ADVANCED;
    return LOG_MODE_CLASSIC; // Default
}

// Map string to enum
static ConfigKey get_config_key(const char* key)
{
    static const struct
    {
        const char* name;
        ConfigKey key;
    } key_map[] = {
        {"port", CONFIG_PORT},
        {"use_https", CONFIG_USE_HTTPS},
        {"log_file", CONFIG_LOG_FILE},
        {"max_threads", CONFIG_MAX_THREADS},
        {"running", CONFIG_RUNNING},
        {"server_name", CONFIG_SERVER_NAME},
        {"log_mode", CONFIG_LOG_MODE},
        {"verbose", CONFIG_VERBOSE}, // Keep for backwards compatibility
        {"enable_http2", CONFIG_ENABLE_HTTP2},
        {"enable_websocket", CONFIG_ENABLE_WEBSOCKET},
        {"www_path", CONFIG_WWW_PATH},
        {"max_connections", CONFIG_MAX_CONNECTIONS},
        {"ssl_cert_path", CONFIG_SSL_CERT_PATH},
        {"ssl_key_path", CONFIG_SSL_KEY_PATH},
        {NULL, CONFIG_UNKNOWN}

    };
    for (int i = 0; key_map[i].name != NULL; i++)
    {
        if (strcasecmp(key, key_map[i].name) == 0)
        {
            return key_map[i].key;
        }
    }
    return CONFIG_UNKNOWN;
}

int load_config(const char* filename, ServerConfig* config)
{
    if (!filename || strlen(filename) > 4096)
    {
        fprintf(stderr, "Invalid config filename\n");
        return 1;
    }

    FILE* fp = fopen(filename, "r");
    if (!fp)
    {
        perror("Error opening config file");
        return 1;
    }

    char line[512];
    int line_number = 0;

    while (fgets(line, sizeof(line), fp))
    {
        line_number++;

        // Remove newline
        line[strcspn(line, "\r\n")] = 0;

        // Trim whitespace
        char* trimmed = trim_whitespace(line);

        // Skip empty lines and comments
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';')
        {
            continue;
        }

        // Find the delimiter (= or space)
        char* delim = strchr(trimmed, '=');
        if (!delim)
        {
            // Try space as delimiter
            delim = strchr(trimmed, ' ');
        }

        if (!delim)
        {
            fprintf(stderr, "Warning: Invalid config line %d: %s\n", line_number, trimmed);
            continue;
        }

        // Split into key and value
        *delim = '\0';
        char* key = trim_whitespace(trimmed);
        char* value = trim_whitespace(delim + 1);

        // Remove quotes from value if present
        if ((value[0] == '"' || value[0] == '\'') &&
            value[strlen(value) - 1] == value[0])
        {
            value[strlen(value) - 1] = '\0';
            value++;
        }
        // Parse configuration options
        switch (get_config_key(key))
        {
        case CONFIG_PORT:
            config->port = strcoll(value, value);
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
            config->max_threads = strcoll(value, value);
            printf("load_config: max_threads = %d\n", config->max_threads);
            break;

        case CONFIG_RUNNING:
            config->running = parse_bool(value);
            if (!config->running)
            {
                fprintf(stderr, "ERROR: current run state is false cannot run the server!\n");
                exit(EXIT_FAILURE);
            }
            printf("load_config: running = %d\n", config->running);
            break;

        case CONFIG_SERVER_NAME:
            strncpy(config->server_name, value, sizeof(config->server_name) - 1);
            config->server_name[sizeof(config->server_name) - 1] = '\0';
            printf("load_config: server_name = %s\n", config->server_name);
            if (strcmp(config->server_name, "Your_domain/IP") == 0)
            {
                fprintf(stderr, "WARNING: server_name is set to default\n"
                        "Please set server_name in server.conf to the server's IP address or domain name for proper operation.\n");
            }
            break;
        case CONFIG_LOG_MODE:
            config->log_mode = parse_log_mode(value);
            printf("load_config: log_mode = %s\n",
                   config->log_mode == LOG_MODE_OFF
                       ? "off"
                       : config->log_mode == LOG_MODE_DEBUG
                       ? "debug"
                       : config->log_mode == LOG_MODE_ADVANCED
                       ? "advanced"
                       : "classic");
            break;
        case CONFIG_VERBOSE:
            // Backwards compatibility: map verbose boolean to log_mode
            if (parse_bool(value))
            {
                config->log_mode = LOG_MODE_CLASSIC;
            }
            else
            {
                config->log_mode = LOG_MODE_OFF;
            }
            printf("load_config: verbose (legacy) -> log_mode = %s\n",
                   config->log_mode == LOG_MODE_OFF ? "off" : "classic");
            break;

        case CONFIG_ENABLE_HTTP2:
            config->enable_http2 = parse_bool(value);
            if (!config->use_https && config->enable_http2)
            {
                printf("Error: Cannot load HTTP/2 while HTTPS is not enabled!\n");
                exit(EXIT_FAILURE);
            }
            else
            {
                printf("load_config: enable_http2 = %d\n", config->enable_http2);
            }

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

        case CONFIG_MAX_CONNECTIONS:
            config->max_connections = strcoll(value, value);
            printf("load_config: max_connections: = %d\n", config->max_connections);

            break;

        case CONFIG_SSL_CERT_PATH:
            if (config->use_https)
            {
                strncpy(config->ssl_cert_path, value, sizeof(config->ssl_cert_path) - 1);
                config->ssl_cert_path[sizeof(config->ssl_cert_path) - 1] = '\0';
                printf("load_config: ssl_cert_path = %s\n", config->ssl_cert_path);
            }
            break;
        case CONFIG_SSL_KEY_PATH:
            if (config->use_https)
            {
                strncpy(config->ssl_key_path, value, sizeof(config->ssl_key_path) - 1);
                config->ssl_key_path[sizeof(config->ssl_key_path) - 1] = '\0';
                printf("load_config: ssl_key_path = %s\n", config->ssl_key_path);
            }
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