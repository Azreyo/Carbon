#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdbool.h>

// Log modes
typedef enum {
    LOG_MODE_OFF = 0,
    LOG_MODE_CLASSIC = 1,
    LOG_MODE_DEBUG = 2,
    LOG_MODE_ADVANCED = 3
} LogMode;

typedef struct
{
    int port;
    bool use_https;
    char log_file[256];
    int max_threads;
    bool running;
    bool automatic_startup;
    char server_name[256];
    LogMode log_mode;           // Replaces verbose - supports off/classic/debug/advanced
    bool enable_http2;
    bool enable_websocket;
    char www_path[256];
    int max_connections;
    char ssl_cert_path[256];
    char ssl_key_path[256];
} ServerConfig;

int load_config(const char *filename, ServerConfig *config);
void init_config(ServerConfig *config);
void log_event(const char *message);

#endif
