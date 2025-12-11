#include <stdio.h>
#include <string.h>
#include "server_config.h"

void init_config(ServerConfig *config)
{
    config->port = 8080;
    config->use_https = false;
    strcpy(config->log_file, "log/server.log");
    config->max_threads = 4;
    config->running = true;
    config->automatic_startup = false;
    config->log_mode = LOG_MODE_CLASSIC;  // Default to classic logging
    strcpy(config->server_name, "127.0.0.1");
    config->enable_http2 = false;
    config->enable_websocket = false;
    strcpy(config->www_path, "www");
    config->max_connections = 1024;
    strcpy(config->ssl_cert_path, "ssl/cert/cert.pem");
    strcpy(config->ssl_key_path, "ssl/key/key.key");
}
