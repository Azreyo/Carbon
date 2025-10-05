#include <stdio.h>
#include <string.h>
#include "server_config.h"

void init_config(ServerConfig *config)
{
    config->port = 8080;
    config->use_https = false;
    strcpy(config->log_file, "server.log");
    config->max_threads = 4;
    config->running = true;
    config->automatic_startup = false;
    config->verbose = 0;
    strcpy(config->server_name, "127.0.0.1");
    config->enable_http2 = false;
    config->enable_websocket = false;
    strcpy(config->www_path, "www");
    config->max_connections = 1024;
    strcpy(config->ssl_cert_path, "ssl/cert/");
    strcpy(config->ssl_key_path, "ssl");
}
