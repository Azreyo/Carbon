#include <stdio.h>
#include <string.h>
#include "server_config.h"

void init_config(ServerConfig *config) {
    config->port = 8080;
    config->use_https = false;
    strcpy(config->log_file, "server.log");
    config->max_threads = 4;
    config->running = true;
	config->automatic_startup = false;
}
