#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdbool.h>

typedef struct {
    int port;
    bool use_https;
    char log_file[256];
    int max_threads;
    bool running;
} ServerConfig;

int load_config(const char *filename, ServerConfig *config);
void init_config(ServerConfig *config);

#endif