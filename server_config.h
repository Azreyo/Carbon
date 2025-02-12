#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdbool.h>

typedef struct {
    int port;
    bool use_https;
    char log_file[256];
    int max_threads;
    bool running;
    bool automatic_startup;
    char server_name[256];   
    int verbose;  
} ServerConfig;

int load_config(const char *filename, ServerConfig *config);
void init_config(ServerConfig *config);
void log_event(const char *message);


#endif
