#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <sys/mman.h>
#include <openssl/ssl.h>

// Connection pool structures
typedef struct connection_task_t
{
    int socket_fd;
    SSL *ssl;
    bool is_https;
    struct connection_task_t *next;
} connection_task_t;

typedef struct
{
    connection_task_t *head;
    connection_task_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
} task_queue_t;

// Memory-mapped file cache
typedef struct
{
    char *path;
    void *mmap_data;
    size_t size;
    time_t last_access;
    char *mime_type;
    int ref_count;
} mmap_cache_entry_t;

// Response buffer pool
typedef struct buffer_pool_t
{
    char *buffer;
    size_t size;
    bool in_use;
    struct buffer_pool_t *next;
} buffer_pool_t;

// Function declarations
void init_task_queue(task_queue_t *queue);
void enqueue_task(task_queue_t *queue, int socket_fd, SSL *ssl, bool is_https);
connection_task_t *dequeue_task(task_queue_t *queue);
void destroy_task_queue(task_queue_t *queue);

void init_mmap_cache(void);
mmap_cache_entry_t *get_cached_file(const char *path);
void cache_file_mmap(const char *path, size_t size, const char *mime_type);
void release_cached_file(mmap_cache_entry_t *entry);
void cleanup_mmap_cache(void);

void init_buffer_pool(void);
char *get_buffer_from_pool(size_t min_size);
void return_buffer_to_pool(char *buffer);
void cleanup_buffer_pool(void);

// Pre-allocated response headers
extern const char *response_200_header;
extern const char *response_404_header;
extern const char *response_403_header;
extern const char *response_429_header;
extern const char *response_500_header;

#endif
