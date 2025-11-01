#include "performance.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#define MAX_MMAP_CACHE_SIZE 50
#define MAX_MMAP_FILE_SIZE (10 * 1024 * 1024) // 10MB
#define BUFFER_POOL_SIZE 32
#define DEFAULT_BUFFER_SIZE 16384
 
// Global cache structures
static mmap_cache_entry_t *mmap_cache = NULL;
static int mmap_cache_size = 0;
static pthread_mutex_t mmap_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static buffer_pool_t *buffer_pool = NULL;
static pthread_mutex_t buffer_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
  
// Pre-allocated response headers
const char *response_200_header = "HTTP/1.1 200 OK\r\n";
const char *response_404_header = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
const char *response_403_header = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
const char *response_429_header = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded";
const char *response_500_header = "HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error";

// Task queue implementation
void init_task_queue(task_queue_t *queue)
{
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
}

void enqueue_task(task_queue_t *queue, int socket_fd, SSL *ssl, bool is_https)
{
    if (queue->count >= INT_MAX - 1)
    {
        return;
    }
    
    connection_task_t *task = malloc(sizeof(connection_task_t));
    if (!task)
        return;

    task->socket_fd = socket_fd;
    task->ssl = ssl;
    task->is_https = is_https;
    task->next = NULL;

    pthread_mutex_lock(&queue->mutex);

    if (queue->tail)
    {
        queue->tail->next = task;
    }
    else
    {
        queue->head = task;
    }
    queue->tail = task;
    queue->count++;

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

connection_task_t *dequeue_task(task_queue_t *queue)
{
    pthread_mutex_lock(&queue->mutex);

    while (queue->head == NULL)
    {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    connection_task_t *task = queue->head;
    queue->head = task->next;

    if (queue->head == NULL)
    {
        queue->tail = NULL;
    }
    queue->count--;

    pthread_mutex_unlock(&queue->mutex);
    return task;
}

void destroy_task_queue(task_queue_t *queue)
{
    pthread_mutex_lock(&queue->mutex);

    connection_task_t *current = queue->head;
    while (current)
    {
        connection_task_t *next = current->next;
        free(current);
        current = next;
    }

    pthread_mutex_unlock(&queue->mutex);
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);
}

// Memory-mapped file cache implementation
void init_mmap_cache(void)
{
    mmap_cache = calloc(MAX_MMAP_CACHE_SIZE, sizeof(mmap_cache_entry_t));
}

mmap_cache_entry_t *get_cached_file(const char *path)
{
    pthread_mutex_lock(&mmap_cache_mutex);

    for (int i = 0; i < mmap_cache_size; i++)
    {
        if (mmap_cache[i].path && strcmp(mmap_cache[i].path, path) == 0)
        {
            mmap_cache[i].last_access = time(NULL);
            mmap_cache[i].ref_count++;
            pthread_mutex_unlock(&mmap_cache_mutex);
            return &mmap_cache[i];
        }
    }

    pthread_mutex_unlock(&mmap_cache_mutex);
    return NULL;
}

void cache_file_mmap(const char *path, size_t size, const char *mime_type)
{
    if (size > MAX_MMAP_FILE_SIZE)
        return;

    pthread_mutex_lock(&mmap_cache_mutex);

    // Check if already cached
    for (int i = 0; i < mmap_cache_size; i++)
    {
        if (mmap_cache[i].path && strcmp(mmap_cache[i].path, path) == 0)
        {
            pthread_mutex_unlock(&mmap_cache_mutex);
            return;
        }
    }

    // Find slot (evict LRU if full)
    int slot = mmap_cache_size;
    if (mmap_cache_size >= MAX_MMAP_CACHE_SIZE)
    {
        time_t oldest = time(NULL);
        for (int i = 0; i < mmap_cache_size; i++)
        {
            if (mmap_cache[i].ref_count == 0 && mmap_cache[i].last_access < oldest)
            {
                oldest = mmap_cache[i].last_access;
                slot = i;
            }
        }

        if (slot == mmap_cache_size)
        {
            pthread_mutex_unlock(&mmap_cache_mutex);
            return; // All entries in use
        }

        // Evict old entry
        if (mmap_cache[slot].mmap_data)
        {
            munmap(mmap_cache[slot].mmap_data, mmap_cache[slot].size);
        }
        free(mmap_cache[slot].path);
        free(mmap_cache[slot].mime_type);
    }
    else
    {
        mmap_cache_size++;
    }

    // Map file
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        pthread_mutex_unlock(&mmap_cache_mutex);
        return;
    }

    void *mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED)
    {
        pthread_mutex_unlock(&mmap_cache_mutex);
        return;
    }

    // Advise kernel about access pattern
    madvise(mapped, size, MADV_WILLNEED | MADV_SEQUENTIAL);

    mmap_cache[slot].path = strdup(path);
    mmap_cache[slot].mmap_data = mapped;
    mmap_cache[slot].size = size;
    mmap_cache[slot].last_access = time(NULL);
    mmap_cache[slot].mime_type = strdup(mime_type);
    mmap_cache[slot].ref_count = 0;

    pthread_mutex_unlock(&mmap_cache_mutex);
}

void release_cached_file(mmap_cache_entry_t *entry)
{
    pthread_mutex_lock(&mmap_cache_mutex);
    entry->ref_count--;
    pthread_mutex_unlock(&mmap_cache_mutex);
}

void cleanup_mmap_cache(void)
{
    pthread_mutex_lock(&mmap_cache_mutex);

    for (int i = 0; i < mmap_cache_size; i++)
    {
        if (mmap_cache[i].mmap_data)
        {
            munmap(mmap_cache[i].mmap_data, mmap_cache[i].size);
        }
        free(mmap_cache[i].path);
        free(mmap_cache[i].mime_type);
    }

    free(mmap_cache);
    mmap_cache = NULL;
    mmap_cache_size = 0;

    pthread_mutex_unlock(&mmap_cache_mutex);
}

// Buffer pool implementation
void init_buffer_pool(void)
{
    pthread_mutex_lock(&buffer_pool_mutex);

    for (int i = 0; i < BUFFER_POOL_SIZE; i++)
    {
        buffer_pool_t *buf = malloc(sizeof(buffer_pool_t));
        if (buf)
        {
            buf->buffer = malloc(DEFAULT_BUFFER_SIZE);
            buf->size = DEFAULT_BUFFER_SIZE;
            buf->in_use = false;
            buf->next = buffer_pool;
            buffer_pool = buf;
        }
    }

    pthread_mutex_unlock(&buffer_pool_mutex);
}

char *get_buffer_from_pool(size_t min_size)
{
    pthread_mutex_lock(&buffer_pool_mutex);

    buffer_pool_t *current = buffer_pool;
    while (current)
    {
        if (!current->in_use && current->size >= min_size)
        {
            current->in_use = true;
            pthread_mutex_unlock(&buffer_pool_mutex);
            return current->buffer;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&buffer_pool_mutex);

    return malloc(min_size);
}

void return_buffer_to_pool(char *buffer)
{
    pthread_mutex_lock(&buffer_pool_mutex);

    buffer_pool_t *current = buffer_pool;
    while (current)
    {
        if (current->buffer == buffer)
        {
            current->in_use = false;
            pthread_mutex_unlock(&buffer_pool_mutex);
            return;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&buffer_pool_mutex);

    // Not from pool, free it
    free(buffer);
}

void cleanup_buffer_pool(void)
{
    pthread_mutex_lock(&buffer_pool_mutex);

    buffer_pool_t *current = buffer_pool;
    while (current)
    {
        buffer_pool_t *next = current->next;
        free(current->buffer);
        free(current);
        current = next;
    }

    buffer_pool = NULL;
    pthread_mutex_unlock(&buffer_pool_mutex);
}
