#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <libgen.h>
#include <ctype.h>

// ANSI color codes
#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"
#define COLOR_BOLD    "\x1b[1m"

// Default configuration
static LogConfig g_log_config = {
    .level = LOG_LEVEL_INFO,
    .categories = LOG_CAT_ALL,
    .format = LOG_FORMAT_PLAIN,
    .console_output = true,
    .file_output = true,
    .include_timestamp = true,
    .include_thread_id = true,
    .include_source_location = false,
    .colorize_console = true,
    .log_file = "log/server.log",
    .max_file_size = 100 * 1024 * 1024,  // 100MB
    .max_backup_files = 5
};

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_log_initialized = false;

// Performance tracking
typedef struct {
    char operation[64];
    struct timeval start_time;
    bool active;
} PerfTracker;

#define MAX_PERF_TRACKERS 32
static PerfTracker g_perf_trackers[MAX_PERF_TRACKERS];
static pthread_mutex_t g_perf_mutex = PTHREAD_MUTEX_INITIALIZER;

// Get color for log level
static const char *get_level_color(LogLevel level)
{
    switch (level) {
        case LOG_LEVEL_ERROR: return COLOR_RED;
        case LOG_LEVEL_WARN:  return COLOR_YELLOW;
        case LOG_LEVEL_INFO:  return COLOR_GREEN;
        case LOG_LEVEL_DEBUG: return COLOR_CYAN;
        case LOG_LEVEL_TRACE: return COLOR_MAGENTA;
        default: return COLOR_WHITE;
    }
}

// Get level prefix
static const char *get_level_prefix(LogLevel level)
{
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARN:  return "WARN ";
        case LOG_LEVEL_INFO:  return "INFO ";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_TRACE: return "TRACE";
        default: return "?????";
    }
}

// Get category name
static const char *get_category_name(LogCategory cat)
{
    switch (cat) {
        case LOG_CAT_GENERAL:     return "GENERAL";
        case LOG_CAT_SECURITY:    return "SECURITY";
        case LOG_CAT_NETWORK:     return "NETWORK";
        case LOG_CAT_HTTP:        return "HTTP";
        case LOG_CAT_SSL:         return "SSL";
        case LOG_CAT_WEBSOCKET:   return "WEBSOCKET";
        case LOG_CAT_CACHE:       return "CACHE";
        case LOG_CAT_PERFORMANCE: return "PERF";
        default: return "UNKNOWN";
    }
}

const char *log_level_to_string(LogLevel level)
{
    switch (level) {
        case LOG_LEVEL_OFF:   return "off";
        case LOG_LEVEL_ERROR: return "error";
        case LOG_LEVEL_WARN:  return "warn";
        case LOG_LEVEL_INFO:  return "info";
        case LOG_LEVEL_DEBUG: return "debug";
        case LOG_LEVEL_TRACE: return "trace";
        default: return "unknown";
    }
}

const char *log_mode_to_string(LogLevel level)
{
    switch (level) {
        case LOG_LEVEL_OFF:   return "off";
        case LOG_LEVEL_ERROR: 
        case LOG_LEVEL_WARN:
        case LOG_LEVEL_INFO:  return "classic";
        case LOG_LEVEL_DEBUG: return "debug";
        case LOG_LEVEL_TRACE: return "advanced";
        default: return "classic";
    }
}

LogLevel log_level_from_string(const char *str)
{
    if (!str) return LOG_LEVEL_INFO;
    
    // Handle mode names
    if (strcasecmp(str, "off") == 0) return LOG_LEVEL_OFF;
    if (strcasecmp(str, "classic") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "debug") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(str, "advanced") == 0) return LOG_LEVEL_TRACE;
    
    // Handle level names
    if (strcasecmp(str, "error") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "warn") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(str, "warning") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(str, "info") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "trace") == 0) return LOG_LEVEL_TRACE;
    
    // Handle boolean-like values for backwards compatibility
    if (strcasecmp(str, "true") == 0 || strcmp(str, "1") == 0) 
        return LOG_LEVEL_INFO;
    if (strcasecmp(str, "false") == 0 || strcmp(str, "0") == 0) 
        return LOG_LEVEL_OFF;
    
    return LOG_LEVEL_INFO;
}

// Rotate log files
static void rotate_logs(void)
{
    struct stat st;
    if (stat(g_log_config.log_file, &st) != 0)
        return;
    
    if (st.st_size < (off_t)g_log_config.max_file_size)
        return;
    
    // Rotate existing backup files
    char old_path[512], new_path[512];
    for (int i = g_log_config.max_backup_files - 1; i >= 0; i--) {
        if (i == 0) {
            snprintf(old_path, sizeof(old_path), "%s", g_log_config.log_file);
        } else {
            snprintf(old_path, sizeof(old_path), "%s.%d", g_log_config.log_file, i);
        }
        snprintf(new_path, sizeof(new_path), "%s.%d", g_log_config.log_file, i + 1);
        
        if (i + 1 >= g_log_config.max_backup_files) {
            unlink(old_path);
        } else {
            rename(old_path, new_path);
        }
    }
}

// Create log directory if needed
static void ensure_log_directory(void)
{
    char log_dir[512];
    strncpy(log_dir, g_log_config.log_file, sizeof(log_dir) - 1);
    log_dir[sizeof(log_dir) - 1] = '\0';
    
    char *dir_path = dirname(log_dir);
    if (!dir_path || strcmp(dir_path, ".") == 0)
        return;
    
    struct stat st;
    if (stat(dir_path, &st) != 0) {
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "Failed to create log directory: %s\n", strerror(errno));
        }
    }
}

void log_init(LogConfig *config)
{
    pthread_mutex_lock(&g_log_mutex);
    
    if (config) {
        memcpy(&g_log_config, config, sizeof(LogConfig));
    }
    
    ensure_log_directory();
    g_log_initialized = true;
    
    pthread_mutex_unlock(&g_log_mutex);
    
    LOG_INFO(LOG_CAT_GENERAL, "Logging system initialized [mode=%s, level=%s]",
             log_mode_to_string(g_log_config.level),
             log_level_to_string(g_log_config.level));
}

void log_cleanup(void)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_initialized = false;
    pthread_mutex_unlock(&g_log_mutex);
}

void log_set_level(LogLevel level)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.level = level;
    pthread_mutex_unlock(&g_log_mutex);
}

void log_set_categories(LogCategory categories)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.categories = categories;
    pthread_mutex_unlock(&g_log_mutex);
}

void log_write(LogLevel level, LogCategory category, const char *file,
               int line, const char *func, const char *fmt, ...)
{
    // Quick check without lock
    if (level == LOG_LEVEL_OFF || g_log_config.level == LOG_LEVEL_OFF)
        return;
    
    if (level > g_log_config.level)
        return;
    
    if (!(category & g_log_config.categories))
        return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    // Get timestamp
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    
    char timestamp[64] = "";
    if (g_log_config.include_timestamp) {
        snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000);
    }
    
    // Get thread ID
    char thread_id[32] = "";
    if (g_log_config.include_thread_id) {
        snprintf(thread_id, sizeof(thread_id), "%lu", (unsigned long)pthread_self());
    }
    
    // Get source location
    char source_loc[256] = "";
    if (g_log_config.include_source_location && file && func) {
        const char *filename = strrchr(file, '/');
        filename = filename ? filename + 1 : file;
        snprintf(source_loc, sizeof(source_loc), "%s:%d:%s", filename, line, func);
    }
    
    // Format the message
    char message[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    // Build log entry based on format
    char log_entry[8192];
    
    if (g_log_config.format == LOG_FORMAT_JSON) {
        snprintf(log_entry, sizeof(log_entry),
                 "{\"timestamp\":\"%s\",\"level\":\"%s\",\"category\":\"%s\","
                 "\"pid\":%d,\"tid\":\"%s\",\"source\":\"%s\",\"message\":\"%s\"}\n",
                 timestamp, get_level_prefix(level), get_category_name(category),
                 getpid(), thread_id, source_loc, message);
    } else if (g_log_config.format == LOG_FORMAT_SYSLOG) {
        // Syslog-compatible format
        snprintf(log_entry, sizeof(log_entry),
                 "<%d>%s %s[%d]: [%s] %s\n",
                 level, timestamp, "carbon", getpid(),
                 get_category_name(category), message);
    } else {
        // Plain text format
        if (g_log_config.include_source_location && source_loc[0]) {
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] [%s] [PID:%d] [TID:%s] [%s] [%s] %s\n",
                     timestamp, get_level_prefix(level), getpid(), thread_id,
                     get_category_name(category), source_loc, message);
        } else {
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] [%s] [PID:%d] [TID:%s] [%s] %s\n",
                     timestamp, get_level_prefix(level), getpid(), thread_id,
                     get_category_name(category), message);
        }
    }
    
    // Write to console
    if (g_log_config.console_output) {
        if (g_log_config.colorize_console && isatty(STDOUT_FILENO)) {
            fprintf(stdout, "%s%s%s", get_level_color(level), log_entry, COLOR_RESET);
        } else {
            fputs(log_entry, stdout);
        }
        fflush(stdout);
    }
    
    // Write to file
    if (g_log_config.file_output && g_log_config.log_file[0]) {
        rotate_logs();
        
        FILE *fp = fopen(g_log_config.log_file, "a");
        if (fp) {
            fputs(log_entry, fp);
            fflush(fp);
            fclose(fp);
        }
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

// Backwards compatible log_event function
void log_event(const char *message)
{
    if (!message) return;
    log_write(LOG_LEVEL_INFO, LOG_CAT_GENERAL, NULL, 0, NULL, "%s", message);
}

// Secure logging - sanitizes potentially sensitive data
void log_secure(LogLevel level, LogCategory category, const char *fmt, ...)
{
    char message[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    // Sanitize common sensitive patterns
    char *patterns[] = {
        "password", "passwd", "pwd", "secret", "token", "key", "auth",
        "credential", "credit", "ssn", "api_key", "apikey", NULL
    };
    
    char sanitized[4096];
    strncpy(sanitized, message, sizeof(sanitized) - 1);
    sanitized[sizeof(sanitized) - 1] = '\0';
    
    // Convert to lowercase for pattern matching
    char lower[4096];
    for (size_t i = 0; i < strlen(sanitized) && i < sizeof(lower) - 1; i++) {
        lower[i] = tolower((unsigned char)sanitized[i]);
    }
    lower[strlen(sanitized)] = '\0';
    
    // Check for sensitive patterns
    bool has_sensitive = false;
    for (int i = 0; patterns[i]; i++) {
        if (strstr(lower, patterns[i])) {
            has_sensitive = true;
            break;
        }
    }
    
    if (has_sensitive) {
        log_write(level, category, NULL, 0, NULL, "[REDACTED] Message contained sensitive data");
    } else {
        log_write(level, category, NULL, 0, NULL, "%s", sanitized);
    }
}

void log_perf_start(const char *operation)
{
    if (g_log_config.level < LOG_LEVEL_DEBUG)
        return;
    
    pthread_mutex_lock(&g_perf_mutex);
    
    for (int i = 0; i < MAX_PERF_TRACKERS; i++) {
        if (!g_perf_trackers[i].active) {
            strncpy(g_perf_trackers[i].operation, operation, sizeof(g_perf_trackers[i].operation) - 1);
            g_perf_trackers[i].operation[sizeof(g_perf_trackers[i].operation) - 1] = '\0';
            gettimeofday(&g_perf_trackers[i].start_time, NULL);
            g_perf_trackers[i].active = true;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_perf_mutex);
}

void log_perf_end(const char *operation)
{
    if (g_log_config.level < LOG_LEVEL_DEBUG)
        return;
    
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    
    pthread_mutex_lock(&g_perf_mutex);
    
    for (int i = 0; i < MAX_PERF_TRACKERS; i++) {
        if (g_perf_trackers[i].active && 
            strcmp(g_perf_trackers[i].operation, operation) == 0) {
            
            long elapsed_us = (end_time.tv_sec - g_perf_trackers[i].start_time.tv_sec) * 1000000 +
                             (end_time.tv_usec - g_perf_trackers[i].start_time.tv_usec);
            
            g_perf_trackers[i].active = false;
            
            pthread_mutex_unlock(&g_perf_mutex);
            
            if (elapsed_us > 1000000) {
                LOG_DEBUG(LOG_CAT_PERFORMANCE, "%s completed in %.2f s", operation, elapsed_us / 1000000.0);
            } else if (elapsed_us > 1000) {
                LOG_DEBUG(LOG_CAT_PERFORMANCE, "%s completed in %.2f ms", operation, elapsed_us / 1000.0);
            } else {
                LOG_DEBUG(LOG_CAT_PERFORMANCE, "%s completed in %ld µs", operation, elapsed_us);
            }
            return;
        }
    }
    
    pthread_mutex_unlock(&g_perf_mutex);
}

void log_hexdump(const char *label, const void *data, size_t len)
{
    if (g_log_config.level < LOG_LEVEL_TRACE)
        return;
    
    if (!data || len == 0)
        return;
    
    // Limit output size
    if (len > 256) {
        LOG_TRACE(LOG_CAT_GENERAL, "%s: [%zu bytes, showing first 256]", label, len);
        len = 256;
    }
    
    const unsigned char *bytes = (const unsigned char *)data;
    char line[80];
    char ascii[17];
    
    for (size_t i = 0; i < len; i += 16) {
        int pos = snprintf(line, sizeof(line), "%04zx: ", i);
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", bytes[i + j]);
                ascii[j] = isprint(bytes[i + j]) ? bytes[i + j] : '.';
            } else {
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
                ascii[j] = ' ';
            }
        }
        ascii[16] = '\0';
        
        LOG_TRACE(LOG_CAT_GENERAL, "%s: %s |%s|", label, line, ascii);
    }
}
