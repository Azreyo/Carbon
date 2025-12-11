#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>

// Log levels
typedef enum {
    LOG_LEVEL_OFF = 0,      // No logging
    LOG_LEVEL_ERROR = 1,    // Only errors
    LOG_LEVEL_WARN = 2,     // Errors + warnings
    LOG_LEVEL_INFO = 3,     // Classic mode: errors + warnings + info
    LOG_LEVEL_DEBUG = 4,    // Debug mode: all above + debug messages
    LOG_LEVEL_TRACE = 5     // Advanced mode: everything including traces
} LogLevel;

// Log categories for filtering
typedef enum {
    LOG_CAT_GENERAL = 0x01,
    LOG_CAT_SECURITY = 0x02,
    LOG_CAT_NETWORK = 0x04,
    LOG_CAT_HTTP = 0x08,
    LOG_CAT_SSL = 0x10,
    LOG_CAT_WEBSOCKET = 0x20,
    LOG_CAT_CACHE = 0x40,
    LOG_CAT_PERFORMANCE = 0x80,
    LOG_CAT_ALL = 0xFF
} LogCategory;

// Log output formats
typedef enum {
    LOG_FORMAT_PLAIN = 0,   // Simple text format
    LOG_FORMAT_JSON = 1,    // JSON structured format
    LOG_FORMAT_SYSLOG = 2   // Syslog compatible format
} LogFormat;

// Logger configuration
typedef struct {
    LogLevel level;
    LogCategory categories;
    LogFormat format;
    bool console_output;
    bool file_output;
    bool include_timestamp;
    bool include_thread_id;
    bool include_source_location;
    bool colorize_console;
    char log_file[256];
    size_t max_file_size;
    int max_backup_files;
} LogConfig;

// Initialize the logging system
void log_init(LogConfig *config);

// Cleanup logging system
void log_cleanup(void);

// Set log level at runtime
void log_set_level(LogLevel level);

// Set log categories at runtime
void log_set_categories(LogCategory categories);

// Core logging functions
void log_write(LogLevel level, LogCategory category, const char *file, 
               int line, const char *func, const char *fmt, ...);

// Convenience macros with source location
#define LOG_ERROR(cat, ...) \
    log_write(LOG_LEVEL_ERROR, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_WARN(cat, ...) \
    log_write(LOG_LEVEL_WARN, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_INFO(cat, ...) \
    log_write(LOG_LEVEL_INFO, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_DEBUG(cat, ...) \
    log_write(LOG_LEVEL_DEBUG, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_TRACE(cat, ...) \
    log_write(LOG_LEVEL_TRACE, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

// Security-specific logging (always logs regardless of level if security category enabled)
#define LOG_SECURITY(level, ...) \
    log_write(level, LOG_CAT_SECURITY, __FILE__, __LINE__, __func__, __VA_ARGS__)

// Simple backwards-compatible log function
void log_event(const char *message);

// Log mode string conversion
const char *log_level_to_string(LogLevel level);
LogLevel log_level_from_string(const char *str);
const char *log_mode_to_string(LogLevel level);

// Secure logging (sanitizes sensitive data)
void log_secure(LogLevel level, LogCategory category, const char *fmt, ...);

// Performance logging with timing
void log_perf_start(const char *operation);
void log_perf_end(const char *operation);

// Hex dump for debugging binary data (only in TRACE level)
void log_hexdump(const char *label, const void *data, size_t len);

#endif