/**
 * @file logging.h
 * @brief Leveled structured logger with optional JSON output.
 */
#ifndef CBAE_LOGGING_H
#define CBAE_LOGGING_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_log_level {
    CBAE_LOG_TRACE = 0,
    CBAE_LOG_DEBUG = 1,
    CBAE_LOG_INFO  = 2,
    CBAE_LOG_WARN  = 3,
    CBAE_LOG_ERROR = 4,
    CBAE_LOG_NONE  = 5,
} cbae_log_level_t;

void cbae_log_init    (cbae_log_level_t min_level,
                       const char *log_path, int json_mode);
void cbae_log_shutdown(void);
void cbae_log_write   (cbae_log_level_t level,
                       const char *file, int line, const char *func,
                       const char *fmt, ...);
void cbae_log_write_v (cbae_log_level_t level,
                       const char *file, int line, const char *func,
                       const char *fmt, va_list args);

#define LOG_TRACE(fmt,...) cbae_log_write(CBAE_LOG_TRACE,__FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_DEBUG(fmt,...) cbae_log_write(CBAE_LOG_DEBUG,__FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_INFO(fmt,...)  cbae_log_write(CBAE_LOG_INFO, __FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_WARN(fmt,...)  cbae_log_write(CBAE_LOG_WARN, __FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_ERROR(fmt,...) cbae_log_write(CBAE_LOG_ERROR,__FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* CBAE_LOGGING_H */
