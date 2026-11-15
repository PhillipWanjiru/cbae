/**
 * @file logging.h
 * @brief Leveled logger: one line per message, plain text or JSON.
 *
 * One logger per process. Nothing is written until cbae_log_init, and nothing after cbae_log_shutdown. Every
 * call is safe from any thread, including init and shutdown while others log; a line is written whole, so
 * lines from different threads never mix.
 *
 *   text   [2026-11-09T08:09:03.412Z] INFO  loader/pe_loader.c:544 (cbae_pe_load)  PE load: a.sys
 *   json   {"ts":"2026-11-09T08:09:03.412Z","level":"INFO","file":"...","line":544,"func":"...","msg":"..."}
 *
 * The time is UTC. Messages come from file names, symbol names and section names of the binary under
 * analysis, which an attacker chooses, so the text of a message cannot start a second line, break the JSON
 * or send a terminal a command. What is written instead of a character:
 *
 *   character                                          text mode               JSON mode
 *   backslash                                          two backslashes         two backslashes
 *   quote                                              as it is                backslash, quote
 *   control character (C0 and DEL)                     \xNN                    \n \r \t \b \f, else \u00NN
 *   C1 control, U+2028, U+2029, bidi override/isolate  \uXXXX                  \uXXXX
 *   byte that is not valid UTF-8                       \xNN                    \ufffd
 *
 * (N and X are lower-case hex digits.) Every other valid UTF-8 character is written as it is. A message is cut at
 * CBAE_LOG_MSG_MAX - 1 bytes, a file or function name at 255.
 */
#ifndef CBAE_LOGGING_H
#define CBAE_LOGGING_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBAE_LOG_MSG_MAX 1024

typedef enum cbae_log_level {
    CBAE_LOG_TRACE = 0,
    CBAE_LOG_DEBUG = 1,
    CBAE_LOG_INFO  = 2,
    CBAE_LOG_WARN  = 3,
    CBAE_LOG_ERROR = 4,
    CBAE_LOG_NONE  = 5,
} cbae_log_level_t;

#if defined(__GNUC__)
#define CBAE_LOG_FORMAT(fmt_idx, first_arg) __attribute__((format(printf, fmt_idx, first_arg)))
#else
#define CBAE_LOG_FORMAT(fmt_idx, first_arg)
#endif

/**
 * Starts (or restarts) logging of messages at @p min_level and above, to the file @p log_path (appended to) or,
 * if that is NULL or empty, to stderr, as JSON lines if @p json_mode is not 0. A file that cannot be opened
 * means stderr and, if @p min_level admits WARN, a warning there says why. A restart closes the previous file.
 * A message whose level is CBAE_LOG_NONE or not a level at all is never written.
 */
void cbae_log_init    (cbae_log_level_t min_level,
                       const char *log_path, int json_mode);

/** Stops logging and closes the file. Calling it again, or before cbae_log_init, does nothing. */
void cbae_log_shutdown(void);

void cbae_log_write   (cbae_log_level_t level,
                       const char *file, int line, const char *func,
                       const char *fmt, ...) CBAE_LOG_FORMAT(5, 6);
void cbae_log_write_v (cbae_log_level_t level,
                       const char *file, int line, const char *func,
                       const char *fmt, va_list args) CBAE_LOG_FORMAT(5, 0);

#define LOG_TRACE(fmt,...) cbae_log_write(CBAE_LOG_TRACE,__FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_DEBUG(fmt,...) cbae_log_write(CBAE_LOG_DEBUG,__FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_INFO(fmt,...)  cbae_log_write(CBAE_LOG_INFO, __FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_WARN(fmt,...)  cbae_log_write(CBAE_LOG_WARN, __FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)
#define LOG_ERROR(fmt,...) cbae_log_write(CBAE_LOG_ERROR,__FILE__,__LINE__,__func__,fmt,##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* CBAE_LOGGING_H */
