/**
 * @file logging.c
 * @brief Leveled structured logger — plain-text or JSON lines.
 */
#include "platform/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>

static struct {
    cbae_log_level_t min_level;
    FILE            *out;
    bool             json;
    pthread_mutex_t  mu;
} g_log = { .min_level = CBAE_LOG_INFO };

static const char *level_str(cbae_log_level_t l) {
    switch(l) {
        case CBAE_LOG_TRACE: return "TRACE";
        case CBAE_LOG_DEBUG: return "DEBUG";
        case CBAE_LOG_INFO:  return "INFO";
        case CBAE_LOG_WARN:  return "WARN";
        case CBAE_LOG_ERROR: return "ERROR";
        default:             return "?";
    }
}

void cbae_log_init(cbae_log_level_t min_level, const char *path, int json_mode) {
    g_log.min_level = min_level;
    g_log.json      = (bool)json_mode;
    g_log.out       = (path && *path) ? fopen(path, "a") : stderr;
    if(!g_log.out) g_log.out = stderr;
    pthread_mutex_init(&g_log.mu, NULL);
}

void cbae_log_shutdown(void) {
    if(g_log.out && g_log.out != stderr) fclose(g_log.out);
    g_log.out = NULL;
    pthread_mutex_destroy(&g_log.mu);
}

void cbae_log_write_v(cbae_log_level_t level,
                      const char *file, int line, const char *func,
                      const char *fmt, va_list args) {
    if(level < g_log.min_level || !g_log.out) return;
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, args);
    pthread_mutex_lock(&g_log.mu);
    if(g_log.json)
        fprintf(g_log.out, "{\"ts\":\"%s\",\"level\":\"%s\",\"file\":\"%s\",\"line\":%d,\"func\":\"%s\",\"msg\":\"%s\"}\n",
                ts, level_str(level), file, line, func, msg);
    else
        fprintf(g_log.out, "[%s] %s  %s:%d (%s)  %s\n",
                ts, level_str(level), file, line, func, msg);
    fflush(g_log.out);
    pthread_mutex_unlock(&g_log.mu);
}

void cbae_log_write(cbae_log_level_t level,
                    const char *file, int line, const char *func,
                    const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cbae_log_write_v(level, file, line, func, fmt, ap);
    va_end(ap);
}
