/**
 * @file logging.c
 * @brief Leveled logger: plain-text or JSON lines, safe from any thread, safe against hostile message text.
 */
#include "platform/logging.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_NAME_MAX  255                                   /* bytes of a file or function name that are kept */
#define LOG_LINE_MAX  (6 * (CBAE_LOG_MSG_MAX + 2 * LOG_NAME_MAX) + 256)   /* no byte becomes more than 6 */

/* The sink. out is only touched with mu held. The level and the format are atomics, so that a message below
 * the level costs one load and the line can be built before the lock is taken. Until cbae_log_init the level
 * is NONE: nothing is logged. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static FILE           *g_out;
static _Atomic int     g_level = CBAE_LOG_NONE;
static _Atomic int     g_json;

static const char *level_str(cbae_log_level_t l) {
    switch (l) {
        case CBAE_LOG_TRACE: return "TRACE";
        case CBAE_LOG_DEBUG: return "DEBUG";
        case CBAE_LOG_INFO:  return "INFO";
        case CBAE_LOG_WARN:  return "WARN";
        case CBAE_LOG_ERROR: return "ERROR";
        default:             return "?";
    }
}

/* ---- a line under construction: appends never overrun, and a line that does not fit is cut ---- */

typedef struct { char *p; size_t n, cap; } lbuf_t;

static void put_raw(lbuf_t *b, const char *s, size_t n) {
    if (n > b->cap - b->n) n = b->cap - b->n;
    memcpy(b->p + b->n, s, n);
    b->n += n;
}
static void put_str(lbuf_t *b, const char *s) { put_raw(b, s, strlen(s)); }

static const char HEX[] = "0123456789abcdef";

static void put_xx(lbuf_t *b, unsigned char c) {                    /* \xNN */
    const char e[4] = { '\\', 'x', HEX[c >> 4], HEX[c & 15] };
    put_raw(b, e, sizeof e);
}
static void put_uxxxx(lbuf_t *b, unsigned cp) {                     /* \uXXXX, cp <= 0xFFFF */
    const char e[6] = { '\\', 'u', HEX[(cp >> 12) & 15], HEX[(cp >> 8) & 15], HEX[(cp >> 4) & 15], HEX[cp & 15] };
    put_raw(b, e, sizeof e);
}

/* Length of the valid UTF-8 sequence that starts at s[0] (n bytes remain) and its code point, or 0 if none starts there. */
static size_t utf8_seq(const unsigned char *s, size_t n, unsigned *cp) {
    if (s[0] < 0x80) { *cp = s[0]; return 1; }
    if (s[0] >= 0xC2 && s[0] <= 0xDF && n >= 2 && (s[1] & 0xC0) == 0x80) {
        *cp = ((unsigned)(s[0] & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (s[0] >= 0xE0 && s[0] <= 0xEF && n >= 3 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {
        *cp = ((unsigned)(s[0] & 0x0F) << 12) | ((unsigned)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return (*cp >= 0x800 && (*cp < 0xD800 || *cp > 0xDFFF)) ? 3 : 0;   /* no overlong form, no surrogate */
    }
    if (s[0] >= 0xF0 && s[0] <= 0xF4 && n >= 4 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
        *cp = ((unsigned)(s[0] & 0x07) << 18) | ((unsigned)(s[1] & 0x3F) << 12) | ((unsigned)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return (*cp >= 0x10000 && *cp <= 0x10FFFF) ? 4 : 0;
    }
    return 0;
}

/* Characters that are valid UTF-8 and still not written as they are: the C1 controls (a terminal acts on them as
 * on their ESC forms), the line and paragraph separators (some tools end a line at them) and the bidirectional
 * overrides and isolates (they reorder what a reader sees, so a forged name can look like another). */
static bool is_special(unsigned cp) {
    return (cp >= 0x80 && cp <= 0x9F) || cp == 0x2028 || cp == 0x2029 ||
           (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
}

/* Appends @p s, at most @p max bytes of it, in a form that cannot end the line or leave the JSON string. */
static void put_escaped(lbuf_t *b, const char *s, size_t max, bool json) {
    const unsigned char *u = (const unsigned char *)s;
    const size_t n = strnlen(s, max);
    for (size_t i = 0; i < n;) {
        unsigned cp;
        const size_t seq = utf8_seq(u + i, n - i, &cp);
        if (seq > 1) {                                                      /* a multi-byte character */
            if (is_special(cp)) put_uxxxx(b, cp); else put_raw(b, s + i, seq);
            i += seq;
            continue;
        }
        const unsigned char c = u[i++];
        if (seq == 0) {                                                     /* a byte that is not UTF-8 */
            if (json) put_uxxxx(b, 0xFFFD); else put_xx(b, c);
        } else if (c == '\\') put_str(b, "\\\\");
        else if (c == '"' && json) put_str(b, "\\\"");
        else if (c >= 0x20 && c != 0x7F) put_raw(b, (const char *)&c, 1);
        else if (!json) put_xx(b, c);
        else switch (c) {                                                   /* a control character, in JSON */
            case '\n': put_str(b, "\\n"); break;
            case '\r': put_str(b, "\\r"); break;
            case '\t': put_str(b, "\\t"); break;
            case '\b': put_str(b, "\\b"); break;
            case '\f': put_str(b, "\\f"); break;
            default:   put_uxxxx(b, c);
        }
    }
}

/* ---- the sink ---- */

void cbae_log_init(cbae_log_level_t min_level, const char *path, int json_mode) {
    FILE *f = NULL;
    int open_errno = 0;
    if (path && *path) {
        f = fopen(path, "a");
        if (!f) open_errno = errno;
    }
    const bool fell_back = !f && path && *path;
    if (!f) f = stderr;

    pthread_mutex_lock(&g_mu);
    FILE *old = g_out;
    g_out = f;
    atomic_store(&g_json, json_mode != 0);
    atomic_store(&g_level, (int)min_level);
    pthread_mutex_unlock(&g_mu);
    if (old && old != stderr) fclose(old);

    if (fell_back) cbae_log_write(CBAE_LOG_WARN, __FILE__, __LINE__, __func__,
                                  "cannot open log file '%s': %s; logging to stderr", path, strerror(open_errno));
}

void cbae_log_shutdown(void) {
    pthread_mutex_lock(&g_mu);
    FILE *old = g_out;
    g_out = NULL;
    atomic_store(&g_level, CBAE_LOG_NONE);
    pthread_mutex_unlock(&g_mu);
    if (old && old != stderr) fclose(old);
}

void cbae_log_write_v(cbae_log_level_t level, const char *file, int line, const char *func,
                      const char *fmt, va_list args) {
    if ((int)level < (int)CBAE_LOG_TRACE || (int)level >= (int)CBAE_LOG_NONE) return;
    if ((int)level < atomic_load(&g_level)) return;

    char msg[CBAE_LOG_MSG_MAX];
    msg[0] = '\0';
    if (fmt && vsnprintf(msg, sizeof msg, fmt, args) < 0) strcpy(msg, "(unformattable log message)");

    char ts[40];
    struct timespec now;
    struct tm tm;
    if (clock_gettime(CLOCK_REALTIME, &now) == 0 && gmtime_r(&now.tv_sec, &tm)) {
        const size_t n = strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S", &tm);
        snprintf(ts + n, sizeof ts - n, ".%03ldZ", now.tv_nsec / 1000000);
    } else strcpy(ts, "?");

    const bool json = atomic_load(&g_json) != 0;
    char text[LOG_LINE_MAX];
    lbuf_t b = { text, 0, sizeof text - 1 };                                /* one byte is kept for the newline */
    char num[16];
    snprintf(num, sizeof num, "%d", line);
    if (json) {
        put_str(&b, "{\"ts\":\"");     put_escaped(&b, ts, sizeof ts, true);
        put_str(&b, "\",\"level\":\""); put_str(&b, level_str(level));
        put_str(&b, "\",\"file\":\"");  put_escaped(&b, file ? file : "?", LOG_NAME_MAX, true);
        put_str(&b, "\",\"line\":");    put_str(&b, num);
        put_str(&b, ",\"func\":\"");    put_escaped(&b, func ? func : "?", LOG_NAME_MAX, true);
        put_str(&b, "\",\"msg\":\"");   put_escaped(&b, msg, sizeof msg, true);
        put_str(&b, "\"}");
    } else {
        put_str(&b, "[");  put_escaped(&b, ts, sizeof ts, false);
        put_str(&b, "] "); put_str(&b, level_str(level));
        put_str(&b, "  "); put_escaped(&b, file ? file : "?", LOG_NAME_MAX, false);
        put_str(&b, ":");  put_str(&b, num);
        put_str(&b, " ("); put_escaped(&b, func ? func : "?", LOG_NAME_MAX, false);
        put_str(&b, ")  "); put_escaped(&b, msg, sizeof msg, false);
    }
    text[b.n++] = '\n';

    pthread_mutex_lock(&g_mu);
    if (g_out) {
        fwrite(text, 1, b.n, g_out);
        fflush(g_out);
    }
    pthread_mutex_unlock(&g_mu);
}

void cbae_log_write(cbae_log_level_t level, const char *file, int line, const char *func,
                    const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cbae_log_write_v(level, file, line, func, fmt, ap);
    va_end(ap);
}
