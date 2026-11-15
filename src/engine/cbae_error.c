/**
 * @file cbae_error.c
 * @brief Thread-local error context — allocation, formatting, retrieval.
 */
#include "cbae/cbae_error.h"
#include <string.h>
#include <stdio.h>

static _Thread_local cbae_error_context_t t_ctx;

cbae_error_context_t *cbae_error_get_context(void) { return &t_ctx; }
void cbae_error_clear(void) { memset(&t_ctx, 0, sizeof(t_ctx)); }

void cbae_error_set(cbae_err_t code,
                    const char *file, int line, const char *func,
                    const char *fmt, ...) {
    t_ctx.code = code;
    t_ctx.file = file;
    t_ctx.line = line;
    t_ctx.func = func;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t_ctx.message, CBAE_ERR_MSG_MAX, fmt, ap);
    va_end(ap);
}

const char *cbae_last_error(void) {
    return t_ctx.message[0] ? t_ctx.message : cbae_err_str(t_ctx.code);
}

const char *cbae_err_str(cbae_err_t code) {
    switch(code) {
        case CBAE_OK:              return "ok";
        case CBAE_ERR_GENERIC:     return "generic error";
        case CBAE_ERR_OOM:         return "out of memory";
        case CBAE_ERR_IO:          return "I/O error";
        case CBAE_ERR_INVALID:     return "invalid argument";
        case CBAE_ERR_NOT_FOUND:   return "not found";
        case CBAE_ERR_PARSE:       return "parse error";
        case CBAE_ERR_DB:          return "database error";
        case CBAE_ERR_OVERFLOW:    return "overflow";
        case CBAE_ERR_UNSUPPORTED: return "unsupported";
        case CBAE_ERR_BUSY:        return "busy";
        case CBAE_ERR_TIMEOUT:     return "timeout";
        case CBAE_ERR_THREAD:      return "thread error";
        default:                   return "unknown error";
    }
}
