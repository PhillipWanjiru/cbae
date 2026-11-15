/**
 * @file cbae_error.h
 * @brief Unified error codes and structured error context.
 */
#ifndef CBAE_ERROR_H
#define CBAE_ERROR_H

#include "cbae_types.h"
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_err {
    CBAE_OK              =  0,
    CBAE_ERR_GENERIC     = -1,
    CBAE_ERR_OOM         = -2,
    CBAE_ERR_IO          = -3,
    CBAE_ERR_INVALID     = -4,
    CBAE_ERR_NOT_FOUND   = -5,
    CBAE_ERR_PARSE       = -6,
    CBAE_ERR_DB          = -7,
    CBAE_ERR_OVERFLOW    = -8,
    CBAE_ERR_UNSUPPORTED = -9,
    CBAE_ERR_BUSY        = -10,
    CBAE_ERR_TIMEOUT     = -11,
    CBAE_ERR_THREAD      = -12,
} cbae_err_t;

#define CBAE_ERR_MSG_MAX  256

typedef struct cbae_error_context {
    cbae_err_t  code;
    char        message[CBAE_ERR_MSG_MAX];
    const char *file;
    int         line;
    const char *func;
} cbae_error_context_t;

cbae_error_context_t *cbae_error_get_context(void);
void                  cbae_error_clear(void);
#if defined(__GNUC__)
#define CBAE_PRINTF_FORMAT(fmt_idx, first_arg) __attribute__((format(printf, fmt_idx, first_arg)))
#else
#define CBAE_PRINTF_FORMAT(fmt_idx, first_arg)
#endif

/** Records an error in the calling thread's context. @p fmt is a printf format; its arguments may
 *  include cbae_last_error() (the message is formatted before the old one is replaced). */
void                  cbae_error_set(cbae_err_t code,
                                     const char *file, int line,
                                     const char *func,
                                     const char *fmt, ...) CBAE_PRINTF_FORMAT(5, 6);

#define CBAE_SET_ERR(code, fmt, ...) \
    cbae_error_set((code), __FILE__, __LINE__, __func__, (fmt), ##__VA_ARGS__)

#define CBAE_RETURN_ERR(code, fmt, ...) \
    do { CBAE_SET_ERR((code),(fmt),##__VA_ARGS__); return (code); } while(0)

#define CBAE_CHECK(expr) \
    do { cbae_err_t _e=(expr); if(_e!=CBAE_OK) return _e; } while(0)

const char *cbae_err_str(cbae_err_t code);
const char *cbae_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_ERROR_H */
