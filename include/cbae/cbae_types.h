/**
 * @file cbae_types.h
 * @brief Fundamental scalar types used across the entire CBAE codebase.
 */
#ifndef CBAE_TYPES_H
#define CBAE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t cbae_addr_t;
typedef uint64_t cbae_offset_t;
typedef uint64_t cbae_off_t;      /* short alias used by loader headers */
typedef uint64_t cbae_size_t;
typedef void    *cbae_handle_t;

#define CBAE_ADDR_INVALID  UINT64_MAX

typedef enum cbae_os {
    CBAE_OS_UNKNOWN = 0,
    CBAE_OS_WINDOWS = 1,
    CBAE_OS_LINUX   = 2,
} cbae_os_t;

#define CBAE_MIN(a, b)  ((a) < (b) ? (a) : (b))
#define CBAE_MAX(a, b)  ((a) > (b) ? (a) : (b))
#define CBAE_ALIGN_UP(v, a)    (((v) + (a) - 1) & ~((a) - 1))
#define CBAE_ALIGN_DOWN(v, a)  ((v) & ~((a) - 1))
#define CBAE_IS_ALIGNED(v, a)  (((v) & ((a) - 1)) == 0)
#define CBAE_ARRAY_LEN(arr)    (sizeof(arr) / sizeof((arr)[0]))
#define CBAE_UNUSED(x)         ((void)(x))

#ifdef __cplusplus
}
#endif

#endif /* CBAE_TYPES_H */
