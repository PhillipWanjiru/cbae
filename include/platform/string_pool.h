/**
 * @file string_pool.h
 * @brief Interned string pool — deduplicated, stable const char* references.
 */
#ifndef CBAE_STRING_POOL_H
#define CBAE_STRING_POOL_H

#include "cbae/cbae_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_string_pool cbae_string_pool_t;

cbae_err_t  cbae_string_pool_init    (cbae_string_pool_t **out_pool,
                                       size_t initial_capacity);
void        cbae_string_pool_destroy (cbae_string_pool_t *pool);
const char *cbae_string_pool_intern  (cbae_string_pool_t *pool, const char *str);
const char *cbae_string_pool_intern_n(cbae_string_pool_t *pool,
                                       const char *str, size_t len);
size_t      cbae_string_pool_count   (const cbae_string_pool_t *pool);
size_t      cbae_string_pool_bytes   (const cbae_string_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_STRING_POOL_H */
