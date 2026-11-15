/**
 * @file string_pool.h
 * @brief Interned string pool: deduplicated strings with stable const char* references.
 *
 * Contract
 *  - A pointer returned by intern or find stays valid, and keeps its contents, until the pool is
 *    destroyed. Interning more strings never moves or frees an earlier one.
 *  - Equal strings (same length, same bytes) are one string: intern returns the same pointer, so
 *    pointer equality is string equality for everything that came out of one pool.
 *  - find never changes the pool. A lookup of a name that is not there costs nothing and allocates
 *    nothing.
 *  - A failed intern (NULL return) leaves the pool exactly as it was.
 *  - intern_n stores the @p len bytes given, whatever they are, plus a terminating NUL; a string with
 *    an embedded NUL is a different string from its prefix, though C code reading it as a C string
 *    stops at the first NUL.
 *  - The hash is keyed (SipHash-2-4, a random key per pool): a hostile binary cannot choose symbol
 *    names that collide. Lookups stay O(1) on average however many strings are interned; the table
 *    doubles when it is three-quarters full.
 *  - Not thread safe: one writer, or any number of readers once interning has finished.
 */
#ifndef CBAE_STRING_POOL_H
#define CBAE_STRING_POOL_H

#include "cbae/cbae_error.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_string_pool cbae_string_pool_t;

/** Longest string the pool accepts (1 GiB); a longer one makes intern return NULL. */
#define CBAE_STRING_POOL_MAX_LEN ((size_t)1 << 30)

typedef struct {
    size_t strings;         /**< distinct strings held */
    size_t bytes;           /**< their bytes, terminators included */
    size_t buckets;         /**< hash table size */
    size_t longest_chain;   /**< most strings in one bucket (a quality measure; walks the table) */
    size_t chunks;          /**< storage blocks allocated */
} cbae_string_pool_stats_t;

/**
 * Creates a pool. @p initial_capacity is a hint for how many strings to expect (the table grows
 * anyway; a huge hint is capped). *out is NULL on failure. CBAE_ERR_INVALID for a NULL @p out,
 * CBAE_ERR_OOM when memory runs out.
 */
cbae_err_t cbae_string_pool_init(cbae_string_pool_t **out, size_t initial_capacity);

/** As init, with the hash key given instead of random: reproducible table layout for tests. */
cbae_err_t cbae_string_pool_init_seeded(cbae_string_pool_t **out, size_t initial_capacity, const uint8_t key[16]);

void cbae_string_pool_destroy(cbae_string_pool_t *pool);

/** The pool's copy of @p str, adding it when new. NULL for a NULL argument, a string over
 *  CBAE_STRING_POOL_MAX_LEN, or when memory runs out. */
const char *cbae_string_pool_intern(cbae_string_pool_t *pool, const char *str);
const char *cbae_string_pool_intern_n(cbae_string_pool_t *pool, const char *str, size_t len);

/** The pool's copy of @p str if it is in the pool, else NULL. Never adds. */
const char *cbae_string_pool_find(const cbae_string_pool_t *pool, const char *str);
const char *cbae_string_pool_find_n(const cbae_string_pool_t *pool, const char *str, size_t len);

size_t cbae_string_pool_count(const cbae_string_pool_t *pool);   /**< distinct strings */
size_t cbae_string_pool_bytes(const cbae_string_pool_t *pool);   /**< their bytes, terminators included */
void   cbae_string_pool_stats(const cbae_string_pool_t *pool, cbae_string_pool_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_STRING_POOL_H */
