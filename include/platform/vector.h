/**
 * @file vector.h
 * @brief Growable array of fixed-size elements.
 *
 * A vector owns one block of heap memory with room for `capacity` elements of `elem_size` bytes; the first
 * `count` are in use. A pointer into it (cbae_vector_at, cbae_vector_bsearch) stays valid until the vector next
 * grows (push, resize or reserve) or is destroyed. Growth doubles the capacity, so a push costs O(1) on average.
 *
 * A vector whose bytes are all zero is the state cbae_vector_destroy leaves behind, and cbae_vector_init leaves
 * behind when it fails: it holds nothing, destroy accepts it, and every other call that would need storage
 * refuses it with CBAE_ERR_INVALID.
 *
 * Errors      CBAE_ERR_INVALID    a NULL argument, a vector that was never initialised, a NULL comparator
 *             CBAE_ERR_NOT_FOUND  pop from an empty vector
 *             CBAE_ERR_OVERFLOW   the vector would need more than PTRDIFF_MAX bytes
 *             CBAE_ERR_OOM        out of memory
 * A call that fails changes nothing: count, capacity and every element are as they were. cbae_vector_init is
 * the one exception: on failure it leaves *v all zero.
 */
#ifndef CBAE_VECTOR_H
#define CBAE_VECTOR_H

#include "cbae/cbae_error.h"
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_vector {
    void  *data;
    size_t elem_size;
    size_t count;
    size_t capacity;
} cbae_vector_t;

/** Prepares @p v to hold elements of @p elem_size bytes, with room for @p initial_cap of them (0: eight). */
cbae_err_t cbae_vector_init   (cbae_vector_t *v, size_t elem_size, size_t initial_cap);

/** Frees the storage and leaves @p v all zero. Accepts NULL and a vector that is already destroyed. */
void       cbae_vector_destroy(cbae_vector_t *v);

/** Appends a copy of the element @p elem points to. It may point into @p v itself. */
cbae_err_t cbae_vector_push   (cbae_vector_t *v, const void *elem);

/** Removes the last element, copying it to @p out unless that is NULL. */
cbae_err_t cbae_vector_pop    (cbae_vector_t *v, void *out_elem);

/** The element at @p idx, or NULL if @p idx is not below count. */
void      *cbae_vector_at     (const cbae_vector_t *v, size_t idx);

/** Sets the count. Elements added by growing are zero bytes. */
cbae_err_t cbae_vector_resize (cbae_vector_t *v, size_t new_count);

/** Makes room for at least @p min_capacity elements, so that pushes up to there cannot fail. */
cbae_err_t cbae_vector_reserve(cbae_vector_t *v, size_t min_capacity);

/** Sets the count to 0; the storage stays. */
void       cbae_vector_clear  (cbae_vector_t *v);

typedef int (*cbae_compare_fn)(const void *a, const void *b);

/** Sorts in place (not stable). */
cbae_err_t cbae_vector_sort   (cbae_vector_t *v, cbae_compare_fn cmp);

/** Binary search of a vector sorted by @p cmp: a matching element, or NULL. */
void      *cbae_vector_bsearch(const cbae_vector_t *v, const void *key, cbae_compare_fn cmp);

/** The element at @p idx as a @p type. @p idx must be below the count (the result is a NULL dereference if not). */
#define CBAE_VEC_AT(vec, type, idx)    (*(type *)cbae_vector_at((vec), (idx)))

/** Appends @p val, a @p type. Evaluates to the error code of the push: check it (CBAE_CHECK(CBAE_VEC_PUSH(...))). */
#define CBAE_VEC_PUSH(vec, type, val)  __extension__ ({ type cbae_vec_val_ = (val); cbae_vector_push((vec), &cbae_vec_val_); })

#define cbae_vector_count(v)           ((v)->count)

#ifdef __cplusplus
}
#endif

#endif /* CBAE_VECTOR_H */
