/**
 * @file vector.h
 * @brief Growable typed dynamic array.
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

cbae_err_t cbae_vector_init   (cbae_vector_t *v, size_t elem_size, size_t initial_cap);
void       cbae_vector_destroy(cbae_vector_t *v);
cbae_err_t cbae_vector_push   (cbae_vector_t *v, const void *elem);
cbae_err_t cbae_vector_pop    (cbae_vector_t *v, void *out_elem);
void      *cbae_vector_at     (const cbae_vector_t *v, size_t idx);
cbae_err_t cbae_vector_resize (cbae_vector_t *v, size_t new_count);
cbae_err_t cbae_vector_reserve(cbae_vector_t *v, size_t min_capacity);
void       cbae_vector_clear  (cbae_vector_t *v);

typedef int (*cbae_compare_fn)(const void *a, const void *b);
void  cbae_vector_sort   (cbae_vector_t *v, cbae_compare_fn cmp);
void *cbae_vector_bsearch(const cbae_vector_t *v,
                           const void *key, cbae_compare_fn cmp);

#define CBAE_VEC_AT(vec, type, idx)    (*(type *)cbae_vector_at((vec),(idx)))
#define CBAE_VEC_PUSH(vec, type, val)  do { type _t=(val); cbae_vector_push((vec),&_t); } while(0)
#define cbae_vector_count(v)           ((v)->count)

#ifdef __cplusplus
}
#endif

#endif /* CBAE_VECTOR_H */
