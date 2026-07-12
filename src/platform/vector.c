/**
 * @file vector.c
 * @brief Growable dynamic array — doubles capacity on overflow.
 */
#include "platform/vector.h"
#include <stdlib.h>
#include <string.h>

#define VEC_INIT_CAP 8

cbae_err_t cbae_vector_init(cbae_vector_t *v, size_t elem_size, size_t initial_cap) {
    if(!v || !elem_size) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "bad vector params");
    if(!initial_cap) initial_cap = VEC_INIT_CAP;
    v->data = malloc(elem_size * initial_cap);
    if(!v->data) CBAE_RETURN_ERR(CBAE_ERR_OOM, "vector alloc failed");
    v->elem_size = elem_size;
    v->count     = 0;
    v->capacity  = initial_cap;
    return CBAE_OK;
}

void cbae_vector_destroy(cbae_vector_t *v) {
    if(!v) return;
    free(v->data);
    memset(v, 0, sizeof(*v));
}

cbae_err_t cbae_vector_reserve(cbae_vector_t *v, size_t min_cap) {
    if(!v) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null vector");
    if(v->capacity >= min_cap) return CBAE_OK;
    size_t new_cap = v->capacity ? v->capacity : VEC_INIT_CAP;
    while(new_cap < min_cap) new_cap <<= 1;
    void *p = realloc(v->data, new_cap * v->elem_size);
    if(!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "vector realloc failed");
    v->data     = p;
    v->capacity = new_cap;
    return CBAE_OK;
}

cbae_err_t cbae_vector_push(cbae_vector_t *v, const void *elem) {
    if(!v || !elem) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null arg");
    CBAE_CHECK(cbae_vector_reserve(v, v->count + 1));
    memcpy((uint8_t *)v->data + v->count * v->elem_size, elem, v->elem_size);
    v->count++;
    return CBAE_OK;
}

cbae_err_t cbae_vector_pop(cbae_vector_t *v, void *out) {
    if(!v || !v->count) CBAE_RETURN_ERR(CBAE_ERR_NOT_FOUND, "vector empty");
    v->count--;
    if(out) memcpy(out, (uint8_t *)v->data + v->count * v->elem_size, v->elem_size);
    return CBAE_OK;
}

void *cbae_vector_at(const cbae_vector_t *v, size_t idx) {
    if(!v || idx >= v->count) return NULL;
    return (uint8_t *)v->data + idx * v->elem_size;
}

cbae_err_t cbae_vector_resize(cbae_vector_t *v, size_t new_count) {
    if(!v) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null vector");
    CBAE_CHECK(cbae_vector_reserve(v, new_count));
    if(new_count > v->count)
        memset((uint8_t *)v->data + v->count * v->elem_size, 0,
               (new_count - v->count) * v->elem_size);
    v->count = new_count;
    return CBAE_OK;
}

void cbae_vector_clear(cbae_vector_t *v) { if(v) v->count = 0; }

void cbae_vector_sort(cbae_vector_t *v, cbae_compare_fn cmp) {
    if(v && v->count > 1) qsort(v->data, v->count, v->elem_size, cmp);
}

void *cbae_vector_bsearch(const cbae_vector_t *v, const void *key, cbae_compare_fn cmp) {
    if(!v || !v->count) return NULL;
    return bsearch(key, v->data, v->count, v->elem_size, cmp);
}
