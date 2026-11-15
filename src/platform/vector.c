/**
 * @file vector.c
 * @brief Growable array: doubling growth, every size computation checked for overflow.
 */
#include "platform/vector.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VEC_INIT_CAP  8
#define VEC_MAX_BYTES ((size_t)PTRDIFF_MAX)     /* what malloc can be asked for, and what pointer arithmetic can span */

#define VEC_REQUIRE_INIT(v) \
    do { if (!(v)) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null vector"); \
         if (!(v)->elem_size) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "vector is not initialised"); } while (0)

cbae_err_t cbae_vector_init(cbae_vector_t *v, size_t elem_size, size_t initial_cap) {
    if (!v) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null vector");
    memset(v, 0, sizeof *v);
    if (!elem_size) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "vector element size is 0");
    if (!initial_cap) initial_cap = VEC_INIT_CAP;
    if (initial_cap > VEC_MAX_BYTES / elem_size)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a vector of %zu elements of %zu bytes is too large", initial_cap, elem_size);
    void *p = malloc(initial_cap * elem_size);
    if (!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "vector allocation of %zu bytes failed", initial_cap * elem_size);
    v->data      = p;
    v->elem_size = elem_size;
    v->capacity  = initial_cap;
    return CBAE_OK;
}

void cbae_vector_destroy(cbae_vector_t *v) {
    if (!v) return;
    free(v->data);
    memset(v, 0, sizeof *v);
}

cbae_err_t cbae_vector_reserve(cbae_vector_t *v, size_t min_cap) {
    VEC_REQUIRE_INIT(v);
    if (v->capacity >= min_cap) return CBAE_OK;
    const size_t limit = VEC_MAX_BYTES / v->elem_size;
    if (min_cap > limit)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a vector of %zu elements of %zu bytes is too large", min_cap, v->elem_size);
    size_t cap = v->capacity ? v->capacity : VEC_INIT_CAP;
    while (cap < min_cap) cap = cap > limit / 2 ? limit : cap * 2;      /* double, but never past what fits */
    void *p = realloc(v->data, cap * v->elem_size);
    if (!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "vector reallocation to %zu bytes failed", cap * v->elem_size);
    v->data     = p;
    v->capacity = cap;
    return CBAE_OK;
}

cbae_err_t cbae_vector_push(cbae_vector_t *v, const void *elem) {
    VEC_REQUIRE_INIT(v);
    if (!elem) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null element");
    if (v->count == v->capacity) {
        /* The element may live in this very block, which growing can move: note where in it, then find it again. */
        const uintptr_t lo = (uintptr_t)v->data, at = (uintptr_t)elem;
        const bool inside = at >= lo && at - lo < v->capacity * v->elem_size;
        const size_t off = inside ? (size_t)(at - lo) : 0;
        CBAE_CHECK(cbae_vector_reserve(v, v->count + 1));
        if (inside) elem = (const uint8_t *)v->data + off;
    }
    memcpy((uint8_t *)v->data + v->count * v->elem_size, elem, v->elem_size);
    v->count++;
    return CBAE_OK;
}

cbae_err_t cbae_vector_pop(cbae_vector_t *v, void *out) {
    if (!v) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null vector");
    if (!v->count) CBAE_RETURN_ERR(CBAE_ERR_NOT_FOUND, "vector is empty");
    v->count--;
    if (out) memcpy(out, (uint8_t *)v->data + v->count * v->elem_size, v->elem_size);
    return CBAE_OK;
}

void *cbae_vector_at(const cbae_vector_t *v, size_t idx) {
    if (!v || idx >= v->count) return NULL;
    return (uint8_t *)v->data + idx * v->elem_size;
}

cbae_err_t cbae_vector_resize(cbae_vector_t *v, size_t new_count) {
    VEC_REQUIRE_INIT(v);
    CBAE_CHECK(cbae_vector_reserve(v, new_count));
    if (new_count > v->count)
        memset((uint8_t *)v->data + v->count * v->elem_size, 0, (new_count - v->count) * v->elem_size);
    v->count = new_count;
    return CBAE_OK;
}

void cbae_vector_clear(cbae_vector_t *v) { if (v) v->count = 0; }

cbae_err_t cbae_vector_sort(cbae_vector_t *v, cbae_compare_fn cmp) {
    if (!v || !cmp) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null vector or comparator");
    if (v->count > 1) qsort(v->data, v->count, v->elem_size, cmp);
    return CBAE_OK;
}

void *cbae_vector_bsearch(const cbae_vector_t *v, const void *key, cbae_compare_fn cmp) {
    if (!v || !key || !cmp || !v->count) return NULL;
    return bsearch(key, v->data, v->count, v->elem_size, cmp);
}
