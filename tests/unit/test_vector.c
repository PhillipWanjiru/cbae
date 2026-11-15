/**
 * @file test_vector.c
 * @brief Unit tests for the growable array (audit A-040): every size computation is checked, a push of an
 *        element that lives in the vector itself is safe, a vector that was never initialised is refused,
 *        and an allocation failure changes nothing.
 */
#include "alloc_inject.h"
#include "oom_sweep.h"
#include "platform/vector.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PASS(name) printf("  [PASS] %s\n", name)

static int cmp_int(const void *a, const void *b) {
    const int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

static void test_basics(void) {
    cbae_vector_t v;
    assert(cbae_vector_init(&v, sizeof(int), 4) == CBAE_OK);
    assert(v.capacity == 4 && v.count == 0 && v.elem_size == sizeof(int));
    for (int i = 0; i < 100; i++) assert(CBAE_VEC_PUSH(&v, int, i) == CBAE_OK);
    assert(cbae_vector_count(&v) == 100);
    for (size_t i = 0; i < 100; i++) assert(CBAE_VEC_AT(&v, int, i) == (int)i);
    assert(cbae_vector_at(&v, 100) == NULL && cbae_vector_at(&v, SIZE_MAX) == NULL);
    int out = -1;
    assert(cbae_vector_pop(&v, &out) == CBAE_OK && out == 99 && cbae_vector_count(&v) == 99);
    assert(cbae_vector_pop(&v, NULL) == CBAE_OK && cbae_vector_count(&v) == 98);
    cbae_vector_clear(&v);
    assert(cbae_vector_count(&v) == 0 && v.capacity >= 100);
    assert(cbae_vector_pop(&v, &out) == CBAE_ERR_NOT_FOUND);
    cbae_vector_destroy(&v);
    assert(v.data == NULL && v.count == 0 && v.capacity == 0 && v.elem_size == 0);
    cbae_vector_destroy(&v);                                       /* twice is fine */
    cbae_vector_destroy(NULL);
    cbae_vector_clear(NULL);
    PASS("init, push, at, pop, clear, destroy (twice)");
}

static void test_growth(void) {
    cbae_vector_t v;
    assert(cbae_vector_init(&v, sizeof(uint64_t), 0) == CBAE_OK);
    assert(v.capacity == 8);                                       /* 0 asks for the default */
    size_t grew = 0, prev = v.capacity;
    for (uint64_t i = 0; i < 100000; i++) {
        assert(cbae_vector_push(&v, &i) == CBAE_OK);
        if (v.capacity != prev) { assert(v.capacity == prev * 2); prev = v.capacity; grew++; }
    }
    assert(grew == 14 && v.capacity == 131072);                    /* 8 -> 131072 by doubling */
    for (uint64_t i = 0; i < 100000; i++) assert(CBAE_VEC_AT(&v, uint64_t, i) == i);
    assert(cbae_vector_reserve(&v, 10) == CBAE_OK && v.capacity == 131072);   /* never shrinks */
    assert(cbae_vector_reserve(&v, 131073) == CBAE_OK && v.capacity == 262144);
    cbae_vector_destroy(&v);
    PASS("capacity doubles, contents survive 14 reallocations, reserve never shrinks");
}

static void test_push_of_own_element(void) {
    /* The element pointer points into the block a push is about to move. */
    cbae_vector_t v;
    assert(cbae_vector_init(&v, sizeof(int), 2) == CBAE_OK);
    int a = 7, b = 9;
    assert(cbae_vector_push(&v, &a) == CBAE_OK && cbae_vector_push(&v, &b) == CBAE_OK);
    for (int round = 0; round < 12; round++) {
        const size_t n = v.count;
        assert(v.count == v.capacity);                             /* the next push must grow */
        assert(cbae_vector_push(&v, cbae_vector_at(&v, 0)) == CBAE_OK);
        assert(v.count == n + 1 && CBAE_VEC_AT(&v, int, n) == 7);
        while (v.count < v.capacity) assert(CBAE_VEC_PUSH(&v, int, 1000 + (int)v.count) == CBAE_OK);
        assert(cbae_vector_push(&v, cbae_vector_at(&v, v.count - 1)) == CBAE_OK);
        assert(CBAE_VEC_AT(&v, int, v.count - 1) == CBAE_VEC_AT(&v, int, v.count - 2));
        while (v.count < v.capacity) assert(CBAE_VEC_PUSH(&v, int, 1) == CBAE_OK);
    }
    assert(CBAE_VEC_AT(&v, int, 0) == 7 && CBAE_VEC_AT(&v, int, 1) == 9);
    cbae_vector_destroy(&v);
    PASS("pushing an element that is in the vector itself, when the push moves the block");
}

static void test_overflow(void) {
    cbae_vector_t v;
    memset(&v, 0xFF, sizeof v);
    assert(cbae_vector_init(&v, 1u << 20, SIZE_MAX / (1u << 20) + 1) == CBAE_ERR_OVERFLOW);
    assert(v.data == NULL && v.elem_size == 0 && v.count == 0 && v.capacity == 0);
    assert(cbae_vector_init(&v, SIZE_MAX, 2) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_init(&v, (size_t)PTRDIFF_MAX + 1, 1) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_init(&v, 8, SIZE_MAX) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_init(&v, 0, 4) == CBAE_ERR_INVALID && v.elem_size == 0);
    assert(cbae_vector_init(NULL, 4, 4) == CBAE_ERR_INVALID);

    assert(cbae_vector_init(&v, sizeof(int), 4) == CBAE_OK);
    int x = 5;
    assert(cbae_vector_push(&v, &x) == CBAE_OK);
    /* asking for more elements than can be addressed: refused at once (a doubling loop would never end) */
    assert(cbae_vector_reserve(&v, SIZE_MAX) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_reserve(&v, SIZE_MAX / 2 + 1) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_reserve(&v, SIZE_MAX / sizeof(int) + 1) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_reserve(&v, (size_t)PTRDIFF_MAX / sizeof(int) + 1) == CBAE_ERR_OVERFLOW);
    assert(cbae_vector_resize(&v, SIZE_MAX) == CBAE_ERR_OVERFLOW);
    /* a request that fits but cannot be had is an out-of-memory error, not an overflow */
    ai_reset();
    ai_fail_from(1);
    assert(cbae_vector_reserve(&v, 1000) == CBAE_ERR_OOM);
    assert(cbae_vector_resize(&v, 1000) == CBAE_ERR_OOM);
    ai_disarm();
    assert(v.count == 1 && v.capacity == 4 && CBAE_VEC_AT(&v, int, 0) == 5);   /* nothing changed */
    cbae_vector_destroy(&v);
    PASS("sizes that do not fit are refused with CBAE_ERR_OVERFLOW; the vector is unchanged; init leaves *v zero");
}

static void test_uninitialised(void) {
    cbae_vector_t z;
    memset(&z, 0, sizeof z);
    int x = 1;
    assert(cbae_vector_push(&z, &x) == CBAE_ERR_INVALID);
    assert(cbae_vector_reserve(&z, 4) == CBAE_ERR_INVALID);
    assert(cbae_vector_resize(&z, 4) == CBAE_ERR_INVALID);
    assert(cbae_vector_at(&z, 0) == NULL);
    assert(cbae_vector_pop(&z, &x) == CBAE_ERR_NOT_FOUND);
    assert(cbae_vector_bsearch(&z, &x, cmp_int) == NULL);
    cbae_vector_destroy(&z);

    assert(cbae_vector_push(NULL, &x) == CBAE_ERR_INVALID);
    assert(cbae_vector_pop(NULL, &x) == CBAE_ERR_INVALID);
    assert(cbae_vector_at(NULL, 0) == NULL);
    assert(cbae_vector_reserve(NULL, 1) == CBAE_ERR_INVALID);
    assert(cbae_vector_resize(NULL, 1) == CBAE_ERR_INVALID);
    assert(cbae_vector_sort(NULL, cmp_int) == CBAE_ERR_INVALID);
    assert(cbae_vector_bsearch(NULL, &x, cmp_int) == NULL);

    cbae_vector_t v;
    assert(cbae_vector_init(&v, sizeof(int), 4) == CBAE_OK);
    assert(cbae_vector_push(&v, NULL) == CBAE_ERR_INVALID && v.count == 0);
    assert(cbae_vector_sort(&v, NULL) == CBAE_ERR_INVALID);
    assert(cbae_vector_bsearch(&v, &x, NULL) == NULL);
    cbae_vector_destroy(&v);
    PASS("a zeroed vector, NULL vectors, NULL elements and NULL comparators are refused, never dereferenced");
}

static void test_resize_sort_search(void) {
    cbae_vector_t v;
    assert(cbae_vector_init(&v, sizeof(int), 4) == CBAE_OK);
    for (int i = 0; i < 40; i++) assert(CBAE_VEC_PUSH(&v, int, 40 - i) == CBAE_OK);
    assert(cbae_vector_sort(&v, cmp_int) == CBAE_OK);
    for (int i = 0; i < 40; i++) assert(CBAE_VEC_AT(&v, int, (size_t)i) == i + 1);
    for (int key = 1; key <= 40; key++) {
        int *f = cbae_vector_bsearch(&v, &key, cmp_int);
        assert(f && *f == key && f == cbae_vector_at(&v, (size_t)key - 1));
    }
    int absent = 41;
    assert(cbae_vector_bsearch(&v, &absent, cmp_int) == NULL);

    /* shrinking and growing again: what grows in is zero, not what was there before */
    memset(v.data, 0xAB, v.count * sizeof(int));
    assert(cbae_vector_resize(&v, 10) == CBAE_OK && v.count == 10);
    assert(cbae_vector_resize(&v, 60) == CBAE_OK && v.count == 60);
    for (size_t i = 0; i < 10; i++) assert(CBAE_VEC_AT(&v, int, i) == (int)0xABABABAB);
    for (size_t i = 10; i < 60; i++) assert(CBAE_VEC_AT(&v, int, i) == 0);
    assert(cbae_vector_resize(&v, 0) == CBAE_OK && v.count == 0);
    assert(cbae_vector_sort(&v, cmp_int) == CBAE_OK);              /* empty and one-element sorts are fine */
    cbae_vector_destroy(&v);
    PASS("sort, bsearch, resize shrinks and grows with zeroes");
}

/* ---- allocation failure ---- */

typedef struct { int pushes; } oom_ctx_t;

static cbae_err_t oom_body(void *c, uint64_t failing) {
    (void)failing;
    const oom_ctx_t *ctx = (const oom_ctx_t *)c;
    cbae_vector_t v;
    memset(&v, 0xEE, sizeof v);
    cbae_err_t rc = cbae_vector_init(&v, sizeof(int), 2);
    if (rc != CBAE_OK) {
        assert(v.data == NULL && v.elem_size == 0 && v.count == 0 && v.capacity == 0);   /* the documented empty state */
        cbae_vector_destroy(&v);
        return rc;
    }
    for (int i = 0; i < ctx->pushes; i++) {
        const size_t count = v.count, cap = v.capacity;
        rc = CBAE_VEC_PUSH(&v, int, i * 3);
        if (rc != CBAE_OK) {
            assert(v.count == count && v.capacity == cap);         /* a failed push changes nothing ... */
            for (size_t k = 0; k < count; k++) assert(CBAE_VEC_AT(&v, int, k) == (int)k * 3);   /* ... and loses nothing */
            cbae_vector_destroy(&v);
            return rc;
        }
    }
    rc = cbae_vector_reserve(&v, (size_t)ctx->pushes * 4);
    if (rc == CBAE_OK) rc = cbae_vector_resize(&v, (size_t)ctx->pushes * 3);
    if (rc != CBAE_OK) {
        assert(v.count == (size_t)ctx->pushes);
        for (size_t k = 0; k < v.count; k++) assert(CBAE_VEC_AT(&v, int, k) == (int)k * 3);
    } else {
        for (size_t k = 0; k < (size_t)ctx->pushes; k++) assert(CBAE_VEC_AT(&v, int, k) == (int)k * 3);
        for (size_t k = (size_t)ctx->pushes; k < v.count; k++) assert(CBAE_VEC_AT(&v, int, k) == 0);
    }
    cbae_vector_destroy(&v);
    return rc;
}

static void test_allocation_failure(void) {
    oom_ctx_t ctx = { 50 };
    const oom_report_t r = oom_sweep(oom_body, &ctx, true);
    assert(r.allocations >= 6 && r.runs == 2 * r.allocations && r.reported > 0 && r.swallowed == 0);
    PASS("an allocation failure in init, push, reserve or resize is reported, changes nothing and loses nothing");
}

int main(void) {
    printf("=== test_vector ===\n");
    test_basics();
    test_growth();
    test_push_of_own_element();
    test_overflow();
    test_uninitialised();
    test_resize_sort_search();
    test_allocation_failure();
    printf("All vector tests passed.\n");
    return 0;
}
