/**
 * @file test_arena_allocator.c
 * @brief Unit tests for the arena and pool allocators.
 */
#include "platform/memory.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_bump_alloc(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 4096) == CBAE_OK);
    void *p1 = cbae_arena_alloc(&a, 64, 8);
    void *p2 = cbae_arena_alloc(&a, 128, 8);
    void *p3 = cbae_arena_alloc(&a, 32, 8);
    assert(p1 && p2 && p3);
    assert(p1 != p2 && p2 != p3);
    cbae_arena_destroy(&a);
    printf("  [PASS] bump alloc\n");
}

static void test_alignment(void) {
    cbae_arena_t a;
    cbae_arena_init(&a, 4096);
    cbae_arena_alloc(&a, 1, 1);
    void *p = cbae_arena_alloc(&a, 8, 8);
    assert(((uintptr_t)p & 7) == 0);
    cbae_arena_destroy(&a);
    printf("  [PASS] alignment\n");
}

static void test_reset(void) {
    cbae_arena_t a;
    cbae_arena_init(&a, 4096);
    cbae_arena_alloc(&a, 512, 8);
    assert(cbae_arena_used(&a) >= 512);
    cbae_arena_reset(&a);
    assert(cbae_arena_used(&a) == 0);
    void *p = cbae_arena_alloc(&a, 512, 8);
    assert(p != NULL);
    cbae_arena_destroy(&a);
    printf("  [PASS] reset\n");
}

static void test_overflow(void) {
    cbae_arena_t a;
    cbae_arena_init(&a, 64);
    void *p = cbae_arena_alloc(&a, 128, 1);
    assert(p == NULL);
    cbae_arena_destroy(&a);
    printf("  [PASS] overflow returns NULL\n");
}

/* ---- Phase 4.5 (audit A-035): requests the old arena mishandled ---- */

static void test_zero_size(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 256) == CBAE_OK);
    void *p = cbae_arena_alloc(&a, 3, 1);
    assert(p);
    const size_t used = cbae_arena_used(&a);
    void *z = cbae_arena_alloc(&a, 0, 8);
    assert(z != NULL);                              /* "nothing" is not "out of memory" */
    assert(cbae_arena_used(&a) == used);            /* and costs nothing */
    void *zn = CBAE_ARENA_ALLOC_N(&a, uint64_t, 0);
    assert(zn != NULL && cbae_arena_used(&a) == used);
    cbae_arena_destroy(&a);
    printf("  [PASS] a request for zero bytes succeeds and uses no space\n");
}

static void test_huge_requests(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 4096) == CBAE_OK);
    assert(cbae_arena_alloc(&a, 8, 8));
    const size_t used = cbae_arena_used(&a);
    /* sizes whose sum with the position wraps around size_t: the old check computed aligned + size and
     * compared that, so these passed it and the arena then wrote SIZE_MAX bytes */
    static const size_t huge[] = { SIZE_MAX, SIZE_MAX - 1, SIZE_MAX - 7, SIZE_MAX - 8, SIZE_MAX / 2 + 1, (size_t)1 << 63, 4096 };
    for (size_t i = 0; i < sizeof huge / sizeof huge[0]; i++) {
        cbae_error_clear();
        assert(cbae_arena_alloc(&a, huge[i], 8) == NULL);
        assert(cbae_error_get_context()->code == CBAE_ERR_OOM);
        assert(cbae_arena_used(&a) == used);        /* a failed request changes nothing */
    }
    assert(cbae_arena_alloc(&a, 4096 - used, 1));   /* and what really fits still fits */
    assert(cbae_arena_remaining(&a) == 0);
    assert(cbae_arena_alloc(&a, 1, 1) == NULL);
    cbae_arena_destroy(&a);
    printf("  [PASS] sizes that wrap size_t are refused, the arena is unchanged\n");
}

static void test_array_overflow(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 4096) == CBAE_OK);
    /* 8 * n wraps to 16: the old macro handed out 16 bytes for "n entries" and the caller wrote n */
    cbae_error_clear();
    assert(CBAE_ARENA_ALLOC_N(&a, uint64_t, SIZE_MAX / 8 + 3) == NULL);
    assert(cbae_error_get_context()->code == CBAE_ERR_OVERFLOW);
    assert(cbae_arena_used(&a) == 0);
    assert(cbae_arena_alloc_array(&a, SIZE_MAX, 2, 1) == NULL);
    uint32_t *ok = CBAE_ARENA_ALLOC_N(&a, uint32_t, 100);
    assert(ok && cbae_arena_used(&a) == 400);
    for (int i = 0; i < 100; i++) assert(ok[i] == 0);
    cbae_arena_destroy(&a);
    printf("  [PASS] CBAE_ARENA_ALLOC_N refuses a product that wraps\n");
}

static void test_alignment_of_the_address(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 1 << 16) == CBAE_OK);
    for (size_t align = 1; align <= 4096; align <<= 1) {
        assert(cbae_arena_alloc(&a, 1, 1));         /* knock the position off any alignment */
        void *p = cbae_arena_alloc(&a, 24, align);
        assert(p && ((uintptr_t)p & (align - 1)) == 0);
    }
    cbae_arena_destroy(&a);
    printf("  [PASS] the address, not the offset, is aligned (up to 4096)\n");
}

static void test_bad_alignment(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 256) == CBAE_OK);
    cbae_error_clear();
    assert(cbae_arena_alloc(&a, 8, 3) == NULL && cbae_error_get_context()->code == CBAE_ERR_INVALID);
    assert(cbae_arena_alloc(&a, 8, 24) == NULL);
    assert(cbae_arena_used(&a) == 0);
    assert(cbae_arena_alloc(&a, 8, 0) != NULL);     /* 0 means "no alignment needed" */
    assert(cbae_arena_alloc(NULL, 8, 8) == NULL);
    cbae_arena_destroy(&a);
    printf("  [PASS] an alignment that is not a power of two is refused\n");
}

static void test_zero_filled_after_reset(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 512) == CBAE_OK);
    uint8_t *p = cbae_arena_alloc(&a, 256, 8);
    assert(p);
    memset(p, 0xAB, 256);
    cbae_arena_reset(&a);
    uint8_t *q = cbae_arena_alloc(&a, 256, 8);
    assert(q == p);
    for (int i = 0; i < 256; i++) assert(q[i] == 0);
    cbae_arena_destroy(&a);
    printf("  [PASS] memory handed out again after a reset is zero\n");
}

static void test_exact_fit_and_pad_accounting(void) {
    cbae_arena_t a;
    assert(cbae_arena_init(&a, 100) == CBAE_OK);
    assert(cbae_arena_alloc(&a, 1, 1));
    const size_t before = cbae_arena_used(&a);
    void *p = cbae_arena_alloc(&a, 32, 16);
    assert(p);
    const size_t pad = cbae_arena_used(&a) - before - 32;
    assert(pad < 16 && cbae_arena_used(&a) + cbae_arena_remaining(&a) == 100);
    /* a request that fits only without its padding must fail and must not consume the padding */
    const size_t used = cbae_arena_used(&a);
    const size_t pad64 = (size_t)(0 - ((uintptr_t)a.base + used)) & 63;
    void *big = cbae_arena_alloc(&a, 100 - used, 64);
    if (pad64 == 0) { assert(big && cbae_arena_remaining(&a) == 0); }
    else            { assert(big == NULL && cbae_arena_used(&a) == used); }
    cbae_arena_destroy(&a);
    printf("  [PASS] padding is accounted for exactly\n");
}

static void test_pool(void) {
    cbae_arena_t a;
    cbae_arena_init(&a, 8192);
    cbae_pool_t pool;
    assert(cbae_pool_init(&pool, &a, 32, 8) == CBAE_OK);
    void *x = cbae_pool_alloc(&pool);
    void *y = cbae_pool_alloc(&pool);
    assert(x && y && x != y);
    cbae_pool_free(&pool, x);
    void *z = cbae_pool_alloc(&pool);
    assert(z == x);
    cbae_arena_destroy(&a);
    printf("  [PASS] pool alloc/free recycle\n");
}

int main(void) {
    printf("=== test_arena_allocator ===\n");
    test_bump_alloc();
    test_alignment();
    test_reset();
    test_overflow();
    test_zero_size();
    test_huge_requests();
    test_array_overflow();
    test_alignment_of_the_address();
    test_bad_alignment();
    test_zero_filled_after_reset();
    test_exact_fit_and_pad_accounting();
    test_pool();
    printf("All arena tests passed.\n");
    return 0;
}
