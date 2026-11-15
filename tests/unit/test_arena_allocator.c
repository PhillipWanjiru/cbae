/**
 * @file test_arena_allocator.c
 * @brief Unit tests for the arena and pool allocators.
 */
#include "platform/memory.h"
#include <assert.h>
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
    test_pool();
    printf("All arena tests passed.\n");
    return 0;
}
