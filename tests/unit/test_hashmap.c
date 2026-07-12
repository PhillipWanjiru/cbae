/**
 * @file test_hashmap.c
 * @brief Unit tests for the Robin Hood hashmap.
 */
#include "platform/hashmap.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

static void test_basic_insert_get(void) {
    cbae_hashmap_t m;
    assert(cbae_hashmap_init(&m, 8) == CBAE_OK);
    void *v;
    assert(cbae_hashmap_insert(&m, 0xDEAD, (void *)1) == CBAE_OK);
    assert(cbae_hashmap_insert(&m, 0xBEEF, (void *)2) == CBAE_OK);
    assert(cbae_hashmap_get(&m, 0xDEAD, &v) && v == (void *)1);
    assert(cbae_hashmap_get(&m, 0xBEEF, &v) && v == (void *)2);
    assert(!cbae_hashmap_get(&m, 0xCAFE, NULL));
    assert(cbae_hashmap_count(&m) == 2);
    cbae_hashmap_destroy(&m);
    printf("  [PASS] basic insert/get\n");
}

static void test_update(void) {
    cbae_hashmap_t m;
    cbae_hashmap_init(&m, 4);
    cbae_hashmap_insert(&m, 42, (void *)100);
    cbae_hashmap_insert(&m, 42, (void *)200);
    void *v;
    cbae_hashmap_get(&m, 42, &v);
    assert(v == (void *)200);
    assert(cbae_hashmap_count(&m) == 1);
    cbae_hashmap_destroy(&m);
    printf("  [PASS] update existing key\n");
}

static void test_remove(void) {
    cbae_hashmap_t m;
    cbae_hashmap_init(&m, 8);
    for(uint64_t i = 0; i < 10; i++)
        cbae_hashmap_insert(&m, i, (void *)(uintptr_t)(i+1));
    assert(cbae_hashmap_remove(&m, 5));
    assert(!cbae_hashmap_contains(&m, 5));
    assert(cbae_hashmap_count(&m) == 9);
    void *v;
    assert(cbae_hashmap_get(&m, 6, &v) && v == (void *)7);
    cbae_hashmap_destroy(&m);
    printf("  [PASS] remove\n");
}

static void test_resize(void) {
    cbae_hashmap_t m;
    cbae_hashmap_init(&m, 4);
    for(uint64_t i = 0; i < 1000; i++)
        assert(cbae_hashmap_insert(&m, i*7919, (void *)(uintptr_t)i) == CBAE_OK);
    assert(cbae_hashmap_count(&m) == 1000);
    for(uint64_t i = 0; i < 1000; i++) {
        void *v;
        assert(cbae_hashmap_get(&m, i*7919, &v));
        assert(v == (void *)(uintptr_t)i);
    }
    cbae_hashmap_destroy(&m);
    printf("  [PASS] resize (1000 entries)\n");
}

int main(void) {
    printf("=== test_hashmap ===\n");
    test_basic_insert_get();
    test_update();
    test_remove();
    test_resize();
    printf("All hashmap tests passed.\n");
    return 0;
}
