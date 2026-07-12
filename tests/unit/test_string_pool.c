/**
 * @file test_string_pool.c
 * @brief Unit tests for the interned string pool.
 */
#include "platform/string_pool.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== test_string_pool ===\n");
    cbae_string_pool_t *pool = NULL;
    assert(cbae_string_pool_init(&pool, 16) == CBAE_OK);
    const char *a = cbae_string_pool_intern(pool, "ExAllocatePool");
    const char *b = cbae_string_pool_intern(pool, "ExAllocatePool");
    assert(a == b);
    printf("  [PASS] deduplication\n");
    const char *c = cbae_string_pool_intern(pool, "request_irq");
    assert(c != a && strcmp(c, "request_irq") == 0);
    printf("  [PASS] distinct strings\n");
    assert(strcmp(a, "ExAllocatePool") == 0);
    printf("  [PASS] content correct\n");
    const char *d = cbae_string_pool_intern_n(pool, "hello world", 5);
    assert(strcmp(d, "hello") == 0);
    printf("  [PASS] intern_n\n");
    for(int i = 0; i < 2000; i++) {
        char buf[32]; snprintf(buf, sizeof(buf), "sym_%04d", i);
        cbae_string_pool_intern(pool, buf);
    }
    assert(strcmp(a, "ExAllocatePool") == 0);
    printf("  [PASS] pointer stability after 2000 more interns\n");
    size_t count = cbae_string_pool_count(pool);
    assert(count >= 2003);
    printf("  [PASS] count = %zu\n", count);
    cbae_string_pool_destroy(pool);
    printf("All string pool tests passed.\n");
    return 0;
}
