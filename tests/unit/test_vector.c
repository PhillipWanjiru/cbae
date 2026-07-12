/**
 * @file test_vector.c
 * @brief Unit tests for the growable dynamic array.
 */
#include "platform/vector.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

int main(void) {
    printf("=== test_vector ===\n");
    cbae_vector_t v;
    assert(cbae_vector_init(&v, sizeof(int), 4) == CBAE_OK);
    for(int i = 0; i < 100; i++) CBAE_VEC_PUSH(&v, int, i);
    assert(cbae_vector_count(&v) == 100);
    printf("  [PASS] push 100 elements\n");
    for(size_t i = 0; i < 100; i++) assert(CBAE_VEC_AT(&v, int, i) == (int)i);
    printf("  [PASS] at() correctness\n");
    int out;
    assert(cbae_vector_pop(&v, &out) == CBAE_OK);
    assert(out == 99 && cbae_vector_count(&v) == 99);
    printf("  [PASS] pop\n");
    cbae_vector_sort(&v, cmp_int);
    int key = 50;
    int *found = (int *)cbae_vector_bsearch(&v, &key, cmp_int);
    assert(found && *found == 50);
    printf("  [PASS] sort + bsearch\n");
    cbae_vector_resize(&v, 10);
    assert(cbae_vector_count(&v) == 10);
    printf("  [PASS] resize shrink\n");
    cbae_vector_destroy(&v);
    printf("All vector tests passed.\n");
    return 0;
}
