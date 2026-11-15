/**
 * @file test_hashmap.c
 * @brief Unit tests for the Robin Hood hashmap (audit A-041): a map of all zero bytes is a valid empty map,
 *        sizes cannot overflow, the table is checked against a reference model through every kind of churn,
 *        and an allocation failure changes nothing.
 */
#include "alloc_inject.h"
#include "oom_sweep.h"
#include "platform/hashmap.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(name) printf("  [PASS] %s\n", name)

/* What a Robin Hood table with backward-shift deletion must look like, read off its public fields: no entry
 * is further from home than the run of entries before it allows (so a lookup that stops at the first slot that
 * is empty or closer to home than the probe is right), the count is the number of occupied slots, and the
 * table is never more than 70% full. */
static void check_table(const cbae_hashmap_t *m) {
    if (!m->capacity) { assert(m->entries == NULL && m->count == 0); return; }
    assert((m->capacity & (m->capacity - 1)) == 0 && m->capacity >= 16);
    size_t n = 0;
    for (size_t i = 0; i < m->capacity; i++) {
        const cbae_hashmap_entry_t *e = &m->entries[i];
        if (!e->occupied) { assert(e->probe_dist == 0 && e->key == 0 && e->value == NULL); continue; }
        n++;
        if (e->probe_dist) {
            const cbae_hashmap_entry_t *prev = &m->entries[(i + m->capacity - 1) & (m->capacity - 1)];
            assert(prev->occupied && prev->probe_dist + 1 >= e->probe_dist);
        }
    }
    assert(n == m->count);
    assert(m->count * 10 <= m->capacity * 7);
}

static void test_basic_insert_get(void) {
    cbae_hashmap_t m;
    assert(cbae_hashmap_init(&m, 8) == CBAE_OK);
    assert(cbae_hashmap_capacity(&m) == 16 && cbae_hashmap_count(&m) == 0);
    void *v;
    assert(cbae_hashmap_insert(&m, 0xDEAD, (void *)1) == CBAE_OK);
    assert(cbae_hashmap_insert(&m, 0xBEEF, (void *)2) == CBAE_OK);
    assert(cbae_hashmap_get(&m, 0xDEAD, &v) && v == (void *)1);
    assert(cbae_hashmap_get(&m, 0xBEEF, &v) && v == (void *)2);
    assert(!cbae_hashmap_get(&m, 0xCAFE, NULL));
    assert(cbae_hashmap_get(&m, 0xDEAD, NULL) && cbae_hashmap_contains(&m, 0xBEEF));
    assert(cbae_hashmap_count(&m) == 2);
    check_table(&m);
    cbae_hashmap_destroy(&m);
    PASS("basic insert/get");
}

static void test_keys_and_values(void) {
    cbae_hashmap_t m;
    assert(cbae_hashmap_init(&m, 0) == CBAE_OK);
    const uint64_t keys[] = { 0, 1, UINT64_MAX, UINT64_MAX - 1, UINT64_C(1) << 63, UINT64_C(0x8000000000000001) };
    for (size_t i = 0; i < 6; i++) assert(cbae_hashmap_insert(&m, keys[i], i % 2 ? (void *)(uintptr_t)(i + 1) : NULL) == CBAE_OK);
    for (size_t i = 0; i < 6; i++) {
        void *v = (void *)0x1234;
        assert(cbae_hashmap_get(&m, keys[i], &v));
        assert(v == (i % 2 ? (void *)(uintptr_t)(i + 1) : NULL));  /* a NULL value is a value: the key is there */
    }
    assert(cbae_hashmap_count(&m) == 6);
    assert(cbae_hashmap_remove(&m, 0) && !cbae_hashmap_contains(&m, 0) && cbae_hashmap_contains(&m, 1));
    check_table(&m);
    cbae_hashmap_destroy(&m);
    PASS("keys 0 and UINT64_MAX, NULL values");
}

static void test_update_and_remove(void) {
    cbae_hashmap_t m;
    cbae_hashmap_init(&m, 4);
    cbae_hashmap_insert(&m, 42, (void *)100);
    cbae_hashmap_insert(&m, 42, (void *)200);
    void *v;
    assert(cbae_hashmap_get(&m, 42, &v) && v == (void *)200 && cbae_hashmap_count(&m) == 1);
    for (uint64_t i = 0; i < 10; i++) cbae_hashmap_insert(&m, i, (void *)(uintptr_t)(i + 1));
    assert(cbae_hashmap_remove(&m, 5));
    assert(!cbae_hashmap_remove(&m, 5) && !cbae_hashmap_contains(&m, 5));
    assert(cbae_hashmap_count(&m) == 10);                          /* 42 and 0..9 without 5 */
    assert(cbae_hashmap_get(&m, 6, &v) && v == (void *)7);
    check_table(&m);
    cbae_hashmap_destroy(&m);
    PASS("update an existing key, remove (twice)");
}

static void test_growth_rule(void) {
    /* 16 slots, at most 70% full: 11 entries fit (11/16 = 68.75%), the 12th doubles the table */
    cbae_hashmap_t m;
    assert(cbae_hashmap_init(&m, 16) == CBAE_OK);
    for (uint64_t i = 0; i < 11; i++) assert(cbae_hashmap_insert(&m, i, (void *)1) == CBAE_OK);
    assert(m.capacity == 16);
    /* a key that is already there needs no room, even at the limit */
    assert(cbae_hashmap_insert(&m, 7, (void *)2) == CBAE_OK && m.capacity == 16 && m.count == 11);
    assert(cbae_hashmap_insert(&m, 11, (void *)1) == CBAE_OK);
    assert(m.capacity == 32 && m.count == 12);
    for (uint64_t i = 0; i < 12; i++) assert(cbae_hashmap_contains(&m, i));
    assert(cbae_hashmap_load(&m) > 0.37f && cbae_hashmap_load(&m) < 0.38f);
    check_table(&m);
    cbae_hashmap_destroy(&m);

    /* capacity rounding */
    static const struct { size_t ask, got; } T[] = { { 0, 16 }, { 1, 16 }, { 16, 16 }, { 17, 32 }, { 1000, 1024 }, { 1024, 1024 }, { 1025, 2048 } };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        assert(cbae_hashmap_init(&m, T[i].ask) == CBAE_OK && m.capacity == T[i].got);
        cbae_hashmap_destroy(&m);
    }
    PASS("a table is 70% full at most: the 12th entry of 16 slots doubles it; capacities round up to a power of two");
}

static void test_zeroed_and_destroyed(void) {
    cbae_hashmap_t z;
    memset(&z, 0, sizeof z);
    void *v = (void *)5;
    assert(!cbae_hashmap_get(&z, 0, &v) && v == (void *)5);        /* nothing found, *out untouched */
    assert(!cbae_hashmap_get(&z, 12345, NULL) && !cbae_hashmap_contains(&z, 1) && !cbae_hashmap_remove(&z, 1));
    assert(cbae_hashmap_count(&z) == 0 && cbae_hashmap_capacity(&z) == 0 && cbae_hashmap_load(&z) == 0.f);
    cbae_hashmap_clear(&z);
    cbae_hashmap_foreach(&z, (cbae_hashmap_iter_fn)abort, NULL);   /* must not call anything */
    check_table(&z);
    assert(cbae_hashmap_insert(&z, 9, (void *)9) == CBAE_OK);      /* the first insert allocates */
    assert(z.capacity == 16 && cbae_hashmap_get(&z, 9, &v) && v == (void *)9);
    check_table(&z);
    cbae_hashmap_destroy(&z);
    assert(z.entries == NULL && z.capacity == 0 && z.count == 0);
    assert(!cbae_hashmap_get(&z, 9, &v));                          /* a destroyed map is an empty map */
    cbae_hashmap_destroy(&z);                                      /* twice is fine */
    cbae_hashmap_destroy(NULL);
    cbae_hashmap_clear(NULL);
    assert(cbae_hashmap_init(NULL, 4) == CBAE_ERR_INVALID && cbae_hashmap_insert(NULL, 1, NULL) == CBAE_ERR_INVALID);
    assert(!cbae_hashmap_get(NULL, 1, &v) && !cbae_hashmap_contains(NULL, 1) && !cbae_hashmap_remove(NULL, 1));
    assert(cbae_hashmap_count(NULL) == 0 && cbae_hashmap_capacity(NULL) == 0 && cbae_hashmap_load(NULL) == 0.f);
    cbae_hashmap_foreach(NULL, NULL, NULL);
    PASS("a zeroed or destroyed map is an empty map: lookups find nothing, the first insert allocates, NULL is refused");
}

static void test_sizes(void) {
    cbae_hashmap_t m;
    memset(&m, 0xFF, sizeof m);
    assert(cbae_hashmap_init(&m, SIZE_MAX) == CBAE_ERR_OVERFLOW);  /* the doubling loop ends */
    assert(m.entries == NULL && m.capacity == 0 && m.count == 0);
    assert(cbae_hashmap_init(&m, SIZE_MAX / 2 + 1) == CBAE_ERR_OVERFLOW);
    assert(cbae_hashmap_init(&m, (size_t)PTRDIFF_MAX / sizeof(cbae_hashmap_entry_t) + 1) == CBAE_ERR_OVERFLOW);
    assert(cbae_hashmap_init(&m, (size_t)1 << 62) == CBAE_ERR_OVERFLOW);
    /* allocation failure: the map is left all zero, so destroy is safe whatever it held before */
    memset(&m, 0xFF, sizeof m);
    ai_reset();
    ai_fail_from(1);
    assert(cbae_hashmap_init(&m, 100) == CBAE_ERR_OOM);
    ai_disarm();
    assert(m.entries == NULL && m.capacity == 0 && m.count == 0);
    cbae_hashmap_destroy(&m);
    PASS("sizes that cannot be addressed are refused (no endless doubling); a failed init leaves the map zero");
}

/* ---- against a reference model ---- */

typedef struct { uint64_t key; uintptr_t value; bool present; } ref_t;

static uint64_t rng_state = UINT64_C(0x9E3779B97F4A7C15);
static uint64_t rnd(void) {
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return rng_state;
}

static void check_against(const cbae_hashmap_t *m, const ref_t *ref, size_t nref) {
    size_t present = 0;
    for (size_t i = 0; i < nref; i++) {
        void *v = NULL;
        const bool found = cbae_hashmap_get(m, ref[i].key, &v);
        assert(found == ref[i].present);
        if (found) { assert((uintptr_t)v == ref[i].value); present++; }
        assert(cbae_hashmap_contains(m, ref[i].key) == ref[i].present);
    }
    assert(cbae_hashmap_count(m) == present);
    check_table(m);
}

static void test_against_reference(void) {
    /* Small key spaces make every operation collide with the others: runs form, break up, shift back. */
    static const size_t spaces[] = { 24, 200, 3000 };
    for (size_t s = 0; s < sizeof spaces / sizeof spaces[0]; s++) {
        const size_t nkeys = spaces[s];
        ref_t *ref = (ref_t *)calloc(nkeys, sizeof *ref);
        assert(ref);
        for (size_t i = 0; i < nkeys; i++) ref[i].key = s == 0 ? i : (rnd() & ((s == 1) ? 0xFFF : UINT64_MAX));
        for (size_t i = 0; i < nkeys; i++)                         /* keep the keys distinct */
            for (size_t j = 0; j < i; j++) if (ref[j].key == ref[i].key) { ref[i].key = rnd(); j = (size_t)-1; }
        cbae_hashmap_t m;
        assert(cbae_hashmap_init(&m, 0) == CBAE_OK);
        for (int step = 0; step < 60000; step++) {
            ref_t *r = &ref[rnd() % nkeys];
            switch (rnd() % 5) {
            case 0: case 1: {
                const uintptr_t val = (uintptr_t)(rnd() | 1);
                assert(cbae_hashmap_insert(&m, r->key, (void *)val) == CBAE_OK);
                r->present = true; r->value = val;
                assert(m.count * 10 <= m.capacity * 7);
                break; }
            case 2: case 3:
                assert(cbae_hashmap_remove(&m, r->key) == r->present);
                r->present = false;
                break;
            default: {
                void *v = NULL;
                assert(cbae_hashmap_get(&m, r->key, &v) == r->present);
                if (r->present) assert((uintptr_t)v == r->value);
                break; }
            }
            if (step % 997 == 0) check_against(&m, ref, nkeys);
        }
        check_against(&m, ref, nkeys);
        size_t visited = 0;
        cbae_hashmap_foreach(&m, NULL, &visited);                  /* a NULL function visits nothing */
        cbae_hashmap_destroy(&m);
        free(ref);
    }
    PASS("60,000 random operations on each of three key spaces agree with a reference model; the table invariants hold");
}

static void count_cb(uint64_t key, void *value, void *ud) { (void)key; (void)value; (*(size_t *)ud)++; }
static void sum_cb(uint64_t key, void *value, void *ud) { (void)value; *(uint64_t *)ud += key; }

static void test_foreach_and_clear(void) {
    cbae_hashmap_t m;
    assert(cbae_hashmap_init(&m, 0) == CBAE_OK);
    uint64_t want = 0;
    for (uint64_t i = 1; i <= 500; i++) { assert(cbae_hashmap_insert(&m, i * 31, (void *)i) == CBAE_OK); want += i * 31; }
    size_t n = 0; uint64_t sum = 0;
    cbae_hashmap_foreach(&m, count_cb, &n);
    cbae_hashmap_foreach(&m, sum_cb, &sum);
    assert(n == 500 && sum == want);
    const size_t cap = m.capacity;
    cbae_hashmap_clear(&m);
    assert(m.count == 0 && m.capacity == cap && !cbae_hashmap_contains(&m, 31));
    check_table(&m);
    n = 0;
    cbae_hashmap_foreach(&m, count_cb, &n);
    assert(n == 0);
    for (uint64_t i = 1; i <= 100; i++) assert(cbae_hashmap_insert(&m, i, NULL) == CBAE_OK);
    assert(m.count == 100 && m.capacity == cap);
    cbae_hashmap_destroy(&m);
    PASS("foreach visits every entry once; clear keeps the table and forgets the entries");
}

static void test_large(void) {
    cbae_hashmap_t m;
    assert(cbae_hashmap_init(&m, 0) == CBAE_OK);
    const uint64_t N = 1000000;
    for (uint64_t i = 0; i < N; i++) assert(cbae_hashmap_insert(&m, i * 0x1000, (void *)(uintptr_t)(i + 1)) == CBAE_OK);
    assert(m.count == N && m.count * 10 <= m.capacity * 7);
    for (uint64_t i = 0; i < N; i += 7) { void *v; assert(cbae_hashmap_get(&m, i * 0x1000, &v) && v == (void *)(uintptr_t)(i + 1)); }
    for (uint64_t i = 0; i < N; i += 2) assert(cbae_hashmap_remove(&m, i * 0x1000));
    assert(m.count == N / 2);
    for (uint64_t i = 0; i < N; i++) assert(cbae_hashmap_contains(&m, i * 0x1000) == (i % 2 == 1));
    check_table(&m);
    cbae_hashmap_destroy(&m);
    PASS("a million page-aligned keys: insert, look up, remove half");
}

/* ---- allocation failure ---- */

static cbae_err_t oom_body(void *ctx, uint64_t failing) {
    (void)ctx; (void)failing;
    cbae_hashmap_t m;
    memset(&m, 0xEE, sizeof m);
    cbae_err_t rc = cbae_hashmap_init(&m, 16);
    if (rc != CBAE_OK) {
        assert(m.entries == NULL && m.capacity == 0 && m.count == 0);
        cbae_hashmap_destroy(&m);
        return rc;
    }
    for (uint64_t i = 0; i < 100; i++) {                           /* the table doubles at the 12th, 23rd, 45th and 90th entry */
        const size_t count = m.count, cap = m.capacity;
        rc = cbae_hashmap_insert(&m, i * 17, (void *)(uintptr_t)(i + 1));
        if (rc != CBAE_OK) {
            assert(m.count == count && m.capacity == cap);         /* nothing changed ... */
            for (uint64_t k = 0; k < i; k++) {                     /* ... and nothing was lost */
                void *v;
                assert(cbae_hashmap_get(&m, k * 17, &v) && v == (void *)(uintptr_t)(k + 1));
            }
            assert(!cbae_hashmap_contains(&m, i * 17));
            check_table(&m);
            cbae_hashmap_destroy(&m);
            return rc;
        }
    }
    check_table(&m);
    cbae_hashmap_destroy(&m);
    return CBAE_OK;
}

static cbae_err_t oom_lazy_body(void *ctx, uint64_t failing) {
    (void)ctx; (void)failing;
    cbae_hashmap_t m;
    memset(&m, 0, sizeof m);
    const cbae_err_t rc = cbae_hashmap_insert(&m, 5, (void *)5);   /* the first insert allocates the table */
    if (rc != CBAE_OK) assert(m.entries == NULL && m.capacity == 0 && m.count == 0 && !cbae_hashmap_contains(&m, 5));
    else assert(cbae_hashmap_contains(&m, 5));
    cbae_hashmap_destroy(&m);
    return rc;
}

static void test_allocation_failure(void) {
    oom_report_t r = oom_sweep(oom_body, NULL, true);
    assert(r.allocations >= 5 && r.runs == 2 * r.allocations && r.reported > 0 && r.swallowed == 0);
    r = oom_sweep(oom_lazy_body, NULL, true);
    assert(r.allocations == 1 && r.reported == 2 && r.swallowed == 0);
    PASS("an allocation failure in init, in a doubling or in the first insert is reported, changes nothing and loses nothing");
}

int main(void) {
    printf("=== test_hashmap ===\n");
    test_basic_insert_get();
    test_keys_and_values();
    test_update_and_remove();
    test_growth_rule();
    test_zeroed_and_destroyed();
    test_sizes();
    test_against_reference();
    test_foreach_and_clear();
    test_large();
    test_allocation_failure();
    printf("All hashmap tests passed.\n");
    return 0;
}
