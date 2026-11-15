/**
 * @file test_string_pool.c
 * @brief Unit tests for the interned string pool and its keyed hash.
 *
 * The defect this file exists for (audit A-031): the old pool kept every string in one block that it
 * realloc'd as it grew, so every pointer handed out earlier dangled once more than 64 KiB had been
 * interned. test_pointer_stability re-reads every pointer after 30,000 interns; under ASan the old
 * pool fails it with heap-use-after-free.
 */
#include "alloc_inject.h"
#include "oom_sweep.h"
#include "platform/siphash.h"
#include "platform/string_pool.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(name) printf("  [PASS] %s\n", name)

static cbae_string_pool_t *new_pool(size_t hint) {
    cbae_string_pool_t *p = NULL;
    assert(cbae_string_pool_init(&p, hint) == CBAE_OK && p);
    return p;
}

/* ── the hash ─────────────────────────────────────────────────────────────── */

static void test_siphash_vectors(void) {
    /* Aumasson & Bernstein's reference vectors for SipHash-2-4: key 00 01 .. 0f, message 00 01 .. (len-1) */
    static const struct { size_t len; uint64_t out; } v[] = {
        { 0, 0x726fdb47dd0e0e31ULL }, { 1, 0x74f839c593dc67fdULL }, { 2, 0x0d6c8009d9a94f5aULL },
        { 3, 0x85676696d7fb7e2dULL }, { 4, 0xcf2794e0277187b7ULL }, { 5, 0x18765564cd99a68dULL },
        { 6, 0xcbc9466e58fee3ceULL }, { 7, 0xab0200f58b01d137ULL }, { 8, 0x93f5f5799a932462ULL },
        { 15, 0xa129ca6149be45e5ULL },
    };
    uint8_t key[16], msg[16];
    for (int i = 0; i < 16; i++) { key[i] = (uint8_t)i; msg[i] = (uint8_t)i; }
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        const uint64_t got = cbae_siphash24(key, msg, v[i].len);
        if (got != v[i].out) {
            fprintf(stderr, "siphash24 length %zu: got %016llx, expected %016llx\n", v[i].len,
                    (unsigned long long)got, (unsigned long long)v[i].out);
            assert(!"siphash24 test vector");
        }
    }
    assert(cbae_siphash24(key, NULL, 0) == v[0].out);          /* NULL with length 0 is the empty message */
    PASS("siphash24 reference vectors");
}

static void test_siphash_keyed(void) {
    uint8_t k1[16] = {0}, k2[16] = {0};
    k2[15] = 1;
    assert(cbae_siphash24(k1, "name", 4) != cbae_siphash24(k2, "name", 4));
    assert(cbae_siphash24(k1, "name", 4) == cbae_siphash24(k1, "name", 4));
    assert(cbae_siphash24(k1, "name", 4) != cbae_siphash24(k1, "namf", 4));
    PASS("siphash24 depends on the key and on every byte");
}

/* ── the pool ─────────────────────────────────────────────────────────────── */

static void test_basics(void) {
    cbae_string_pool_t *pool = new_pool(16);
    const char *a = cbae_string_pool_intern(pool, "ExAllocatePool");
    const char *b = cbae_string_pool_intern(pool, "ExAllocatePool");
    assert(a && a == b);
    const char *c = cbae_string_pool_intern(pool, "request_irq");
    assert(c && c != a && strcmp(c, "request_irq") == 0 && strcmp(a, "ExAllocatePool") == 0);
    const char *d = cbae_string_pool_intern_n(pool, "hello world", 5);
    assert(d && strcmp(d, "hello") == 0);
    assert(cbae_string_pool_intern(pool, "hello") == d);       /* the 5-byte prefix is the string "hello" */
    assert(cbae_string_pool_count(pool) == 3);
    assert(cbae_string_pool_bytes(pool) == strlen("ExAllocatePool") + 1 + strlen("request_irq") + 1 + 6);
    /* a copy: changing the caller's buffer does not change the pool's string */
    char buf[8] = "abc";
    const char *e = cbae_string_pool_intern(pool, buf);
    buf[0] = 'X';
    assert(strcmp(e, "abc") == 0 && cbae_string_pool_intern(pool, "abc") == e);
    cbae_string_pool_destroy(pool);
    PASS("dedup, identity, content, intern_n, count and bytes, strings are copied");
}

static void test_empty_and_embedded_nul(void) {
    cbae_string_pool_t *pool = new_pool(0);
    const char *e0 = cbae_string_pool_intern(pool, "");
    assert(e0 && e0[0] == '\0' && cbae_string_pool_intern_n(pool, "x", 0) == e0 && cbae_string_pool_find(pool, "") == e0);
    const char *s1 = cbae_string_pool_intern_n(pool, "a\0b", 3);
    const char *s2 = cbae_string_pool_intern_n(pool, "a\0c", 3);
    const char *s0 = cbae_string_pool_intern(pool, "a");
    assert(s1 && s2 && s0 && s1 != s2 && s1 != s0 && s2 != s0);
    assert(memcmp(s1, "a\0b", 4) == 0 && memcmp(s2, "a\0c", 4) == 0);   /* NUL-terminated after the 3 bytes */
    assert(cbae_string_pool_find_n(pool, "a\0b", 3) == s1 && cbae_string_pool_find_n(pool, "a\0d", 3) == NULL);
    assert(cbae_string_pool_count(pool) == 4);
    cbae_string_pool_destroy(pool);
    PASS("the empty string and strings with an embedded NUL");
}

static void test_find_never_inserts(void) {
    cbae_string_pool_t *pool = new_pool(8);
    const char *a = cbae_string_pool_intern(pool, "present");
    cbae_string_pool_stats_t before, after;
    cbae_string_pool_stats(pool, &before);
    assert(cbae_string_pool_find(pool, "present") == a);
    assert(cbae_string_pool_find(pool, "absent") == NULL);
    assert(cbae_string_pool_find_n(pool, "presentation", 7) == a);        /* the first 7 bytes */
    assert(cbae_string_pool_find_n(pool, "present", 6) == NULL);          /* a prefix is another string */
    assert(cbae_string_pool_find(pool, NULL) == NULL && cbae_string_pool_find(NULL, "present") == NULL);
    for (int i = 0; i < 5000; i++) { char n[24]; snprintf(n, sizeof n, "missing_%d", i); assert(cbae_string_pool_find(pool, n) == NULL); }
    cbae_string_pool_stats(pool, &after);
    assert(after.strings == before.strings && after.bytes == before.bytes && after.chunks == before.chunks && after.buckets == before.buckets);
    cbae_string_pool_destroy(pool);
    PASS("find never changes the pool, and answers for exact length and bytes");
}

static void test_pointer_stability(void) {
    enum { N = 30000 };
    cbae_string_pool_t *pool = new_pool(16);
    const char **ptr = malloc(N * sizeof *ptr);
    assert(ptr);
    for (int i = 0; i < N; i++) {
        char n[32];
        snprintf(n, sizeof n, "symbol_number_%06d", i);
        ptr[i] = cbae_string_pool_intern(pool, n);
        assert(ptr[i]);
    }
    assert(cbae_string_pool_count(pool) == N);
    cbae_string_pool_stats_t st;
    cbae_string_pool_stats(pool, &st);
    assert(st.bytes > 64 * 1024 && st.chunks >= 2);      /* well past the size of the old single block */
    for (int i = 0; i < N; i++) {                         /* every pointer still reads its own string */
        char n[32];
        snprintf(n, sizeof n, "symbol_number_%06d", i);
        assert(strcmp(ptr[i], n) == 0);
        assert(cbae_string_pool_intern(pool, n) == ptr[i] && cbae_string_pool_find(pool, n) == ptr[i]);
    }
    free(ptr);
    cbae_string_pool_destroy(pool);
    PASS("30,000 strings: every pointer handed out earlier is still valid and unique");
}

static void test_long_strings(void) {
    cbae_string_pool_t *pool = new_pool(0);
    /* around half a chunk (32 KiB): the largest string that shares a chunk and the smallest that does not */
    static const size_t sizes[] = { 1000, 32 * 1024 - 64, 32 * 1024 - 24, 32 * 1024 - 23, 32 * 1024, 40 * 1024, 300 * 1024, 1024 * 1024 };
    const char *kept[sizeof sizes / sizeof sizes[0]];
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        char *s = malloc(sizes[i] + 1);
        assert(s);
        memset(s, (int)('a' + i), sizes[i]);
        s[sizes[i]] = '\0';
        kept[i] = cbae_string_pool_intern(pool, s);
        assert(kept[i] && kept[i] != s && strlen(kept[i]) == sizes[i] && memcmp(kept[i], s, sizes[i] + 1) == 0);
        assert(cbae_string_pool_intern(pool, s) == kept[i]);
        free(s);
        cbae_string_pool_intern(pool, "short between the long ones");
    }
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {          /* no later string disturbed an earlier one */
        assert(strlen(kept[i]) == sizes[i] && kept[i][0] == (char)('a' + i) && kept[i][sizes[i] - 1] == (char)('a' + i));
    }
    assert(cbae_string_pool_intern_n(pool, "x", CBAE_STRING_POOL_MAX_LEN + 1) == NULL);   /* refused before it is read */
    assert(cbae_string_pool_find_n(pool, "x", CBAE_STRING_POOL_MAX_LEN + 1) == NULL);
    cbae_string_pool_destroy(pool);
    PASS("long strings: around the chunk boundary, 300 KiB and 1 MiB; over-long refused");
}

static void test_table_growth(void) {
    enum { N = 200000 };
    cbae_string_pool_t *pool = new_pool(4);
    for (int i = 0; i < N; i++) {
        char n[24];
        snprintf(n, sizeof n, "%d", i);                   /* short, similar keys: the worst case for a weak hash */
        assert(cbae_string_pool_intern(pool, n));
    }
    cbae_string_pool_stats_t st;
    cbae_string_pool_stats(pool, &st);
    assert(st.strings == N);
    assert(st.buckets >= (size_t)N);                      /* it grew with the pool, load factor at most 3/4 */
    assert(st.buckets - st.buckets / 4 >= (size_t)N);
    assert(st.longest_chain <= 24);                       /* the fixed 256 buckets of the old pool would give ~800 */
    cbae_string_pool_destroy(pool);
    PASS("200,000 strings: the table grows, the longest chain stays short");
}

static void test_seeded(void) {
    uint8_t k1[16] = {1}, k2[16] = {2};
    cbae_string_pool_t *a = NULL, *b = NULL, *c = NULL;
    assert(cbae_string_pool_init_seeded(&a, 64, k1) == CBAE_OK && cbae_string_pool_init_seeded(&b, 64, k1) == CBAE_OK);
    assert(cbae_string_pool_init_seeded(&c, 64, k2) == CBAE_OK);
    for (int i = 0; i < 5000; i++) {
        char n[24];
        snprintf(n, sizeof n, "s%d", i);
        cbae_string_pool_intern(a, n); cbae_string_pool_intern(b, n); cbae_string_pool_intern(c, n);
    }
    cbae_string_pool_stats_t sa, sb, sc;
    cbae_string_pool_stats(a, &sa); cbae_string_pool_stats(b, &sb); cbae_string_pool_stats(c, &sc);
    assert(sa.longest_chain == sb.longest_chain && sa.buckets == sb.buckets);        /* same key, same layout */
    assert(sc.strings == sa.strings);                                                  /* the key changes layout, never content */
    cbae_string_pool_destroy(a); cbae_string_pool_destroy(b); cbae_string_pool_destroy(c);
    cbae_string_pool_t *r = (cbae_string_pool_t *)1;
    assert(cbae_string_pool_init_seeded(&r, 8, NULL) == CBAE_ERR_INVALID && r == NULL);
    PASS("seeded pools are reproducible; a NULL key is refused");
}

static void test_bad_arguments(void) {
    cbae_string_pool_t *pool = new_pool(0);
    assert(cbae_string_pool_init(NULL, 8) == CBAE_ERR_INVALID);
    assert(cbae_string_pool_intern(NULL, "x") == NULL && cbae_string_pool_intern(pool, NULL) == NULL);
    assert(cbae_string_pool_intern_n(pool, NULL, 0) == NULL && cbae_string_pool_intern_n(NULL, "x", 1) == NULL);
    assert(cbae_string_pool_count(NULL) == 0 && cbae_string_pool_bytes(NULL) == 0);
    cbae_string_pool_stats_t st;
    memset(&st, 0xab, sizeof st);
    cbae_string_pool_stats(NULL, &st);
    assert(st.strings == 0 && st.buckets == 0 && st.chunks == 0);
    cbae_string_pool_stats(pool, NULL);
    cbae_string_pool_destroy(NULL);
    assert(cbae_string_pool_count(pool) == 0);
    cbae_string_pool_destroy(pool);
    cbae_string_pool_t *huge = NULL;                                  /* a silly hint is capped, not an error */
    assert(cbae_string_pool_init(&huge, (size_t)-1) == CBAE_OK && huge);
    cbae_string_pool_destroy(huge);
    PASS("NULL arguments, a huge capacity hint");
}

/* ── memory running out ───────────────────────────────────────────────────── */

typedef struct { const char *kept[40]; } oom_ctx_t;

/* One pass: create, intern enough to fill chunks, take chunks of their own and grow the table, check
 * after every step that a failure changed nothing, destroy. Returns an error if any step failed. */
static cbae_err_t oom_body(void *vctx, uint64_t failing) {
    (void)vctx; (void)failing;
    cbae_string_pool_t *pool = NULL;
    cbae_err_t rc = cbae_string_pool_init(&pool, 0);
    if (rc != CBAE_OK) { assert(pool == NULL); return rc; }
    cbae_err_t result = CBAE_OK;
    size_t nseen = 0;
    static char big[40 * 1024];
    memset(big, 'z', sizeof big - 1);
    for (int i = 0; i < 400; i++) {
        char n[256];
        const size_t before = cbae_string_pool_count(pool), bytes = cbae_string_pool_bytes(pool);
        const char *p;
        if (i % 100 == 99) { big[0] = (char)('a' + i / 100); p = cbae_string_pool_intern_n(pool, big, sizeof big - 1); }
        else { snprintf(n, sizeof n, "oom_symbol_%d_%0200d", i, i); p = cbae_string_pool_intern(pool, n); }
        if (!p) {
            /* a failed intern leaves the pool exactly as it was */
            assert(cbae_string_pool_count(pool) == before && cbae_string_pool_bytes(pool) == bytes);
            result = CBAE_ERR_OOM;
            continue;
        }
        assert(cbae_string_pool_count(pool) == before + 1);
        nseen++;
    }
    /* whatever failed, what was interned is all still there, with its content */
    size_t k = 0;
    for (int i = 0; i < 400; i++) {
        if (i % 100 == 99) continue;
        char n[256];
        snprintf(n, sizeof n, "oom_symbol_%d_%0200d", i, i);
        const char *f = cbae_string_pool_find(pool, n);
        if (f) { assert(strcmp(f, n) == 0); k++; }
    }
    assert(k + 4 >= nseen && nseen >= k);
    cbae_string_pool_destroy(pool);
    return result;
}

static void test_out_of_memory(void) {
    oom_ctx_t ctx;
    /* not strict: a table that cannot grow is tolerated by design (longer chains), so an injected failure
     * does not always end in an error; what must hold is asserted inside the body */
    const oom_report_t r = oom_sweep(oom_body, &ctx, false);
    assert(r.allocations >= 8 && r.runs >= 2 * r.allocations);
    assert(r.reported >= 1);
    printf("  [PASS] allocation failures: %llu allocations, %llu runs, %llu reported, %llu tolerated\n",
           (unsigned long long)r.allocations, (unsigned long long)r.runs,
           (unsigned long long)r.reported, (unsigned long long)r.swallowed);

    cbae_string_pool_t *p = (cbae_string_pool_t *)1;
    ai_reset(); ai_fail_at(1);
    assert(cbae_string_pool_init(&p, 0) == CBAE_ERR_OOM && p == NULL);
    ai_reset(); ai_fail_at(2);
    p = (cbae_string_pool_t *)1;
    assert(cbae_string_pool_init(&p, 0) == CBAE_ERR_OOM && p == NULL);     /* the bucket array: the pool struct is not leaked */
    ai_reset();
    PASS("init: failure of either allocation leaves *out NULL");
}

int main(void) {
    printf("=== test_string_pool ===\n");
    test_siphash_vectors();
    test_siphash_keyed();
    test_basics();
    test_empty_and_embedded_nul();
    test_find_never_inserts();
    test_pointer_stability();
    test_long_strings();
    test_table_growth();
    test_seeded();
    test_bad_arguments();
    test_out_of_memory();
    printf("All string pool tests passed.\n");
    return 0;
}
