/**
 * @file string_pool.c
 * @brief Interned string pool: chunked stable storage, keyed hash, growing table.
 *
 * Storage. Each string is stored with its table entry in a bump-allocated chunk, so an insertion is
 * one memory allocation at most (usually none) and nothing is ever moved: the old design kept every
 * string in one block that was realloc'd as it grew, which left every pointer already handed out
 * dangling. A string longer than half a chunk gets a chunk of its own.
 *
 * Table. Chained buckets that double when the pool is three-quarters full. Entries remember their
 * hash, so growing re-links them without hashing again. If the larger table cannot be allocated the
 * pool simply carries on with the smaller one (longer chains) and tries again at the next insertion:
 * running short of memory costs speed, never correctness.
 */
#include "platform/string_pool.h"
#include "platform/siphash.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif

#define SP_MIN_BUCKETS       256u
#define SP_MAX_INITIAL_HINT  ((size_t)1 << 22)
#define SP_CHUNK_BYTES       ((size_t)64 * 1024)

typedef struct sp_entry {
    struct sp_entry *next;
    uint64_t         hash;
    size_t           len;
    /* len + 1 bytes follow: the string and its NUL */
} sp_entry_t;

typedef struct sp_chunk {
    struct sp_chunk *next;
    size_t           used;
    size_t           cap;
    /* cap bytes of storage follow */
} sp_chunk_t;

struct cbae_string_pool {
    sp_entry_t **buckets;
    size_t       bucket_count;      /* a power of two */
    size_t       count;
    size_t       total_bytes;
    sp_chunk_t  *fill;              /* chunks shared by many strings; the first is being filled */
    sp_chunk_t  *own;               /* chunks that each hold one long string */
    uint8_t      key[16];
};

#define SP_STR(e)        ((char *)((e) + 1))
#define SP_CSTR(e)       ((const char *)((e) + 1))
#define SP_DATA(c)       ((uint8_t *)((c) + 1))

/* A key nobody can predict where the system offers randomness; where it does not, one that at least
 * differs between pools and between runs. */
static void random_key(uint8_t key[16]) {
#ifdef __linux__
    size_t got = 0;
    while (got < 16) {
        const ssize_t r = getrandom(key + got, 16 - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
    }
    if (got == 16) return;
#endif
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    const uint64_t a = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 21) ^ (uint64_t)getpid();
    const uint64_t b = (uint64_t)(uintptr_t)key ^ (uint64_t)(uintptr_t)&random_key;
    memcpy(key, &a, 8);
    memcpy(key + 8, &b, 8);
}

static cbae_err_t pool_create(cbae_string_pool_t **out, size_t hint, const uint8_t *key) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "string pool: out is NULL");
    *out = NULL;
    if (hint > SP_MAX_INITIAL_HINT) hint = SP_MAX_INITIAL_HINT;
    size_t want = hint + hint / 3 + 1;                 /* room for `hint` strings below the growth threshold */
    size_t buckets = SP_MIN_BUCKETS;
    while (buckets < want) buckets <<= 1;

    cbae_string_pool_t *p = calloc(1, sizeof *p);
    if (!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "string pool: allocating the pool failed");
    p->buckets = calloc(buckets, sizeof *p->buckets);
    if (!p->buckets) { free(p); CBAE_RETURN_ERR(CBAE_ERR_OOM, "string pool: allocating %zu buckets failed", buckets); }
    p->bucket_count = buckets;
    if (key) memcpy(p->key, key, 16); else random_key(p->key);
    *out = p;
    return CBAE_OK;
}

cbae_err_t cbae_string_pool_init(cbae_string_pool_t **out, size_t initial_capacity) {
    return pool_create(out, initial_capacity, NULL);
}

cbae_err_t cbae_string_pool_init_seeded(cbae_string_pool_t **out, size_t initial_capacity, const uint8_t key[16]) {
    if (!key) { if (out) *out = NULL; CBAE_RETURN_ERR(CBAE_ERR_INVALID, "string pool: key is NULL"); }
    return pool_create(out, initial_capacity, key);
}

static void free_chunks(sp_chunk_t *c) {
    while (c) { sp_chunk_t *next = c->next; free(c); c = next; }
}

void cbae_string_pool_destroy(cbae_string_pool_t *pool) {
    if (!pool) return;
    free_chunks(pool->fill);
    free_chunks(pool->own);
    free(pool->buckets);
    free(pool);
}

static sp_entry_t *lookup(const cbae_string_pool_t *p, const char *str, size_t len, uint64_t hash) {
    for (sp_entry_t *e = p->buckets[hash & (p->bucket_count - 1)]; e; e = e->next)
        if (e->hash == hash && e->len == len && memcmp(SP_CSTR(e), str, len) == 0) return e;
    return NULL;
}

/* Storage for an entry holding a string of `len` bytes, or NULL. Changes nothing when it fails. */
static sp_entry_t *alloc_entry(cbae_string_pool_t *p, size_t len) {
    /* len <= CBAE_STRING_POOL_MAX_LEN, so this cannot wrap */
    const size_t need = (sizeof(sp_entry_t) + len + 1 + 7) & ~(size_t)7;
    if (need > SP_CHUNK_BYTES / 2) {
        sp_chunk_t *c = malloc(sizeof *c + need);
        if (!c) return NULL;
        c->used = c->cap = need;
        c->next = p->own;
        p->own = c;
        return (sp_entry_t *)SP_DATA(c);
    }
    if (!p->fill || p->fill->cap - p->fill->used < need) {
        sp_chunk_t *c = malloc(sizeof *c + SP_CHUNK_BYTES);
        if (!c) return NULL;
        c->used = 0;
        c->cap = SP_CHUNK_BYTES;
        c->next = p->fill;
        p->fill = c;
    }
    sp_entry_t *e = (sp_entry_t *)(SP_DATA(p->fill) + p->fill->used);
    p->fill->used += need;
    return e;
}

static void grow(cbae_string_pool_t *p) {
    if (p->bucket_count > SIZE_MAX / sizeof(sp_entry_t *) / 2) return;
    const size_t nb = p->bucket_count * 2;
    sp_entry_t **nbk = calloc(nb, sizeof *nbk);
    if (!nbk) return;
    for (size_t i = 0; i < p->bucket_count; i++) {
        sp_entry_t *e = p->buckets[i];
        while (e) {
            sp_entry_t *next = e->next;
            const size_t j = (size_t)(e->hash & (nb - 1));
            e->next = nbk[j];
            nbk[j] = e;
            e = next;
        }
    }
    free(p->buckets);
    p->buckets = nbk;
    p->bucket_count = nb;
}

const char *cbae_string_pool_find_n(const cbae_string_pool_t *pool, const char *str, size_t len) {
    if (!pool || !str || len > CBAE_STRING_POOL_MAX_LEN) return NULL;
    const sp_entry_t *e = lookup(pool, str, len, cbae_siphash24(pool->key, str, len));
    return e ? SP_CSTR(e) : NULL;
}

const char *cbae_string_pool_find(const cbae_string_pool_t *pool, const char *str) {
    return str ? cbae_string_pool_find_n(pool, str, strlen(str)) : NULL;
}

const char *cbae_string_pool_intern_n(cbae_string_pool_t *pool, const char *str, size_t len) {
    if (!pool || !str || len > CBAE_STRING_POOL_MAX_LEN) return NULL;
    const uint64_t hash = cbae_siphash24(pool->key, str, len);
    const sp_entry_t *found = lookup(pool, str, len, hash);
    if (found) return SP_CSTR(found);

    sp_entry_t *e = alloc_entry(pool, len);
    if (!e) return NULL;
    e->hash = hash;
    e->len = len;
    memcpy(SP_STR(e), str, len);
    SP_STR(e)[len] = '\0';

    const size_t idx = (size_t)(hash & (pool->bucket_count - 1));
    e->next = pool->buckets[idx];
    pool->buckets[idx] = e;
    pool->count++;
    pool->total_bytes += len + 1;
    if (pool->count > pool->bucket_count - pool->bucket_count / 4) grow(pool);
    return SP_CSTR(e);
}

const char *cbae_string_pool_intern(cbae_string_pool_t *pool, const char *str) {
    return str ? cbae_string_pool_intern_n(pool, str, strlen(str)) : NULL;
}

size_t cbae_string_pool_count(const cbae_string_pool_t *p) { return p ? p->count : 0; }
size_t cbae_string_pool_bytes(const cbae_string_pool_t *p) { return p ? p->total_bytes : 0; }

void cbae_string_pool_stats(const cbae_string_pool_t *p, cbae_string_pool_stats_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!p) return;
    out->strings = p->count;
    out->bytes = p->total_bytes;
    out->buckets = p->bucket_count;
    for (size_t i = 0; i < p->bucket_count; i++) {
        size_t n = 0;
        for (const sp_entry_t *e = p->buckets[i]; e; e = e->next) n++;
        if (n > out->longest_chain) out->longest_chain = n;
    }
    for (const sp_chunk_t *c = p->fill; c; c = c->next) out->chunks++;
    for (const sp_chunk_t *c = p->own; c; c = c->next) out->chunks++;
}
