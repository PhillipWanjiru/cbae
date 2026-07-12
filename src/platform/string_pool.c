/**
 * @file string_pool.c
 * @brief Interned string pool backed by a FNV-1a hash table.
 */
#include "platform/string_pool.h"
#include <stdlib.h>
#include <string.h>

#define SP_INIT_BUCKETS 256

typedef struct sp_entry {
    const char      *str;
    size_t           len;
    uint32_t         hash;
    struct sp_entry *next;
} sp_entry_t;

struct cbae_string_pool {
    sp_entry_t **buckets;
    size_t       bucket_count;
    size_t       count;
    size_t       total_bytes;
    char        *block;
    size_t       block_used;
    size_t       block_cap;
};

static uint32_t fnv1a(const char *s, size_t len) {
    uint32_t h = 2166136261u;
    for(size_t i = 0; i < len; i++) h = (h ^ (uint8_t)s[i]) * 16777619u;
    return h;
}

cbae_err_t cbae_string_pool_init(cbae_string_pool_t **out, size_t initial_cap) {
    if(!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null out");
    cbae_string_pool_t *p = calloc(1, sizeof(*p));
    if(!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "pool struct alloc");
    size_t bc = SP_INIT_BUCKETS;
    while(bc < initial_cap) bc <<= 1;
    p->buckets      = calloc(bc, sizeof(sp_entry_t *));
    p->bucket_count = bc;
    p->block_cap    = 64 * 1024;
    p->block        = malloc(p->block_cap);
    if(!p->buckets || !p->block) {
        free(p->buckets); free(p->block); free(p);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "pool backing alloc");
    }
    *out = p;
    return CBAE_OK;
}

void cbae_string_pool_destroy(cbae_string_pool_t *pool) {
    if(!pool) return;
    for(size_t i = 0; i < pool->bucket_count; i++) {
        sp_entry_t *e = pool->buckets[i];
        while(e) { sp_entry_t *nxt = e->next; free(e); e = nxt; }
    }
    free(pool->buckets);
    free(pool->block);
    free(pool);
}

const char *cbae_string_pool_intern_n(cbae_string_pool_t *pool,
                                       const char *str, size_t len) {
    if(!pool || !str) return NULL;
    uint32_t h   = fnv1a(str, len);
    size_t   idx = h & (pool->bucket_count - 1);
    for(sp_entry_t *e = pool->buckets[idx]; e; e = e->next)
        if(e->hash == h && e->len == len && memcmp(e->str, str, len) == 0)
            return e->str;
    size_t needed = len + 1;
    if(pool->block_used + needed > pool->block_cap) {
        size_t new_cap = pool->block_cap * 2;
        if(new_cap < pool->block_used + needed) new_cap = pool->block_used + needed;
        pool->block     = realloc(pool->block, new_cap);
        pool->block_cap = new_cap;
        if(!pool->block) return NULL;
    }
    char *stored = pool->block + pool->block_used;
    memcpy(stored, str, len);
    stored[len] = '\0';
    pool->block_used  += needed;
    pool->total_bytes += needed;
    sp_entry_t *entry = malloc(sizeof(*entry));
    if(!entry) return NULL;
    entry->str  = stored;
    entry->len  = len;
    entry->hash = h;
    entry->next = pool->buckets[idx];
    pool->buckets[idx] = entry;
    pool->count++;
    return stored;
}

const char *cbae_string_pool_intern(cbae_string_pool_t *pool, const char *str) {
    return str ? cbae_string_pool_intern_n(pool, str, strlen(str)) : NULL;
}

size_t cbae_string_pool_count(const cbae_string_pool_t *p) { return p ? p->count : 0; }
size_t cbae_string_pool_bytes(const cbae_string_pool_t *p) { return p ? p->total_bytes : 0; }
