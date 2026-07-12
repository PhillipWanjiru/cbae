/**
 * @file hashmap.c
 * @brief Robin Hood open-addressing hashmap (uint64_t -> void*).
 */
#include "platform/hashmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define LOAD_FACTOR_MAX  0.70f
#define INITIAL_CAP      16

static inline size_t hm_hash(uint64_t key, size_t cap) {
    key ^= key >> 33;
    key *= UINT64_C(0xff51afd7ed558ccd);
    key ^= key >> 33;
    key *= UINT64_C(0xc4ceb9fe1a85ec53);
    key ^= key >> 33;
    return (size_t)(key & (cap - 1));
}

cbae_err_t cbae_hashmap_init(cbae_hashmap_t *m, size_t initial_capacity) {
    if(!m) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null hashmap");
    size_t cap = INITIAL_CAP;
    while(cap < initial_capacity) cap <<= 1;
    m->entries = (cbae_hashmap_entry_t *)calloc(cap, sizeof(*m->entries));
    if(!m->entries) CBAE_RETURN_ERR(CBAE_ERR_OOM, "hashmap alloc failed");
    m->capacity   = cap;
    m->count      = 0;
    m->tombstones = 0;
    return CBAE_OK;
}

void cbae_hashmap_destroy(cbae_hashmap_t *m) {
    if(!m) return;
    free(m->entries);
    memset(m, 0, sizeof(*m));
}

void cbae_hashmap_clear(cbae_hashmap_t *m) {
    if(!m) return;
    memset(m->entries, 0, m->capacity * sizeof(*m->entries));
    m->count = m->tombstones = 0;
}

static cbae_err_t hm_rehash(cbae_hashmap_t *m, size_t new_cap) {
    cbae_hashmap_entry_t *old = m->entries;
    size_t old_cap = m->capacity;
    m->entries = (cbae_hashmap_entry_t *)calloc(new_cap, sizeof(*m->entries));
    if(!m->entries) { m->entries = old; CBAE_RETURN_ERR(CBAE_ERR_OOM, "rehash OOM"); }
    m->capacity   = new_cap;
    m->count      = 0;
    m->tombstones = 0;
    for(size_t i = 0; i < old_cap; i++)
        if(old[i].occupied)
            cbae_hashmap_insert(m, old[i].key, old[i].value);
    free(old);
    return CBAE_OK;
}

cbae_err_t cbae_hashmap_insert(cbae_hashmap_t *m, uint64_t key, void *value) {
    if(!m) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null map");
    if((float)(m->count + 1) / (float)m->capacity > LOAD_FACTOR_MAX) {
        cbae_err_t e = hm_rehash(m, m->capacity << 1);
        if(e != CBAE_OK) return e;
    }
    cbae_hashmap_entry_t ins = { .key=key, .value=value, .probe_dist=0, .occupied=true };
    size_t idx = hm_hash(key, m->capacity);
    for(;;) {
        cbae_hashmap_entry_t *slot = &m->entries[idx];
        if(!slot->occupied) { *slot = ins; m->count++; return CBAE_OK; }
        if(slot->key == key) { slot->value = value; return CBAE_OK; }
        if(slot->probe_dist < ins.probe_dist) {
            cbae_hashmap_entry_t tmp = *slot;
            *slot = ins; ins = tmp;
        }
        ins.probe_dist++;
        idx = (idx + 1) & (m->capacity - 1);
    }
}

bool cbae_hashmap_get(const cbae_hashmap_t *m, uint64_t key, void **out) {
    if(!m) return false;
    size_t idx = hm_hash(key, m->capacity);
    uint32_t pd = 0;
    for(;;) {
        const cbae_hashmap_entry_t *slot = &m->entries[idx];
        if(!slot->occupied || pd > slot->probe_dist) return false;
        if(slot->key == key) { if(out) *out = slot->value; return true; }
        pd++;
        idx = (idx + 1) & (m->capacity - 1);
    }
}

bool cbae_hashmap_contains(const cbae_hashmap_t *m, uint64_t key)
{ return cbae_hashmap_get(m, key, NULL); }

bool cbae_hashmap_remove(cbae_hashmap_t *m, uint64_t key) {
    if(!m) return false;
    size_t idx = hm_hash(key, m->capacity);
    uint32_t pd = 0;
    for(;;) {
        cbae_hashmap_entry_t *slot = &m->entries[idx];
        if(!slot->occupied || pd > slot->probe_dist) return false;
        if(slot->key == key) {
            slot->occupied = false;
            m->count--;
            size_t cur = idx;
            for(;;) {
                size_t nxt = (cur + 1) & (m->capacity - 1);
                if(!m->entries[nxt].occupied || m->entries[nxt].probe_dist == 0) {
                    m->entries[cur].occupied = false; break;
                }
                m->entries[cur] = m->entries[nxt];
                m->entries[cur].probe_dist--;
                cur = nxt;
            }
            return true;
        }
        pd++;
        idx = (idx + 1) & (m->capacity - 1);
    }
}

void cbae_hashmap_foreach(const cbae_hashmap_t *m,
                           cbae_hashmap_iter_fn fn, void *ud) {
    if(!m || !fn) return;
    for(size_t i = 0; i < m->capacity; i++)
        if(m->entries[i].occupied)
            fn(m->entries[i].key, m->entries[i].value, ud);
}

size_t cbae_hashmap_count   (const cbae_hashmap_t *m) { return m ? m->count    : 0; }
size_t cbae_hashmap_capacity(const cbae_hashmap_t *m) { return m ? m->capacity : 0; }
float  cbae_hashmap_load    (const cbae_hashmap_t *m) {
    return (m && m->capacity) ? (float)m->count/(float)m->capacity : 0.f;
}
