/**
 * @file hashmap.c
 * @brief Robin Hood open-addressing hashmap (uint64_t -> void*), backward-shift deletion.
 */
#include "platform/hashmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define INITIAL_CAP  16
#define MAX_CAP      ((size_t)PTRDIFF_MAX / sizeof(cbae_hashmap_entry_t))    /* slots that fit in one allocation */

/* The table may be at most 70% full: a new entry is refused room when (count + 1) / capacity would pass 7/10. */
static inline bool hm_would_exceed_load(size_t count_after, size_t capacity) {
    return count_after * 10 > capacity * 7;       /* capacity <= MAX_CAP < 2^59: neither product can overflow */
}

static inline size_t hm_hash(uint64_t key, size_t cap) {
    key ^= key >> 33;
    key *= UINT64_C(0xff51afd7ed558ccd);
    key ^= key >> 33;
    key *= UINT64_C(0xc4ceb9fe1a85ec53);
    key ^= key >> 33;
    return (size_t)(key & (cap - 1));
}

/* Gives an empty map a table of @p cap slots (a power of two). */
static cbae_err_t hm_alloc(cbae_hashmap_t *m, size_t cap) {
    if (cap > MAX_CAP) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a hashmap of %zu slots is too large", cap);
    cbae_hashmap_entry_t *e = (cbae_hashmap_entry_t *)calloc(cap, sizeof *e);
    if (!e) CBAE_RETURN_ERR(CBAE_ERR_OOM, "hashmap allocation of %zu slots failed", cap);
    m->entries  = e;
    m->capacity = cap;
    m->count    = 0;
    return CBAE_OK;
}

cbae_err_t cbae_hashmap_init(cbae_hashmap_t *m, size_t initial_capacity) {
    if (!m) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null hashmap");
    memset(m, 0, sizeof *m);
    size_t cap = INITIAL_CAP;
    while (cap < initial_capacity) {
        if (cap > MAX_CAP / 2) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a hashmap of %zu slots is too large", initial_capacity);
        cap <<= 1;
    }
    return hm_alloc(m, cap);
}

void cbae_hashmap_destroy(cbae_hashmap_t *m) {
    if (!m) return;
    free(m->entries);
    memset(m, 0, sizeof *m);
}

void cbae_hashmap_clear(cbae_hashmap_t *m) {
    if (!m) return;
    if (m->capacity) memset(m->entries, 0, m->capacity * sizeof *m->entries);
    m->count = 0;
}

/* The slot holding @p key (its index in *idx), or NULL. */
static cbae_hashmap_entry_t *hm_find(const cbae_hashmap_t *m, uint64_t key, size_t *idx) {
    if (!m || !m->capacity) return NULL;
    const size_t mask = m->capacity - 1;
    size_t i = hm_hash(key, m->capacity);
    for (uint32_t pd = 0;; pd++) {
        cbae_hashmap_entry_t *slot = &m->entries[i];
        if (!slot->occupied || pd > slot->probe_dist) return NULL;      /* Robin Hood: the key would have been here by now */
        if (slot->key == key) { if (idx) *idx = i; return slot; }
        i = (i + 1) & mask;
    }
}

/* Puts @p key in a table that has a free slot. True if the key is new, false if it only changed a value. */
static bool hm_place(cbae_hashmap_t *m, uint64_t key, void *value) {
    cbae_hashmap_entry_t ins = { .key = key, .value = value, .probe_dist = 0, .occupied = true };
    const size_t mask = m->capacity - 1;
    size_t i = hm_hash(key, m->capacity);
    for (;;) {
        cbae_hashmap_entry_t *slot = &m->entries[i];
        if (!slot->occupied) { *slot = ins; return true; }
        if (slot->key == key) { slot->value = value; return false; }
        if (slot->probe_dist < ins.probe_dist) {                        /* the richer entry gives way to the poorer */
            const cbae_hashmap_entry_t tmp = *slot;
            *slot = ins;
            ins = tmp;
        }
        ins.probe_dist++;
        i = (i + 1) & mask;
    }
}

static cbae_err_t hm_grow(cbae_hashmap_t *m) {
    if (m->capacity > MAX_CAP / 2) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a hashmap of more than %zu slots is too large", m->capacity);
    cbae_hashmap_t bigger;
    CBAE_CHECK(hm_alloc(&bigger, m->capacity << 1));
    for (size_t i = 0; i < m->capacity; i++)
        if (m->entries[i].occupied) hm_place(&bigger, m->entries[i].key, m->entries[i].value);
    bigger.count = m->count;
    free(m->entries);
    *m = bigger;
    return CBAE_OK;
}

cbae_err_t cbae_hashmap_insert(cbae_hashmap_t *m, uint64_t key, void *value) {
    if (!m) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null map");
    if (!m->capacity) CBAE_CHECK(hm_alloc(m, INITIAL_CAP));
    else if (hm_would_exceed_load(m->count + 1, m->capacity)) {
        cbae_hashmap_entry_t *e = hm_find(m, key, NULL);                /* a key that is there needs no room */
        if (e) { e->value = value; return CBAE_OK; }
        CBAE_CHECK(hm_grow(m));
    }
    if (hm_place(m, key, value)) m->count++;
    return CBAE_OK;
}

bool cbae_hashmap_get(const cbae_hashmap_t *m, uint64_t key, void **out) {
    const cbae_hashmap_entry_t *e = hm_find(m, key, NULL);
    if (!e) return false;
    if (out) *out = e->value;
    return true;
}

bool cbae_hashmap_contains(const cbae_hashmap_t *m, uint64_t key) { return hm_find(m, key, NULL) != NULL; }

bool cbae_hashmap_remove(cbae_hashmap_t *m, uint64_t key) {
    size_t i;
    if (!hm_find(m, key, &i)) return false;
    const size_t mask = m->capacity - 1;
    m->count--;
    for (;;) {                                                          /* shift what follows back by one, until a gap or an entry at home */
        const size_t next = (i + 1) & mask;
        if (!m->entries[next].occupied || m->entries[next].probe_dist == 0) break;
        m->entries[i] = m->entries[next];
        m->entries[i].probe_dist--;
        i = next;
    }
    memset(&m->entries[i], 0, sizeof m->entries[i]);
    return true;
}

void cbae_hashmap_foreach(const cbae_hashmap_t *m, cbae_hashmap_iter_fn fn, void *ud) {
    if (!m || !fn) return;
    for (size_t i = 0; i < m->capacity; i++)
        if (m->entries[i].occupied) fn(m->entries[i].key, m->entries[i].value, ud);
}

size_t cbae_hashmap_count   (const cbae_hashmap_t *m) { return m ? m->count    : 0; }
size_t cbae_hashmap_capacity(const cbae_hashmap_t *m) { return m ? m->capacity : 0; }
float  cbae_hashmap_load    (const cbae_hashmap_t *m) {
    return (m && m->capacity) ? (float)m->count / (float)m->capacity : 0.f;
}
