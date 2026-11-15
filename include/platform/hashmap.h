/**
 * @file hashmap.h
 * @brief Open-addressing Robin Hood hashmap (uint64 key -> void* value).
 *
 * The table is a power of two in size (at least 16 slots) and holds at most 70% full; inserting past that
 * doubles it. Lookups, inserts and removals are O(1) on average; a removal shifts the entries behind it back
 * (no tombstones), so a table never degrades with churn. Keys are hashed with a fixed mixing function:
 * keys chosen by an attacker to collide can make operations slow, so do not use it where the keys are
 * attacker-chosen and worst-case time matters.
 *
 * A map whose bytes are all zero is a valid empty map (it is also what cbae_hashmap_destroy leaves, and what
 * cbae_hashmap_init leaves when it fails): lookups find nothing, and the first insert allocates the table.
 * Do not insert or remove while cbae_hashmap_foreach is running.
 *
 * Errors      CBAE_ERR_INVALID   NULL map
 *             CBAE_ERR_OVERFLOW  the table would need more than PTRDIFF_MAX bytes
 *             CBAE_ERR_OOM       out of memory
 * A call that fails changes nothing (except init, which leaves the map all zero).
 */
#ifndef CBAE_HASHMAP_H
#define CBAE_HASHMAP_H

#include "cbae/cbae_error.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_hashmap_entry {
    uint64_t key;
    void    *value;
    uint32_t probe_dist;        /* how far this entry sits from the slot its key hashes to */
    bool     occupied;
} cbae_hashmap_entry_t;

typedef struct cbae_hashmap {
    cbae_hashmap_entry_t *entries;
    size_t                capacity;     /* slots: a power of two, or 0 for a map that holds no table yet */
    size_t                count;
} cbae_hashmap_t;

/** An empty map with at least @p initial_capacity slots (16 or more, rounded up to a power of two). */
cbae_err_t cbae_hashmap_init    (cbae_hashmap_t *m, size_t initial_capacity);

/** Frees the table and leaves @p m all zero. Accepts NULL and a map that is already destroyed. */
void       cbae_hashmap_destroy (cbae_hashmap_t *m);

/** Removes every entry; the table stays. */
void       cbae_hashmap_clear   (cbae_hashmap_t *m);

/** Sets @p key to @p value, adding it if it is new. */
cbae_err_t cbae_hashmap_insert  (cbae_hashmap_t *m, uint64_t key, void *value);

/** Finds @p key; its value goes to @p out_value unless that is NULL. */
bool       cbae_hashmap_get     (const cbae_hashmap_t *m, uint64_t key, void **out_value);

/** Removes @p key; false if it was not there. */
bool       cbae_hashmap_remove  (cbae_hashmap_t *m, uint64_t key);
bool       cbae_hashmap_contains(const cbae_hashmap_t *m, uint64_t key);

typedef void (*cbae_hashmap_iter_fn)(uint64_t key, void *value, void *ud);

/** Calls @p fn for every entry, in table order (which is not insertion order). */
void   cbae_hashmap_foreach (const cbae_hashmap_t *m,
                              cbae_hashmap_iter_fn fn, void *userdata);
size_t cbae_hashmap_count   (const cbae_hashmap_t *m);
size_t cbae_hashmap_capacity(const cbae_hashmap_t *m);

/** count / capacity; 0 for a map with no table. */
float  cbae_hashmap_load    (const cbae_hashmap_t *m);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_HASHMAP_H */
