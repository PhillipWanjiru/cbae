/**
 * @file hashmap.h
 * @brief Open-addressing Robin Hood hashmap (uint64 key -> void* value).
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
    uint32_t probe_dist;
    bool     occupied;
} cbae_hashmap_entry_t;

typedef struct cbae_hashmap {
    cbae_hashmap_entry_t *entries;
    size_t                capacity;
    size_t                count;
    size_t                tombstones;
} cbae_hashmap_t;

cbae_err_t cbae_hashmap_init    (cbae_hashmap_t *m, size_t initial_capacity);
void       cbae_hashmap_destroy (cbae_hashmap_t *m);
void       cbae_hashmap_clear   (cbae_hashmap_t *m);
cbae_err_t cbae_hashmap_insert  (cbae_hashmap_t *m, uint64_t key, void *value);
bool       cbae_hashmap_get     (const cbae_hashmap_t *m, uint64_t key, void **out_value);
bool       cbae_hashmap_remove  (cbae_hashmap_t *m, uint64_t key);
bool       cbae_hashmap_contains(const cbae_hashmap_t *m, uint64_t key);

typedef void (*cbae_hashmap_iter_fn)(uint64_t key, void *value, void *ud);
void   cbae_hashmap_foreach (const cbae_hashmap_t *m,
                              cbae_hashmap_iter_fn fn, void *userdata);
size_t cbae_hashmap_count   (const cbae_hashmap_t *m);
size_t cbae_hashmap_capacity(const cbae_hashmap_t *m);
float  cbae_hashmap_load    (const cbae_hashmap_t *m);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_HASHMAP_H */
