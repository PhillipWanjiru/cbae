/**
 * @file memory.h
 * @brief Arena and pool allocators for zero-fragmentation bulk allocation.
 */
#ifndef CBAE_MEMORY_H
#define CBAE_MEMORY_H

#include "cbae/cbae_error.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_arena {
    uint8_t *base;
    size_t   capacity;
    size_t   used;
    bool     owns_mem;
} cbae_arena_t;

cbae_err_t cbae_arena_init    (cbae_arena_t *a, size_t capacity_bytes);
void       cbae_arena_destroy (cbae_arena_t *a);
void      *cbae_arena_alloc   (cbae_arena_t *a, size_t size, size_t align);
void       cbae_arena_reset   (cbae_arena_t *a);
size_t     cbae_arena_used    (const cbae_arena_t *a);
size_t     cbae_arena_remaining(const cbae_arena_t *a);

#define CBAE_ARENA_ALLOC(arena, type) \
    ((type *)cbae_arena_alloc((arena), sizeof(type), _Alignof(type)))
#define CBAE_ARENA_ALLOC_N(arena, type, n) \
    ((type *)cbae_arena_alloc((arena), sizeof(type)*(n), _Alignof(type)))

typedef struct cbae_pool {
    cbae_arena_t *arena;
    void         *free_list;
    size_t        obj_size;
    size_t        alignment;
    size_t        alloc_count;
    size_t        free_count;
} cbae_pool_t;

cbae_err_t cbae_pool_init (cbae_pool_t *p, cbae_arena_t *arena,
                            size_t obj_size, size_t alignment);
void      *cbae_pool_alloc(cbae_pool_t *p);
void       cbae_pool_free (cbae_pool_t *p, void *obj);
void       cbae_pool_stats(const cbae_pool_t *p,
                            size_t *out_alloc, size_t *out_free);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_MEMORY_H */
