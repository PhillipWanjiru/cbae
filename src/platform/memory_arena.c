/**
 * @file memory_arena.c
 * @brief Arena allocator: bump-pointer alloc, pool, O(1) free-all.
 */
#include "platform/memory.h"
#include "cbae/cbae_error.h"
#include <stdlib.h>
#include <string.h>

cbae_err_t cbae_arena_init(cbae_arena_t *a, size_t capacity_bytes) {
    if(!a || capacity_bytes == 0)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "invalid arena params");
    a->base = (uint8_t *)malloc(capacity_bytes);
    if(!a->base)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "arena malloc(%zu) failed", capacity_bytes);
    a->capacity = capacity_bytes;
    a->used     = 0;
    a->owns_mem = true;
    return CBAE_OK;
}

void cbae_arena_destroy(cbae_arena_t *a) {
    if(!a) return;
    if(a->owns_mem && a->base) free(a->base);
    memset(a, 0, sizeof(*a));
}

void *cbae_arena_alloc(cbae_arena_t *a, size_t size, size_t align) {
    if(!a || !a->base) return NULL;
    if(align == 0) align = 1;
    if(align & (align - 1)) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "arena alignment %zu is not a power of two", align);
        return NULL;
    }
    /* Align the ADDRESS, not the offset: base is only malloc-aligned, so for a larger alignment the
     * offset and the address disagree. Every comparison is a subtraction from a quantity known to be
     * in range (used <= capacity), so no sum of untrusted numbers can wrap. */
    const size_t pad = (size_t)(0 - ((uintptr_t)a->base + a->used)) & (align - 1);
    const size_t room = a->capacity - a->used;
    if(size == 0) return a->base + a->used;
    if(pad > room || size > room - pad) {
        CBAE_SET_ERR(CBAE_ERR_OOM, "arena exhausted: need %zu bytes (aligned to %zu), have %zu",
                     size, align, pad > room ? (size_t)0 : room - pad);
        return NULL;
    }
    void *ptr = a->base + a->used + pad;
    a->used  += pad + size;
    memset(ptr, 0, size);
    return ptr;
}

void *cbae_arena_alloc_array(cbae_arena_t *a, size_t elem_size, size_t n, size_t align) {
    if(elem_size != 0 && n > SIZE_MAX / elem_size) {
        CBAE_SET_ERR(CBAE_ERR_OVERFLOW, "arena array of %zu x %zu bytes does not fit in size_t", n, elem_size);
        return NULL;
    }
    return cbae_arena_alloc(a, elem_size * n, align);
}

void   cbae_arena_reset    (cbae_arena_t *a) { if(a) a->used = 0; }
size_t cbae_arena_used     (const cbae_arena_t *a) { return a ? a->used : 0; }
size_t cbae_arena_remaining(const cbae_arena_t *a) {
    return a ? a->capacity - a->used : 0;
}

typedef struct pool_node { struct pool_node *next; } pool_node_t;

cbae_err_t cbae_pool_init(cbae_pool_t *p, cbae_arena_t *arena,
                           size_t obj_size, size_t alignment) {
    if(!p || !arena) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null pool/arena");
    if(obj_size < sizeof(pool_node_t)) obj_size = sizeof(pool_node_t);
    p->arena       = arena;
    p->free_list   = NULL;
    p->obj_size    = obj_size;
    p->alignment   = alignment ? alignment : sizeof(void*);
    p->alloc_count = 0;
    p->free_count  = 0;
    return CBAE_OK;
}

void *cbae_pool_alloc(cbae_pool_t *p) {
    if(!p) return NULL;
    if(p->free_list) {
        pool_node_t *node = (pool_node_t *)p->free_list;
        p->free_list = node->next;
        p->free_count--;
        p->alloc_count++;
        memset(node, 0, p->obj_size);
        return node;
    }
    void *mem = cbae_arena_alloc(p->arena, p->obj_size, p->alignment);
    if(mem) p->alloc_count++;
    return mem;
}

void cbae_pool_free(cbae_pool_t *p, void *obj) {
    if(!p || !obj) return;
    pool_node_t *node = (pool_node_t *)obj;
    node->next   = (pool_node_t *)p->free_list;
    p->free_list = node;
    p->free_count++;
}

void cbae_pool_stats(const cbae_pool_t *p, size_t *out_alloc, size_t *out_free) {
    if(out_alloc) *out_alloc = p ? p->alloc_count : 0;
    if(out_free)  *out_free  = p ? p->free_count  : 0;
}
