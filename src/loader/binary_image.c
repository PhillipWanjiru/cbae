/**
 * @file binary_image.c
 * @brief Unified binary image lifecycle, index building, and lookup operations.
 */
#include "loader/binary_image.h"
#include "platform/logging.h"
#include "platform/sha256.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define IMAGE_DEFAULT_ARENA_SIZE   (8 * 1024 * 1024)
#define IMAGE_HASHMAP_INIT_CAP     256

cbae_err_t cbae_image_create(cbae_size_t arena_size, cbae_binary_image_t **out) {
    if(!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out is NULL");
    *out = NULL;
    if(arena_size == 0) arena_size = IMAGE_DEFAULT_ARENA_SIZE;
    if(arena_size > (cbae_size_t)SIZE_MAX)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "arena of %llu bytes does not fit in memory", (unsigned long long)arena_size);
    cbae_binary_image_t *img = calloc(1, sizeof(*img));
    if(!img) CBAE_RETURN_ERR(CBAE_ERR_OOM, "calloc binary_image_t failed");
    img->db_id = -1;
    /* Everything below is released by cbae_image_destroy, which copes with members not yet set up. */
    cbae_err_t err = cbae_arena_init(&img->arena, (size_t)arena_size);
    if(err == CBAE_OK) err = cbae_string_pool_init(&img->strings, 512);
    if(err == CBAE_OK) err = cbae_hashmap_init(&img->va_to_section,  IMAGE_HASHMAP_INIT_CAP);
    if(err == CBAE_OK) err = cbae_hashmap_init(&img->va_to_symbol,   IMAGE_HASHMAP_INIT_CAP);
    if(err == CBAE_OK) err = cbae_hashmap_init(&img->iat_to_import,  IMAGE_HASHMAP_INIT_CAP);
    if(err == CBAE_OK) err = cbae_hashmap_init(&img->name_to_symbol, IMAGE_HASHMAP_INIT_CAP);
    if(err != CBAE_OK) {
        const cbae_err_t first = err;
        char why[CBAE_ERR_MSG_MAX];
        snprintf(why, sizeof why, "%s", cbae_last_error());
        cbae_image_destroy(&img);
        CBAE_RETURN_ERR(first, "cannot create a binary image: %s", why);
    }
    *out = img;
    LOG_DEBUG("binary_image created (arena=%zu bytes)", (size_t)arena_size);
    return CBAE_OK;
}

/* Which of two symbols that share an address or a name a lookup finds: the resolved one, then the
 * exported or global one; between equals, the one that came first. */
static int symbol_rank(const cbae_symbol_t *s) {
    return (cbae_symbol_is_resolved(s) ? 2 : 0) + ((s->type == CBAE_SYM_EXPORT || s->binding != CBAE_BIND_LOCAL) ? 1 : 0);
}

/* Inserts key -> value unless the key is taken by something that ranks at least as high. */
static cbae_err_t insert_ranked(cbae_hashmap_t *m, uint64_t key, cbae_symbol_t *sym) {
    void *existing = NULL;
    if(cbae_hashmap_get(m, key, &existing) && symbol_rank((const cbae_symbol_t *)existing) >= symbol_rank(sym))
        return CBAE_OK;
    return cbae_hashmap_insert(m, key, sym);
}

cbae_err_t cbae_image_build_indexes(cbae_binary_image_t *img) {
    if(!img) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "img is NULL");
    cbae_err_t err;
    for(uint32_t i = 0; i < img->section_count; i++) {
        cbae_section_t *s = &img->sections[i];
        if(cbae_hashmap_contains(&img->va_to_section, (uint64_t)s->virt_addr)) continue;   /* first section at an address wins, as in section_at_va */
        err = cbae_hashmap_insert(&img->va_to_section, (uint64_t)s->virt_addr, s);
        if(err != CBAE_OK) CBAE_RETURN_ERR(err, "build_indexes: section %u", i);
    }
    for(uint32_t i = 0; i < img->symbol_count; i++) {
        cbae_symbol_t *sym = &img->symbols[i];
        if(sym->type == CBAE_SYM_SECTION || sym->type == CBAE_SYM_FILE) continue;   /* they stand for a section or a source file, not for something an address or a name lookup should find */
        if(cbae_symbol_is_resolved(sym)) {
            err = insert_ranked(&img->va_to_symbol, (uint64_t)sym->address, sym);
            if(err != CBAE_OK) CBAE_RETURN_ERR(err, "build_indexes: symbol %u by address", i);
        }
        if(sym->name[0] != '\0') {
            const char *interned = cbae_string_pool_intern(img->strings, sym->name);
            if(!interned) CBAE_RETURN_ERR(CBAE_ERR_OOM, "build_indexes: cannot intern the name of symbol %u", i);
            err = insert_ranked(&img->name_to_symbol, (uint64_t)(uintptr_t)interned, sym);
            if(err != CBAE_OK) CBAE_RETURN_ERR(err, "build_indexes: symbol %u by name", i);
        }
    }
    for(uint32_t i = 0; i < img->import_count; i++) {
        cbae_import_entry_t *imp = &img->imports[i];
        if(!cbae_import_has_iat(imp) || cbae_hashmap_contains(&img->iat_to_import, (uint64_t)imp->iat_va)) continue;
        err = cbae_hashmap_insert(&img->iat_to_import, (uint64_t)imp->iat_va, imp);
        if(err != CBAE_OK) CBAE_RETURN_ERR(err, "build_indexes: import %u", i);
    }
    LOG_DEBUG("image indexes built: %u sections, %u symbols, %u imports",
              img->section_count, img->symbol_count, img->import_count);
    return CBAE_OK;
}

void cbae_image_destroy(cbae_binary_image_t **img) {
    if(!img || !*img) return;
    cbae_binary_image_t *m = *img;
    free((void *)m->file_data);
    m->file_data = NULL;
    cbae_hashmap_destroy(&m->va_to_section);
    cbae_hashmap_destroy(&m->va_to_symbol);
    cbae_hashmap_destroy(&m->iat_to_import);
    cbae_hashmap_destroy(&m->name_to_symbol);
    if(m->strings) cbae_string_pool_destroy(m->strings);
    cbae_arena_destroy(&m->arena);
    free(m);
    *img = NULL;
    LOG_DEBUG("binary_image destroyed");
}

void cbae_image_adopt_file(cbae_binary_image_t *img, uint8_t *data, size_t size) {
    if(!img) { free(data); return; }
    if(img->file_data != data) free((void *)img->file_data);
    img->file_data = data;
    img->file_size = size;
    uint8_t digest[CBAE_SHA256_DIGEST_BYTES];
    cbae_sha256(data, size, digest);
    cbae_sha256_hex(digest, img->sha256);
}

void cbae_image_note(cbae_binary_image_t *img, const char *fmt, ...) {
    if(!img || !fmt) return;
    const uint32_t slot = img->note_count;
    if(img->note_count < UINT32_MAX) img->note_count++;
    if(slot >= CBAE_IMAGE_NOTES_MAX) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(img->notes[slot], CBAE_IMAGE_NOTE_LEN, fmt, ap);
    va_end(ap);
    LOG_DEBUG("%s: %s", img->path[0] ? img->path : "(image)", img->notes[slot]);
}

cbae_section_t *cbae_image_section_at_va(const cbae_binary_image_t *img, cbae_addr_t va) {
    if(!img) return NULL;
    for(uint32_t i = 0; i < img->section_count; i++)
        if(cbae_section_contains_va(&img->sections[i], va))
            return &img->sections[i];
    return NULL;
}

cbae_section_t *cbae_image_section_by_name(const cbae_binary_image_t *img, const char *name) {
    if(!img || !name) return NULL;
    for(uint32_t i = 0; i < img->section_count; i++)
        if(strncmp(img->sections[i].name, name, CBAE_SEC_NAME_MAX) == 0)
            return &img->sections[i];
    return NULL;
}

const uint8_t *cbae_image_va_to_ptr(const cbae_binary_image_t *img, cbae_addr_t va) {
    cbae_section_t *sec = cbae_image_section_at_va(img, va);
    if(!sec) return NULL;
    return cbae_section_va_to_ptr(sec, va);
}

cbae_addr_t cbae_image_offset_to_va(const cbae_binary_image_t *img, cbae_off_t offset) {
    if(!img) return CBAE_ADDR_INVALID;
    for(uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        if(offset >= s->file_offset && offset - s->file_offset < s->file_size && offset - s->file_offset < s->virt_size)   /* a section that is not loaded has no address */
            return s->virt_addr + (offset - s->file_offset);
    }
    return CBAE_ADDR_INVALID;
}

cbae_symbol_t *cbae_image_symbol_at_va(const cbae_binary_image_t *img, cbae_addr_t va) {
    if(!img) return NULL;
    void *val = NULL;
    cbae_hashmap_get(&img->va_to_symbol, (uint64_t)va, &val);
    return (cbae_symbol_t *)val;
}

cbae_symbol_t *cbae_image_symbol_by_name(const cbae_binary_image_t *img, const char *name) {
    if(!img || !name) return NULL;
    /* find, not intern: a query for a name the image does not have must not grow the pool (A-031) */
    const char *interned = cbae_string_pool_find(img->strings, name);
    if(!interned) return NULL;
    void *val = NULL;
    cbae_hashmap_get(&img->name_to_symbol, (uint64_t)(uintptr_t)interned, &val);
    return (cbae_symbol_t *)val;
}

cbae_import_entry_t *cbae_image_import_at_iat(const cbae_binary_image_t *img, cbae_addr_t iat_va) {
    if(!img) return NULL;
    void *val = NULL;
    cbae_hashmap_get(&img->iat_to_import, (uint64_t)iat_va, &val);
    return (cbae_import_entry_t *)val;
}

cbae_import_entry_t *cbae_image_import_by_name(const cbae_binary_image_t *img, const char *name) {
    if(!img || !name) return NULL;
    for(uint32_t i = 0; i < img->import_count; i++)
        if(strncmp(img->imports[i].name, name, CBAE_IMPORT_NAME_MAX) == 0)
            return &img->imports[i];
    return NULL;
}

void cbae_image_log_summary(const cbae_binary_image_t *img) {
    if(!img) return;
    LOG_INFO("=== Binary Image Summary ===");
    LOG_INFO("  Path    : %s", img->path[0] ? img->path : "(none)");
    LOG_INFO("  Format  : %s", cbae_fmt_str(img->format));
    LOG_INFO("  Arch    : %s", cbae_arch_str(img->arch));
    LOG_INFO("  Sections: %u  Symbols: %u  Imports: %u  Relocs: %u",
             img->section_count, img->symbol_count,
             img->import_count, img->reloc_count);
    if(img->sha256[0]) LOG_INFO("  SHA-256 : %s", img->sha256);
    if(img->note_count) LOG_INFO("  Notes   : %u (the loader coped with oddities in this file)", img->note_count);
    LOG_INFO("============================");
}
