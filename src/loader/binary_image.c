/**
 * @file binary_image.c
 * @brief Unified binary image lifecycle, index building, and lookup operations.
 */
#include "loader/binary_image.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
  #include <sys/mman.h>
  #include <unistd.h>
#endif

#define IMAGE_DEFAULT_ARENA_SIZE   (8 * 1024 * 1024)
#define IMAGE_HASHMAP_INIT_CAP     256

cbae_err_t cbae_image_create(cbae_size_t arena_size, cbae_binary_image_t **out) {
    if(!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out is NULL");
    if(arena_size == 0) arena_size = IMAGE_DEFAULT_ARENA_SIZE;
    cbae_binary_image_t *img = calloc(1, sizeof(*img));
    if(!img) CBAE_RETURN_ERR(CBAE_ERR_OOM, "calloc binary_image_t failed");
    cbae_err_t err = cbae_arena_init(&img->arena, arena_size);
    if(err != CBAE_OK) { free(img); return err; }
    err = cbae_string_pool_init(&img->strings, 512);
    if(err != CBAE_OK) { cbae_arena_destroy(&img->arena); free(img); return err; }
    cbae_hashmap_init(&img->va_to_section,  IMAGE_HASHMAP_INIT_CAP);
    cbae_hashmap_init(&img->va_to_symbol,   IMAGE_HASHMAP_INIT_CAP);
    cbae_hashmap_init(&img->iat_to_import,  IMAGE_HASHMAP_INIT_CAP);
    cbae_hashmap_init(&img->name_to_symbol, IMAGE_HASHMAP_INIT_CAP);
    img->db_id   = -1;
    img->mmap_fd = -1;
    *out = img;
    LOG_DEBUG("binary_image created (arena=%zu MB)", arena_size/(1024*1024));
    return CBAE_OK;
}

cbae_err_t cbae_image_build_indexes(cbae_binary_image_t *img) {
    if(!img) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "img is NULL");
    cbae_err_t err;
    for(uint32_t i = 0; i < img->section_count; i++) {
        cbae_section_t *s = &img->sections[i];
        err = cbae_hashmap_insert(&img->va_to_section, (uint64_t)s->virt_addr, s);
        if(err != CBAE_OK) CBAE_RETURN_ERR(err, "build_indexes: section %u", i);
    }
    for(uint32_t i = 0; i < img->symbol_count; i++) {
        cbae_symbol_t *sym = &img->symbols[i];
        if(cbae_symbol_is_resolved(sym)) {
            void *existing = NULL;
            if(!cbae_hashmap_get(&img->va_to_symbol, (uint64_t)sym->address, &existing)) {
                cbae_hashmap_insert(&img->va_to_symbol, (uint64_t)sym->address, sym);
            } else {
                cbae_symbol_t *ex = (cbae_symbol_t *)existing;
                if(sym->type == CBAE_SYM_EXPORT && ex->type != CBAE_SYM_EXPORT)
                    cbae_hashmap_insert(&img->va_to_symbol, (uint64_t)sym->address, sym);
            }
        }
        if(sym->name[0] != '\0') {
            const char *interned = cbae_string_pool_intern(img->strings, sym->name);
            if(interned)
                cbae_hashmap_insert(&img->name_to_symbol, (uint64_t)(uintptr_t)interned, sym);
        }
    }
    for(uint32_t i = 0; i < img->import_count; i++) {
        cbae_import_entry_t *imp = &img->imports[i];
        if(cbae_import_has_iat(imp)) {
            err = cbae_hashmap_insert(&img->iat_to_import, (uint64_t)imp->iat_va, imp);
            if(err != CBAE_OK) CBAE_RETURN_ERR(err, "build_indexes: import %u", i);
        }
    }
    LOG_DEBUG("image indexes built: %u sections, %u symbols, %u imports",
              img->section_count, img->symbol_count, img->import_count);
    return CBAE_OK;
}

void cbae_image_destroy(cbae_binary_image_t **img) {
    if(!img || !*img) return;
    cbae_binary_image_t *m = *img;
    if(m->file_data && m->file_size > 0) {
#ifndef _WIN32
        munmap((void *)m->file_data, m->file_size);
#endif
        m->file_data = NULL;
    }
    if(m->mmap_fd >= 0) { close(m->mmap_fd); m->mmap_fd = -1; }
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
        if(offset >= s->file_offset && offset < s->file_offset + s->file_size)
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
    const char *interned = cbae_string_pool_intern(
                               (cbae_string_pool_t *)img->strings, name);
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
    LOG_INFO("============================");
}
