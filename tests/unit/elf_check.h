/*
 * elf_check.h - what every image the ELF loader returns must satisfy, whatever the file said.
 *
 * A hostile or damaged file may make the loader refuse it, or clamp, skip or cut something (and say so in
 * a note), but it may never make the loader hand back an image whose pointers, counts, ranges or strings
 * are not what binary_image.h and elf_loader.h promise. elf_check_image() states those promises once; the
 * sweeps in test_elf_loader.c and test_elf_hostile.c call it after every successful load.
 */
#ifndef CBAE_TEST_ELF_CHECK_H
#define CBAE_TEST_ELF_CHECK_H

#include "loader/elf_loader.h"
#include "platform/sha256.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static inline size_t ec_strnlen(const char *s, size_t cap) { size_t n = 0; while (n < cap && s[n]) n++; return n; }

/* the loaded section (one with an address range) that holds va, or the first of them if they overlap */
static inline const cbae_section_t *ec_section_of(const cbae_binary_image_t *img, uint64_t va) {
    for (uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        if (s->virt_size && va >= s->virt_addr && va - s->virt_addr < s->virt_size) return s;
    }
    return NULL;
}

/* @p file is the byte string that was loaded (n bytes). */
static inline void elf_check_image(const cbae_binary_image_t *img, const uint8_t *file, size_t n) {
    assert(img);
    assert(img->format == CBAE_FMT_ELF64 && img->os_origin == CBAE_OS_LINUX && img->load_base == 0);
    const uint16_t etype = n >= 18 ? (uint16_t)(file[16] | (file[17] << 8)) : 0;
    const bool rel = etype == 1;

    /* the image owns an exact copy of the file, and says what it hashes to */
    assert(img->file_data && img->file_size == n && (n == 0 || memcmp(img->file_data, file, n) == 0));
    uint8_t dg[32];
    char hex[65];
    cbae_sha256(file, n, dg);
    cbae_sha256_hex(dg, hex);
    assert(strcmp(img->sha256, hex) == 0);
    assert(img->entry_point == CBAE_ADDR_INVALID || img->entry_point != 0);
    if (rel) assert(img->entry_point == CBAE_ADDR_INVALID);

    /* sections: contents point into the file, never past its end; loaded ranges do not wrap */
    assert(img->section_count <= n / 64 && (img->section_count == 0 || img->sections));
    uint64_t prev_end = 0;
    for (uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        assert(ec_strnlen(s->name, CBAE_SEC_NAME_MAX) < CBAE_SEC_NAME_MAX);
        const bool loaded = (s->flags & CBAE_SEC_READ) != 0;
        if (s->file_size) {
            assert(s->data);
            assert(s->file_offset <= n && s->file_size <= n - s->file_offset);
            assert(s->data == img->file_data + s->file_offset);
        } else {
            assert(s->data == NULL);
        }
        if (s->flags & CBAE_SEC_BSS) assert(s->file_size == 0);
        if (s->flags & (CBAE_SEC_EXEC | CBAE_SEC_WRITE)) assert(loaded);
        if (!loaded) {
            assert(s->virt_addr == 0 && s->virt_size == 0);
            continue;
        }
        assert(s->virt_size <= ((uint64_t)1 << 40) && s->virt_size <= UINT64_MAX - s->virt_addr);
        assert(s->file_size <= s->virt_size);
        if (rel) {                                              /* the loader's own layout: ascending, page aligned, no overlap */
            assert(s->virt_addr >= CBAE_ELF_REL_BASE && s->virt_addr % 0x1000 == 0);
            assert(s->virt_addr >= prev_end);
            prev_end = s->virt_addr + s->virt_size;
        }
    }

    /* symbols */
    assert(img->symbol_count <= n && (img->symbol_count == 0 || img->symbols));
    uint32_t n_import_syms = 0;
    for (uint32_t i = 0; i < img->symbol_count; i++) {
        const cbae_symbol_t *y = &img->symbols[i];
        assert(ec_strnlen(y->name, CBAE_SYM_NAME_MAX) < CBAE_SYM_NAME_MAX);
        assert(ec_strnlen(y->source, CBAE_SYM_SOURCE_MAX) < CBAE_SYM_SOURCE_MAX);
        assert(y->table_index == i);
        if (y->type == CBAE_SYM_IMPORT) { n_import_syms++; assert(y->address == CBAE_ADDR_INVALID && strcmp(y->source, "kernel") == 0); }
        if (y->type == CBAE_SYM_FILE) assert(y->address == CBAE_ADDR_INVALID);
        if (y->type == CBAE_SYM_SECTION) assert(y->kind == CBAE_KIND_NOTYPE);
        if (y->type == CBAE_SYM_LOCAL) assert(y->binding == CBAE_BIND_LOCAL);
        if (y->type == CBAE_SYM_EXPORT) assert(y->binding != CBAE_BIND_LOCAL);
        if (rel && y->address != CBAE_ADDR_INVALID && y->section_idx != 0xFFF1) {   /* not ABS: in or at the end of a loaded section */
            bool ok = false;
            for (uint32_t k = 0; k < img->section_count && !ok; k++) {
                const cbae_section_t *s = &img->sections[k];
                if ((s->flags & CBAE_SEC_READ) && y->address >= s->virt_addr && y->address - s->virt_addr <= s->virt_size) ok = true;
            }
            assert(ok);
        }
        if (y->name[0]) {
            const cbae_symbol_t *found = cbae_image_symbol_by_name(img, y->name);
            if (y->type == CBAE_SYM_SECTION || y->type == CBAE_SYM_FILE) assert(found != y);
            else assert(found && strcmp(found->name, y->name) == 0);
        }
        if (y->type != CBAE_SYM_SECTION && y->type != CBAE_SYM_FILE && cbae_symbol_is_resolved(y)) {
            const cbae_symbol_t *at = cbae_image_symbol_at_va(img, y->address);
            assert(at && at->address == y->address && at->type != CBAE_SYM_SECTION && at->type != CBAE_SYM_FILE);
        }
    }

    /* relocations */
    uint64_t n_rela_sections = 0;                               /* relocation sections may share one table of entries: the bound is per section */
    for (uint32_t i = 0; i < img->section_count; i++) n_rela_sections += (img->sections[i].flags & CBAE_SEC_RELOC) != 0;
    assert(img->reloc_count <= n_rela_sections * (n / 24) && (img->reloc_count == 0 || img->relocations));
    for (uint32_t i = 0; i < img->reloc_count; i++) {
        const cbae_relocation_t *r = &img->relocations[i];
        assert(r->table_index == i && !r->applied);
        assert(r->sym_index == CBAE_RELOC_NO_SYMBOL || r->sym_index < img->symbol_count);
        if (r->references_import) assert(r->sym_index != CBAE_RELOC_NO_SYMBOL && img->symbols[r->sym_index].type == CBAE_SYM_IMPORT);
        else if (r->sym_index != CBAE_RELOC_NO_SYMBOL) assert(img->symbols[r->sym_index].type != CBAE_SYM_IMPORT);
        if (r->file_offset != (cbae_off_t)CBAE_ADDR_INVALID) {
            assert(r->file_offset < n);
            bool in_a_section = false;
            for (uint32_t k = 0; k < img->section_count; k++) {
                const cbae_section_t *s = &img->sections[k];
                if (r->file_offset >= s->file_offset && r->file_offset - s->file_offset < s->file_size) in_a_section = true;
            }
            assert(in_a_section);
        }
        if (rel) assert(ec_section_of(img, r->target_va) != NULL);
    }

    /* imports: one per undefined symbol that a relocation names, so never more than there are such symbols */
    assert(img->import_count <= n_import_syms && (img->import_count == 0 || img->imports));
    for (uint32_t i = 0; i < img->import_count; i++) {
        const cbae_import_entry_t *m = &img->imports[i];
        assert(ec_strnlen(m->name, CBAE_IMPORT_NAME_MAX) < CBAE_IMPORT_NAME_MAX);
        assert(strcmp(m->module, "kernel") == 0);
        assert(m->table_index == i && m->iat_va == CBAE_ADDR_INVALID && !cbae_import_has_iat(m));
        assert(m->state == CBAE_IMPORT_UNRESOLVED);
        assert(m->rela_offset == (cbae_off_t)CBAE_ADDR_INVALID || m->rela_offset < n);
    }

    /* the arena holds exactly what the plan said: used <= capacity, and not much unused */
    assert(img->arena.used <= img->arena.capacity);
    assert(img->arena.capacity - img->arena.used <= 4 * 16 + 16);

    /* diagnostics */
    const uint32_t kept = img->note_count < CBAE_IMAGE_NOTES_MAX ? img->note_count : CBAE_IMAGE_NOTES_MAX;
    for (uint32_t i = 0; i < kept; i++) assert(img->notes[i][0] != '\0' && ec_strnlen(img->notes[i], CBAE_IMAGE_NOTE_LEN) < CBAE_IMAGE_NOTE_LEN);

    /* a loaded section's first address is answered by that section; overlap only in a linked file */
    for (uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        if (!(s->flags & CBAE_SEC_READ) || s->virt_size == 0) continue;
        const cbae_section_t *at = cbae_image_section_at_va(img, s->virt_addr);
        assert(at && cbae_section_contains_va(at, s->virt_addr));
        if (rel) assert(at == s);
    }
}

#endif /* CBAE_TEST_ELF_CHECK_H */
