/*
 * pe_check.h - what every image the PE loader returns must satisfy, whatever the file said.
 *
 * A hostile or damaged file may make the loader refuse it, or clamp a table, but it may never make
 * the loader hand back an image whose pointers, counts or strings are not what the headers of
 * binary_image.h promise. pe_check_image() states those promises once; the sweeps in test_pe_loader.c
 * and test_pe_hostile.c call it after every successful load.
 */
#ifndef CBAE_TEST_PE_CHECK_H
#define CBAE_TEST_PE_CHECK_H

#include "loader/pe_loader.h"
#include "platform/sha256.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static inline size_t pc_strnlen(const char *s, size_t cap) { size_t n = 0; while (n < cap && s[n]) n++; return n; }

/* The section that owns an address: the first in table order whose memory holds it. Written out here, not asked of the image's own
 * index, so the check does not depend on the thing it is checking. */
static inline const cbae_section_t *pc_first_section(const cbae_binary_image_t *img, cbae_addr_t va) {
    for (uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        if (va >= s->virt_addr && va - s->virt_addr < s->virt_size) return s;
    }
    return NULL;
}

/* @p file is the byte string that was loaded (n bytes). */
static inline void pe_check_image(const cbae_binary_image_t *img, const uint8_t *file, size_t n) {
    assert(img);
    assert(img->format == CBAE_FMT_PE32PLUS && img->os_origin == CBAE_OS_WINDOWS);

    /* the image owns an exact copy of the file, and says what it hashes to */
    assert(img->file_data && img->file_size == n && (n == 0 || memcmp(img->file_data, file, n) == 0));
    uint8_t dg[32];
    char hex[65];
    cbae_sha256(file, n, dg);
    cbae_sha256_hex(dg, hex);
    assert(strcmp(img->sha256, hex) == 0);

    /* sections: data points into the file, never past its end; nothing wraps */
    assert(img->section_count <= 96 && (img->section_count == 0 || img->sections));
    for (uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        assert(pc_strnlen(s->name, CBAE_SEC_NAME_MAX) < CBAE_SEC_NAME_MAX);
        assert(s->file_size <= s->virt_size);
        assert(s->virt_addr >= img->load_base && s->virt_addr + s->virt_size >= s->virt_addr);
        if (s->file_size) {
            assert(s->data);
            assert(s->data >= img->file_data && s->data + s->file_size <= img->file_data + n);
            assert(s->data == img->file_data + s->file_offset);
        } else {
            assert(s->data == NULL);
        }
    }

    /* symbols */
    assert(img->symbol_count == 0 || img->symbols);
    for (uint32_t i = 0; i < img->symbol_count; i++) {
        const cbae_symbol_t *y = &img->symbols[i];
        assert(pc_strnlen(y->name, CBAE_SYM_NAME_MAX) < CBAE_SYM_NAME_MAX);
        assert(pc_strnlen(y->source, CBAE_SYM_SOURCE_MAX) < CBAE_SYM_SOURCE_MAX);
        assert(y->table_index == i && y->type == CBAE_SYM_EXPORT);
        assert(y->address == CBAE_ADDR_INVALID || y->address >= img->load_base);
        const cbae_symbol_t *found = cbae_image_symbol_by_name(img, y->name);
        if (y->name[0]) assert(found && strcmp(found->name, y->name) == 0);
        /* a forwarder has no address; anything else is code, data or neither, as the section that holds its address says */
        if (strncmp(y->source, "fwd:", 4) == 0) {
            assert(y->address == CBAE_ADDR_INVALID && y->kind == CBAE_KIND_FUNCTION);
        } else {
            const cbae_section_t *at = pc_first_section(img, y->address);
            assert(y->address != CBAE_ADDR_INVALID && y->source[0] == '\0');
            assert(y->kind == (!at ? CBAE_KIND_NOTYPE : (at->flags & CBAE_SEC_EXEC) ? CBAE_KIND_FUNCTION : CBAE_KIND_OBJECT));
        }
    }

    /* imports */
    assert(img->import_count == 0 || img->imports);
    for (uint32_t i = 0; i < img->import_count; i++) {
        const cbae_import_entry_t *m = &img->imports[i];
        assert(pc_strnlen(m->name, CBAE_IMPORT_NAME_MAX) < CBAE_IMPORT_NAME_MAX);
        assert(pc_strnlen(m->module, CBAE_IMPORT_MODULE_MAX) < CBAE_IMPORT_MODULE_MAX);
        assert(m->table_index == i && m->iat_va >= img->load_base);
        assert(cbae_image_import_at_iat(img, m->iat_va) != NULL);
    }

    /* relocations */
    assert(img->reloc_count == 0 || img->relocations);
    for (uint32_t i = 0; i < img->reloc_count; i++) {
        const cbae_relocation_t *r = &img->relocations[i];
        assert(r->table_index == i && r->target_va >= img->load_base);
        assert(r->file_offset == (cbae_off_t)CBAE_ADDR_INVALID || r->file_offset < n);
        /* the bytes a relocation names are the bytes its address has: in a section's file data they are at that section's offset, in a
         * section's zero-filled tail there are none, and outside every section only the headers (RVA == file offset) can hold them */
        const cbae_section_t *at = pc_first_section(img, r->target_va);
        if (at && r->target_va - at->virt_addr < at->file_size)
            assert(r->file_offset == (cbae_off_t)(at->file_offset + (r->target_va - at->virt_addr)));
        else if (at)
            assert(r->file_offset == (cbae_off_t)CBAE_ADDR_INVALID);
        else
            assert(r->file_offset == (cbae_off_t)CBAE_ADDR_INVALID || r->file_offset == (cbae_off_t)(r->target_va - img->load_base));
    }

    /* the arena holds exactly what the plan said: used <= capacity, and not much unused */
    assert(img->arena.used <= img->arena.capacity);
    assert(img->arena.capacity - img->arena.used <= 4 * 16 + 16);

    /* diagnostics */
    const uint32_t kept = img->note_count < CBAE_IMAGE_NOTES_MAX ? img->note_count : CBAE_IMAGE_NOTES_MAX;
    for (uint32_t i = 0; i < kept; i++) assert(img->notes[i][0] != '\0' && pc_strnlen(img->notes[i], CBAE_IMAGE_NOTE_LEN) < CBAE_IMAGE_NOTE_LEN);

    /* the section index answers for every section's first address: with that section, or, if sections
     * overlap in memory, with the first of them, and then the loader must have said so */
    for (uint32_t i = 0; i < img->section_count; i++) {
        const cbae_section_t *s = &img->sections[i];
        if (s->virt_size == 0) continue;
        const cbae_section_t *at = cbae_image_section_at_va(img, s->virt_addr);
        assert(at && cbae_section_contains_va(at, s->virt_addr));
        assert(at == s || img->note_count > 0);
    }
}

#endif /* CBAE_TEST_PE_CHECK_H */
