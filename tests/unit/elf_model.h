/*
 * elf_model.h - what the ELF loader must make of an eb_spec_t, worked out from the rules in
 * elf_loader.h and the ELF specification, without looking at the loader. em_check() compares the image
 * the loader returned with that expectation, field by field: every section, symbol, relocation and import.
 *
 * Scope: descriptions made by elf_builder.h that have a symbol table, no section of type SHT_NULL among the
 * user's, and at most EB_LAYOUT_SECS sections in all (the builder reports positions for that many). The
 * pseudo-exports from __ksymtab_strings come after the symbols the model checks; their number is a
 * parameter and their contents are the test's own business.
 */
#ifndef CBAE_TEST_ELF_MODEL_H
#define CBAE_TEST_ELF_MODEL_H

#include "elf_builder.h"
#include "loader/elf_loader.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define EM_PAGE 0x1000u
#define EM_MAX_ALIGN ((uint64_t)1 << 20)
#define EM_MAX_VSIZE ((uint64_t)1 << 40)

typedef struct { bool loaded; uint32_t type; uint64_t flags, size, va, vsize; } em_sec_t;

static inline uint64_t em_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static inline bool em_pow2(uint64_t a) { return a && !(a & (a - 1)); }

/* the header fields of section i (1 <= i <= nsec + pads), as the description gives them */
static inline void em_header(const eb_spec_t *sp, uint32_t i, uint32_t *type, uint64_t *flags, uint64_t *align, uint64_t *size, uint64_t *addr) {
    if (i <= (uint32_t)sp->nsec) {
        const eb_section_t *u = &sp->sec[i - 1];
        *type = u->type; *flags = u->flags; *align = u->align; *size = u->size; *addr = u->addr;
    } else {
        *type = EB_SHT_PROGBITS; *flags = sp->pad_flags; *align = 1; *size = 0; *addr = 0;
    }
}

/* the address range of each user and pad section; the caller frees */
static inline em_sec_t *em_layout(const eb_spec_t *sp) {
    const uint32_t total = (uint32_t)sp->nsec + sp->pad_sections;
    em_sec_t *m = (em_sec_t *)calloc(1 + total, sizeof *m);
    assert(m);
    uint64_t cursor = CBAE_ELF_REL_BASE;
    for (uint32_t i = 1; i <= total; i++) {
        uint32_t type; uint64_t flags, align, size, addr;
        em_header(sp, i, &type, &flags, &align, &size, &addr);
        m[i].type = type; m[i].flags = flags; m[i].size = size;
        assert(type != EB_SHT_NULL);
        if (!(flags & EB_SHF_ALLOC)) continue;
        m[i].loaded = true;
        uint64_t vs = em_min(size, EM_MAX_VSIZE);
        if (sp->etype == EB_ET_REL) {
            uint64_t a = align;
            if (a > 1 && !em_pow2(a)) a = 1;
            if (a > EM_MAX_ALIGN) a = EM_MAX_ALIGN;
            if (a < EM_PAGE) a = EM_PAGE;
            const uint64_t start = (cursor + a - 1) / a * a;
            m[i].va = start; m[i].vsize = vs;
            cursor = start + vs;
        } else {
            if (addr > UINT64_MAX - vs) vs = UINT64_MAX - addr;
            m[i].va = addr; m[i].vsize = vs;
        }
    }
    return m;
}

static inline uint32_t em_reloc_type(uint16_t machine, uint32_t t) {
    if (t == EB_R_X86_64_NONE) return CBAE_RELOC_NOP;
    if (machine != EB_EM_X86_64) return CBAE_RELOC_UNKNOWN;
    switch (t) {
    case EB_R_X86_64_64: return CBAE_RELOC_64;
    case EB_R_X86_64_PC32: return CBAE_RELOC_PC32;
    case EB_R_X86_64_PLT32: return CBAE_RELOC_PLT32;
    case EB_R_X86_64_32: return CBAE_RELOC_ABS32;
    case EB_R_X86_64_32S: return CBAE_RELOC_32S;
    case EB_R_X86_64_GOTPCREL: case EB_R_X86_64_GOTPCRELX: case EB_R_X86_64_REX_GOTPCRELX: return CBAE_RELOC_GOTPCREL;
    default: return CBAE_RELOC_UNKNOWN;
    }
}

static inline void em_cut(char *dst, const char *src, size_t cap) {      /* a name as the image holds it: at most cap - 1 bytes */
    const size_t l = src ? strlen(src) : 0;
    const size_t c = l < cap - 1 ? l : cap - 1;
    if (c) memcpy(dst, src, c);
    dst[c] = '\0';
}

/* the name of section idx (1 <= idx < shnum) as the section name table holds it, uncut */
static inline void em_secname(const eb_spec_t *sp, const eb_layout_t *L, uint32_t idx, char *dst, size_t cap) {
    const uint32_t U = (uint32_t)sp->nsec, total = U + sp->pad_sections;
    if (idx <= U) { snprintf(dst, cap, "%s", sp->sec[idx - 1].name ? sp->sec[idx - 1].name : ""); return; }
    if (idx <= total) { snprintf(dst, cap, ".pad"); return; }
    if (idx == L->symtab) { snprintf(dst, cap, ".symtab"); return; }
    if (idx == L->strtab) { snprintf(dst, cap, ".strtab"); return; }
    if (idx == L->shstrtab) { snprintf(dst, cap, ".shstrtab"); return; }
    if (idx == L->shndx_tab) { snprintf(dst, cap, ".symtab_shndx"); return; }
    for (uint32_t k = 0; k < L->nrelsec; k++)
        if (L->rela_idx[k] == idx) {
            const uint32_t t = L->rela_target[k];
            snprintf(dst, cap, ".rela%s", t >= 1 && t <= U ? (sp->sec[t - 1].name ? sp->sec[t - 1].name : "") : ".x");
            return;
        }
    assert(!"a section index the builder did not make");
}

/* undefined, and not a file or section symbol; xindex only says where the index is stored, not what it is */
static inline bool em_sym_is_import(const eb_symbol_t *y) {
    const unsigned st = y->info & 0xF;
    return y->shndx == EB_SHN_UNDEF && st != EB_STT_FILE && st != EB_STT_SECTION;
}

/*
 * Compares the whole image with the expectation. @p pseudo is how many pseudo-exports the test expects
 * after the symbols (it checks those itself).
 */
static inline void em_check(const eb_spec_t *sp, const eb_layout_t *L, const cbae_binary_image_t *img, uint32_t pseudo) {
    assert(!sp->no_symtab && L->shnum <= EB_LAYOUT_SECS);
    const bool rel = sp->etype == EB_ET_REL;
    const uint32_t U = (uint32_t)sp->nsec, P = sp->pad_sections, total = U + P;
    (void)U;
    em_sec_t *m = em_layout(sp);

    /* sections: the user's, the pads, then what the builder adds, in table order */
    assert(img->section_count == L->shnum - 1);
    for (uint32_t i = 1; i < L->shnum; i++) {
        const cbae_section_t *s = &img->sections[i - 1];
        char full[160], want[CBAE_SEC_NAME_MAX];
        em_secname(sp, L, i, full, sizeof full);
        em_cut(want, full, sizeof want);
        assert(strcmp(s->name, want) == 0);

        uint64_t file_size = L->sec_size[i];
        if (i <= total) {
            uint32_t type; uint64_t flags, align, size, addr;
            em_header(sp, i, &type, &flags, &align, &size, &addr);
            uint32_t f = 0;
            if (flags & EB_SHF_ALLOC) { f |= CBAE_SEC_READ; if (flags & EB_SHF_EXECINSTR) f |= CBAE_SEC_EXEC; if (flags & EB_SHF_WRITE) f |= CBAE_SEC_WRITE; }
            if (type == EB_SHT_NOBITS) f |= CBAE_SEC_BSS;
            if (type == EB_SHT_RELA || type == EB_SHT_REL) f |= CBAE_SEC_RELOC;
            assert(s->flags == f);
            assert(s->virt_addr == (m[i].loaded ? m[i].va : 0) && s->virt_size == (m[i].loaded ? m[i].vsize : 0));
            if (type == EB_SHT_NOBITS) file_size = 0;
            else if (m[i].loaded) file_size = em_min(file_size, m[i].vsize);
        } else {
            const bool is_rela = i != L->symtab && i != L->strtab && i != L->shstrtab && i != L->shndx_tab;
            assert(s->flags == (is_rela ? (uint32_t)CBAE_SEC_RELOC : 0u));
            assert(s->virt_addr == 0 && s->virt_size == 0);
        }
        assert(s->file_size == file_size);
        assert(s->file_offset == L->sec_off[i]);
        assert(s->data == (file_size ? img->file_data + L->sec_off[i] : NULL));
    }

    /* symbols: ELF symbol k + 1 is img->symbols[k] */
    assert(img->symbol_count == (uint32_t)sp->nsym + pseudo);
    for (int k = 0; k < sp->nsym; k++) {
        const eb_symbol_t *y = &sp->sym[k];
        const cbae_symbol_t *o = &img->symbols[k];
        const unsigned stype = y->info & 0xF, bind = y->info >> 4;
        const uint32_t shndx = y->shndx;
        assert(o->table_index == (uint32_t)k);
        assert(o->binding == (bind == EB_STB_GLOBAL || bind == EB_STB_GNU_UNIQUE ? CBAE_BIND_GLOBAL : bind == EB_STB_WEAK ? CBAE_BIND_WEAK : CBAE_BIND_LOCAL));
        cbae_sym_kind_t kind = CBAE_KIND_UNKNOWN;
        if (stype == EB_STT_FUNC || stype == EB_STT_GNU_IFUNC) kind = CBAE_KIND_FUNCTION;
        else if (stype == EB_STT_OBJECT || stype == EB_STT_COMMON || stype == EB_STT_TLS) kind = CBAE_KIND_OBJECT;
        else if (stype == EB_STT_NOTYPE || stype == EB_STT_SECTION || stype == EB_STT_FILE) kind = CBAE_KIND_NOTYPE;
        assert(o->kind == kind);
        assert(o->size == y->size);
        /* a number from the extended table that does not fit the 16-bit field, or would read as a reserved value, is SHN_XINDEX */
        assert(o->section_idx == (((y->xindex && shndx >= EB_SHN_LORESERVE) || shndx > 0xFFFF) ? 0xFFFF : (uint16_t)shndx));

        cbae_sym_type_t type;
        if (stype == EB_STT_FILE) type = CBAE_SYM_FILE;
        else if (stype == EB_STT_SECTION) type = CBAE_SYM_SECTION;
        else if (shndx == EB_SHN_UNDEF) type = CBAE_SYM_IMPORT;
        else type = o->binding == CBAE_BIND_LOCAL ? CBAE_SYM_LOCAL : CBAE_SYM_EXPORT;
        assert(o->type == type);

        char full[160], name[CBAE_SYM_NAME_MAX];
        if (stype == EB_STT_SECTION) {                          /* a section symbol is named for its section, as the file has the name, cut to a symbol name's length */
            if (shndx >= 1 && shndx < L->shnum) em_secname(sp, L, shndx, full, sizeof full);
            else full[0] = '\0';
            em_cut(name, full, sizeof name);
        } else {
            em_cut(name, y->name, sizeof name);
        }
        assert(strcmp(o->name, name) == 0);
        assert(strcmp(o->source, type == CBAE_SYM_IMPORT ? "kernel" : "") == 0);

        uint64_t addr = CBAE_ADDR_INVALID;
        /* ABS, COMMON and the other reserved values are meaningful only in st_shndx itself, not when the index is in the extended table */
        if (type == CBAE_SYM_IMPORT || type == CBAE_SYM_FILE || stype == EB_STT_COMMON || stype == EB_STT_TLS || (!y->xindex && shndx == EB_SHN_COMMON)) {
            /* nothing is placed */
        } else if (!y->xindex && shndx == EB_SHN_ABS) {
            addr = y->value;
        } else if ((!y->xindex && shndx >= EB_SHN_LORESERVE) || shndx >= L->shnum) {
            /* reserved, or not a section */
        } else if (shndx <= total && m[shndx].loaded) {
            if (!rel) addr = y->value;
            else if (y->value <= m[shndx].vsize) addr = m[shndx].va + y->value;
        }
        assert(o->address == addr);
    }

    /* relocations: grouped by relocation section in table order, loaded targets only (ET_REL) */
    uint32_t nrel = 0, nimp = 0;
    bool seen[EB_MAX_SYM + 2];
    memset(seen, 0, sizeof seen);
    for (uint32_t g = 0; g < L->nrelsec; g++) {
        const uint32_t tgt = L->rela_target[g];
        if (rel && !(tgt >= 1 && tgt <= total && m[tgt].loaded)) continue;
        for (int i = 0; i < sp->nrel; i++) {
            const eb_rela_t *e = &sp->rel[i];
            if (e->target != tgt) continue;
            uint64_t va = e->offset, file_off = CBAE_ADDR_INVALID;
            if (rel) {
                if (e->offset >= m[tgt].vsize) continue;
                va = m[tgt].va + e->offset;
                if (m[tgt].type != EB_SHT_NOBITS && e->offset < m[tgt].size) file_off = (uint64_t)L->sec_off[tgt] + e->offset;
            }
            assert(nrel < img->reloc_count);
            const cbae_relocation_t *r = &img->relocations[nrel];
            assert(r->table_index == nrel && !r->applied);
            assert(r->target_va == va && r->file_offset == file_off);
            assert(r->type == em_reloc_type(sp->machine, e->type) && r->addend == e->addend);
            const bool sym_ok = e->sym != 0 && e->sym <= (uint32_t)sp->nsym;
            assert(r->sym_index == (sym_ok ? e->sym - 1 : CBAE_RELOC_NO_SYMBOL));
            const bool import = sym_ok && em_sym_is_import(&sp->sym[e->sym - 1]);
            assert(r->references_import == import);
            nrel++;
            if (import && !seen[e->sym]) {
                seen[e->sym] = true;
                assert(nimp < img->import_count);
                const cbae_import_entry_t *im = &img->imports[nimp];
                char name[CBAE_IMPORT_NAME_MAX];
                em_cut(name, sp->sym[e->sym - 1].name, sizeof name);
                assert(strcmp(im->name, name) == 0 && strcmp(im->module, "kernel") == 0);
                assert(im->table_index == nimp && im->iat_va == CBAE_ADDR_INVALID);
                assert(im->rela_offset == file_off && im->rela_type == e->type && im->state == CBAE_IMPORT_UNRESOLVED);
                nimp++;
            }
        }
    }
    assert(nrel == img->reloc_count && nimp == img->import_count);

    /* header facts */
    assert(img->arch == (sp->machine == EB_EM_X86_64 ? CBAE_ARCH_X86_64 : sp->machine == EB_EM_AARCH64 ? CBAE_ARCH_ARM64 : CBAE_ARCH_UNKNOWN));
    assert(img->entry_point == ((!rel && sp->entry) ? sp->entry : CBAE_ADDR_INVALID));
    free(m);
}

#endif /* CBAE_TEST_ELF_MODEL_H */
