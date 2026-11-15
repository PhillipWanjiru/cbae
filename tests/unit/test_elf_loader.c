/**
 * @file test_elf_loader.c
 * @brief ELF64 loader tests (audit A-036, A-037, A-038).
 *
 * Every file here is written by elf_builder.h from the ELF gABI and the x86-64 psABI, not from the
 * loader's idea of the format, and what the loader must make of it is stated twice: in numbers worked out
 * by hand (the default file) and by elf_model.h (every random file). The first version of this test
 * used one hand-laid fixture and eleven checks; it passed for a loader that gave every section the
 * address index * 0x400000 and read relocation and symbol tables through a stride taken from the file.
 *
 *   - the default file (a small driver-like module), checked field by field
 *   - where sections go: layout of a relocatable object, alignment rules, linked files
 *   - the tables' edge cases: symbol addresses and names, relocation targets, imports, extended numbering
 *   - .modinfo and __ksymtab_strings
 *   - headers: each kind of damage, with the error code it must give; each oddity that is only noted
 *   - loading from a path
 *   - a model check: random specifications, the loader's output compared with what the spec says
 *   - an out-of-memory sweep over the whole load
 * The sweeps over damaged files are in test_elf_hostile.c.
 */
#include "loader/elf_loader.h"
#include "platform/file_io.h"
#include "oom_sweep.h"
#include "elf_builder.h"
#include "elf_check.h"
#include "elf_model.h"
#include "elf_random.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define R_   CBAE_SEC_READ
#define X_   CBAE_SEC_EXEC
#define W_   CBAE_SEC_WRITE
#define B_   CBAE_SEC_BSS
#define RL_  CBAE_SEC_RELOC
#define AX   (EB_SHF_ALLOC | EB_SHF_EXECINSTR)
#define AW   (EB_SHF_ALLOC | EB_SHF_WRITE)
#define NOSYM CBAE_RELOC_NO_SYMBOL

/* ---- helpers ---- */

static cbae_binary_image_t *load_ok(const eb_file_t *f) {
    cbae_binary_image_t *img = NULL;
    const cbae_err_t rc = cbae_elf_load_buffer(f->b, f->n, "t.ko", &img);
    if (rc != CBAE_OK) fprintf(stderr, "load failed: %s\n", cbae_last_error());
    assert(rc == CBAE_OK && img);
    elf_check_image(img, f->b, f->n);
    return img;
}

static cbae_err_t load_err_n(const uint8_t *b, size_t n) {
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_elf_load_buffer(b, n, "t.ko", &img);
    assert(rc != CBAE_OK && img == NULL);
    return rc;
}
static cbae_err_t load_err(const eb_file_t *f) { return load_err_n(f->b, f->n); }

static bool has_note(const cbae_binary_image_t *img, const char *part) {
    const uint32_t kept = img->note_count < CBAE_IMAGE_NOTES_MAX ? img->note_count : CBAE_IMAGE_NOTES_MAX;
    for (uint32_t i = 0; i < kept; i++) if (strstr(img->notes[i], part)) return true;
    return false;
}

static eb_file_t clone(const eb_file_t *f) { eb_file_t c = { eb_copy(f->b, f->n), f->n }; return c; }

static const cbae_symbol_t *sym_named(const cbae_binary_image_t *img, const char *name) {
    for (uint32_t i = 0; i < img->symbol_count; i++) if (strcmp(img->symbols[i].name, name) == 0) return &img->symbols[i];
    return NULL;
}

/* a pattern to give sections as contents; sections here are never longer than this */
static uint8_t blob[0x4000];
static void blob_init(void) { for (size_t i = 0; i < sizeof blob; i++) blob[i] = (uint8_t)(i * 7 + 1); }

static eb_spec_t blank(uint16_t etype) {
    eb_spec_t s;
    memset(&s, 0, sizeof s);
    s.etype = etype; s.machine = EB_EM_X86_64; s.ei_class = EB_CLASS64; s.ei_data = EB_DATA_LSB;
    return s;
}
static eb_section_t S(const char *name, uint32_t type, uint64_t flags, uint64_t size, uint64_t align) {
    eb_section_t s;
    memset(&s, 0, sizeof s);
    assert(type == EB_SHT_NOBITS || size <= sizeof blob);
    s.name = name; s.type = type; s.flags = flags; s.size = size; s.align = align;
    s.data = type == EB_SHT_NOBITS ? NULL : blob;
    return s;
}
static eb_symbol_t Y(const char *name, unsigned bind, unsigned type, uint32_t shndx, uint64_t value, uint64_t size) {
    eb_symbol_t y;
    memset(&y, 0, sizeof y);
    y.name = name; y.info = EB_ST_INFO_OF(bind, type); y.shndx = shndx; y.value = value; y.size = size;
    return y;
}
static eb_rela_t RA(uint32_t target, uint64_t offset, uint32_t sym, uint32_t type, int64_t addend) {
    eb_rela_t r = { target, offset, sym, type, addend };
    return r;
}

/* build, load, check against the model and the invariants */
static cbae_binary_image_t *build_and_check(const eb_spec_t *sp, eb_layout_t *L, eb_file_t *f, uint32_t pseudo) {
    *f = eb_build(sp, L);
    cbae_binary_image_t *img = load_ok(f);
    em_check(sp, L, img, pseudo);
    return img;
}

/* ---- the default file, against numbers worked out from the specification ---- */

typedef struct { const char *name; uint32_t flags; uint64_t va, vsize, fsize; } want_sec_t;
typedef struct { const char *name; cbae_sym_type_t type; cbae_sym_binding_t bind; cbae_sym_kind_t kind; uint64_t addr, size; uint16_t shndx; } want_sym_t;

static void test_default_file(void) {
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(&f);

    assert(img->format == CBAE_FMT_ELF64 && img->os_origin == CBAE_OS_LINUX && img->arch == CBAE_ARCH_X86_64);
    assert(img->load_base == 0 && img->entry_point == CBAE_ADDR_INVALID);
    assert(strcmp(img->path, "t.ko") == 0 && img->file_size == f.n);

    /* sections: in table order; the loaded ones one after another from 0x400000, each on a page */
    const uint64_t msz = sp.sec[EB_S_MODINFO - 1].size, ksz = sp.sec[EB_S_KSYMSTR - 1].size;
    const want_sec_t ws[14] = {
        { ".text",             R_ | X_,       0x400000, 0x80,  0x80 },
        { ".rodata",           R_,            0x401000, 0x40,  0x40 },
        { ".data",             R_ | W_,       0x402000, 0x20,  0x20 },
        { ".bss",              R_ | W_ | B_,  0x403000, 0x100, 0 },
        { ".modinfo",          R_,            0x404000, msz,   msz },
        { "__ksymtab_strings", R_,            0x405000, ksz,   ksz },
        { ".comment",          0,             0,        0,     18 },
        { ".debug_info",       0,             0,        0,     0x20 },
        { ".rela.text",        RL_,           0,        0,     12 * 24 },
        { ".rela.data",        RL_,           0,        0,     2 * 24 },
        { ".rela.debug_info",  RL_,           0,        0,     3 * 24 },
        { ".symtab",           0,             0,        0,     21 * 24 },
        { ".strtab",           0,             0,        0,     L.strtab_size },
        { ".shstrtab",         0,             0,        0,     L.shstrtab_size },
    };
    assert(img->section_count == 14);
    for (uint32_t i = 0; i < 14; i++) {
        const cbae_section_t *s = &img->sections[i];
        assert(strcmp(s->name, ws[i].name) == 0);
        assert(s->flags == ws[i].flags);
        assert(s->virt_addr == ws[i].va && s->virt_size == ws[i].vsize && s->file_size == ws[i].fsize);
        assert(s->file_offset == L.sec_off[i + 1]);
        assert(s->data == (ws[i].fsize ? img->file_data + L.sec_off[i + 1] : NULL));
        assert(cbae_image_section_by_name(img, ws[i].name) == s);
    }
    assert(cbae_section_is_code(&img->sections[0]) && !cbae_section_is_code(&img->sections[1]));

    /* addresses */
    assert(cbae_image_section_at_va(img, 0x400000) == &img->sections[0] && cbae_image_section_at_va(img, 0x40007F) == &img->sections[0]);
    assert(cbae_image_section_at_va(img, 0x400080) == NULL);                                  /* the gap between sections is in none */
    assert(cbae_image_section_at_va(img, 0x401000) == &img->sections[1] && cbae_image_section_at_va(img, 0x403000) == &img->sections[3]);
    assert(cbae_image_section_at_va(img, 0x1) == NULL && cbae_image_section_at_va(img, 0) == NULL);
    assert(cbae_image_va_to_ptr(img, 0x400000) == img->file_data + L.sec_off[1] && *cbae_image_va_to_ptr(img, 0x400000) == 0xE8);
    assert(*cbae_image_va_to_ptr(img, 0x400001) == 0x90 && cbae_image_va_to_ptr(img, 0x40007F) != NULL);
    assert(cbae_image_va_to_ptr(img, 0x400080) == NULL);                                      /* past the end */
    assert(cbae_image_va_to_ptr(img, 0x403000) == NULL);                                      /* .bss: no bytes in the file */
    assert(cbae_image_offset_to_va(img, L.sec_off[1] + 5) == 0x400005);
    assert(cbae_image_offset_to_va(img, L.sec_off[3]) == 0x402000);
    assert(cbae_image_offset_to_va(img, L.sec_off[7]) == CBAE_ADDR_INVALID);                  /* .comment is not loaded */
    assert(cbae_image_offset_to_va(img, L.sec_off[9]) == CBAE_ADDR_INVALID);                  /* nor is .rela.text */
    assert(cbae_image_offset_to_va(img, 0) == CBAE_ADDR_INVALID);                             /* the ELF header */

    /* symbols: ELF symbol k + 1 is symbols[k], then the names only __ksymtab_strings has */
    const cbae_sym_type_t FI = CBAE_SYM_FILE, SE = CBAE_SYM_SECTION, LO = CBAE_SYM_LOCAL, EX = CBAE_SYM_EXPORT, IM = CBAE_SYM_IMPORT;
    const cbae_sym_binding_t BL = CBAE_BIND_LOCAL, BG = CBAE_BIND_GLOBAL, BW = CBAE_BIND_WEAK;
    const cbae_sym_kind_t KN = CBAE_KIND_NOTYPE, KF = CBAE_KIND_FUNCTION, KO = CBAE_KIND_OBJECT, KU = CBAE_KIND_UNKNOWN;
    const uint64_t NA = CBAE_ADDR_INVALID;
    const want_sym_t wy[22] = {
        { "mod.c",           FI, BL, KN, NA,       0,    0xFFF1 },
        { ".text",           SE, BL, KN, 0x400000, 0,    1 },
        { ".rodata",         SE, BL, KN, 0x401000, 0,    2 },
        { ".data",           SE, BL, KN, 0x402000, 0,    3 },
        { "helper",          LO, BL, KF, 0x400030, 0x10, 1 },
        { "local_var",       LO, BL, KO, 0x402018, 8,    3 },
        { "init_module",     EX, BG, KF, 0x400000, 0x20, 1 },
        { "cleanup_module",  EX, BG, KF, 0x400020, 0x10, 1 },
        { "g_counter",       EX, BG, KO, 0x402010, 8,    3 },
        { "weak_hook",       EX, BW, KF, 0x400040, 8,    1 },
        { "printk",          IM, BG, KN, NA,       0,    0 },
        { "kmalloc",         IM, BG, KN, NA,       0,    0 },
        { "optional_api",    IM, BW, KN, NA,       0,    0 },
        { "jiffies",         IM, BG, KO, NA,       0,    0 },
        { "shared_buf",      EX, BG, KO, NA,       64,   0xFFF2 },                            /* common: placed by the linker */
        { "ABS_CONST",       EX, BG, KN, 0x1234,   0,    0xFFF1 },
        { "big_bss",         EX, BG, KO, 0x403000, 0x100, 4 },
        { "never_referenced", IM, BG, KN, NA,      0,    0 },
        { "resolver",        EX, BG, KF, 0x400048, 8,    1 },                                 /* STT_GNU_IFUNC */
        { "tls_var",         EX, BG, KO, NA,       8,    3 },                                 /* thread-local: no address */
        { "my_export",       EX, BG, KU, NA,       0,    0 },                                 /* only in __ksymtab_strings */
        { "other_export",    EX, BG, KU, NA,       0,    0 },
    };
    assert(img->symbol_count == 22);
    for (uint32_t i = 0; i < 22; i++) {
        const cbae_symbol_t *y = &img->symbols[i];
        assert(strcmp(y->name, wy[i].name) == 0 && y->type == wy[i].type && y->binding == wy[i].bind && y->kind == wy[i].kind);
        assert(y->address == wy[i].addr && y->size == wy[i].size && y->section_idx == wy[i].shndx && y->table_index == i);
        assert(strcmp(y->source, wy[i].type == IM ? "kernel" : "") == 0);
    }
    assert(cbae_symbol_is_resolved(&img->symbols[6]) && !cbae_symbol_is_resolved(&img->symbols[10]) && !cbae_symbol_is_resolved(&img->symbols[14]));
    assert(cbae_image_symbol_by_name(img, "init_module") == &img->symbols[6]);                /* the ksymtab name is not a second symbol */
    assert(cbae_image_symbol_by_name(img, "printk") == &img->symbols[10] && cbae_image_symbol_by_name(img, "my_export") == &img->symbols[20]);
    assert(cbae_image_symbol_by_name(img, ".text") == NULL && cbae_image_symbol_by_name(img, "mod.c") == NULL);   /* section and file symbols name nothing */
    assert(cbae_image_symbol_by_name(img, "nope") == NULL);
    assert(cbae_image_symbol_at_va(img, 0x400000) == &img->symbols[6]);                       /* not the section symbol at the same address */
    assert(cbae_image_symbol_at_va(img, 0x400030) == &img->symbols[4] && cbae_image_symbol_at_va(img, 0x403000) == &img->symbols[16]);
    assert(cbae_image_symbol_at_va(img, 0x400048) == &img->symbols[18] && cbae_image_symbol_at_va(img, 0x400001) == NULL);

    /* relocations: .text's twelve, then .data's two; .debug_info's three are for a section that is not loaded */
    typedef struct { cbae_reloc_type_t type; uint64_t va; uint32_t sym; bool imp; int64_t addend; } want_rel_t;
    const want_rel_t wr[14] = {
        { CBAE_RELOC_PLT32,    0x400001, 10, true,  -4 },
        { CBAE_RELOC_PLT32,    0x400011, 10, true,  -4 },
        { CBAE_RELOC_PLT32,    0x400021, 11, true,  -4 },
        { CBAE_RELOC_PC32,     0x400031, 2,  false, 0xC },                                    /* against the .rodata section symbol */
        { CBAE_RELOC_PLT32,    0x400039, 4,  false, -4 },                                     /* a local function */
        { CBAE_RELOC_PLT32,    0x400041, 12, true,  -4 },                                     /* a weak undefined one */
        { CBAE_RELOC_GOTPCREL, 0x400049, 13, true,  -4 },                                     /* GOTPCRELX */
        { CBAE_RELOC_32S,      0x400051, 3,  false, 8 },
        { CBAE_RELOC_GOTPCREL, 0x40005A, 13, true,  -4 },                                     /* REX_GOTPCRELX */
        { CBAE_RELOC_ABS32,    0x400062, 2,  false, 0x10 },
        { CBAE_RELOC_NOP,      0x40006A, 2,  false, 0 },
        { CBAE_RELOC_UNKNOWN,  0x400072, 10, true,  0 },                                      /* R_X86_64_PC64: not one the model knows */
        { CBAE_RELOC_64,       0x402000, 6,  false, 0 },
        { CBAE_RELOC_64,       0x402008, 10, true,  0 },
    };
    assert(img->reloc_count == 14);
    for (uint32_t i = 0; i < 14; i++) {
        const cbae_relocation_t *r = &img->relocations[i];
        assert(r->type == wr[i].type && r->target_va == wr[i].va && r->sym_index == wr[i].sym && r->references_import == wr[i].imp);
        assert(r->addend == wr[i].addend && r->table_index == i && !r->applied);
        const uint64_t off = i < 12 ? L.sec_off[1] + (wr[i].va - 0x400000) : L.sec_off[3] + (wr[i].va - 0x402000);
        assert(r->file_offset == off);
    }

    /* imports: the undefined symbols a kept relocation names, once each, at the first reference */
    typedef struct { const char *name; uint64_t off; uint32_t type; } want_imp_t;
    const want_imp_t wi[4] = {
        { "printk",       L.sec_off[1] + 0x01, 4 },
        { "kmalloc",      L.sec_off[1] + 0x21, 4 },
        { "optional_api", L.sec_off[1] + 0x41, 4 },
        { "jiffies",      L.sec_off[1] + 0x49, 41 },                                          /* the first of its two references */
    };
    assert(img->import_count == 4);
    for (uint32_t i = 0; i < 4; i++) {
        const cbae_import_entry_t *m = &img->imports[i];
        assert(strcmp(m->name, wi[i].name) == 0 && strcmp(m->module, "kernel") == 0 && m->table_index == i);
        assert(m->rela_offset == wi[i].off && m->rela_type == wi[i].type && m->state == CBAE_IMPORT_UNRESOLVED);
        assert(cbae_import_has_rela(m) && !cbae_import_has_iat(m) && m->iat_va == CBAE_ADDR_INVALID);
        assert(cbae_image_import_by_name(img, wi[i].name) == m);
    }
    assert(cbae_image_import_by_name(img, "never_referenced") == NULL && cbae_image_import_by_name(img, "init_module") == NULL);
    assert(cbae_image_import_at_iat(img, CBAE_ADDR_INVALID) == NULL);

    /* .modinfo: the first of each key wins, as in the kernel's get_modinfo */
    assert(strcmp(img->meta.elf.module_license, "GPL") == 0 && strcmp(img->meta.elf.module_author, "A. Author") == 0);
    assert(strcmp(img->meta.elf.module_description, "A test module") == 0 && strcmp(img->meta.elf.kernel_version, "6.8.0 SMP mod_unload") == 0);
    assert(img->meta.elf.has_ksymtab);

    /* one thing was left out, and said so: a clean file has no notes */
    assert(img->note_count == 1 && has_note(img, "3 relocation entries apply to sections that are not loaded"));

    em_check(&sp, &L, img, 2);                                                                /* and the model agrees with every field */
    cbae_image_destroy(&img);
    assert(img == NULL);
    eb_free(&f);
    PASS("the default file: sections, addresses, symbols, relocations, imports, modinfo and notes, field by field");
}

/* ---- where sections go ---- */

static void test_layout_rel(void) {
    eb_spec_t sp = blank(EB_ET_REL);
    int k = 0;
    sp.sec[k++] = S(".text",    EB_SHT_PROGBITS, AX,                  0x2345, 16);
    sp.sec[k++] = S(".rodata",  EB_SHT_PROGBITS, EB_SHF_ALLOC,        0x10,   8);
    sp.sec[k++] = S(".data",    EB_SHT_PROGBITS, AW,                  0x20,   0x10000);
    sp.sec[k++] = S(".bss",     EB_SHT_NOBITS,   AW,                  0x5000, 0x1000);
    sp.sec[k++] = S(".note.x",  EB_SHT_NOTE,     EB_SHF_ALLOC,        0x24,   4);
    sp.sec[k++] = S(".comment", EB_SHT_PROGBITS, 0,                   8,      1);
    sp.nsec = k;
    eb_layout_t L; eb_file_t f;
    cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 0);

    const uint64_t va[5] = { 0x400000, 0x403000, 0x410000, 0x411000, 0x416000 };
    const uint64_t sz[5] = { 0x2345, 0x10, 0x20, 0x5000, 0x24 };
    for (int i = 0; i < 5; i++) assert(img->sections[i].virt_addr == va[i] && img->sections[i].virt_size == sz[i]);
    assert(img->sections[5].virt_addr == 0 && img->sections[5].virt_size == 0 && cbae_image_section_by_name(img, ".comment") != NULL);
    assert(img->note_count == 0);

    /* a section owns [va, va + size); the page gaps and the bytes before the first section are in none */
    const struct { uint64_t a; int sec; } at[] = {
        { 0x3FFFFF, -1 }, { 0x400000, 0 }, { 0x402344, 0 }, { 0x402345, -1 }, { 0x402FFF, -1 }, { 0x403000, 1 }, { 0x40300F, 1 }, { 0x403010, -1 },
        { 0x40FFFF, -1 }, { 0x410000, 2 }, { 0x41001F, 2 }, { 0x410020, -1 }, { 0x411000, 3 }, { 0x415FFF, 3 }, { 0x416000, 4 }, { 0x416023, 4 }, { 0x416024, -1 },
    };
    for (size_t i = 0; i < sizeof at / sizeof at[0]; i++)
        assert(cbae_image_section_at_va(img, at[i].a) == (at[i].sec < 0 ? NULL : &img->sections[at[i].sec]));
    assert(cbae_image_va_to_ptr(img, 0x402344) == img->file_data + L.sec_off[1] + 0x2344 && cbae_image_va_to_ptr(img, 0x402345) == NULL);
    assert(cbae_image_va_to_ptr(img, 0x411000) == NULL);                                      /* .bss */
    cbae_image_destroy(&img);
    eb_free(&f);

    /* odd alignments: not a power of two (page, however large the number is), above 1 MiB (cut to it), exactly 1 MiB (kept),
     * zero (page); a section over 1 TiB is cut to it. The cursor after .f is 0x502008 + 2^40. */
    sp = blank(EB_ET_REL);
    k = 0;
    sp.sec[k++] = S(".a", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, 1);
    sp.sec[k++] = S(".b", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, 3);
    sp.sec[k++] = S(".c", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, (uint64_t)1 << 22);
    sp.sec[k++] = S(".d", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, 0);
    sp.sec[k++] = S(".e", EB_SHT_NOBITS,   AW,           ((uint64_t)1 << 40) + 5, 0x1000);
    sp.sec[k++] = S(".f", EB_SHT_PROGBITS, EB_SHF_ALLOC, 8, 1);
    sp.sec[k++] = S(".g", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, 0x3000);                       /* 3 pages: not a power of two, so a page, not a multiple of 0x3000 */
    sp.sec[k++] = S(".h", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, 0x100001);                     /* just over 1 MiB and not a power of two: a page, and not "cut" */
    sp.sec[k++] = S(".i", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0x10, 0x100000);                     /* exactly 1 MiB: kept */
    sp.nsec = k;
    img = build_and_check(&sp, &L, &f, 0);
    const uint64_t T = (uint64_t)1 << 40;
    const uint64_t va2[9] = { 0x400000, 0x401000, 0x500000, 0x501000, 0x502000, 0x502000 + T, 0x503000 + T, 0x504000 + T, 0x600000 + T };
    for (int i = 0; i < 9; i++) assert(img->sections[i].virt_addr == va2[i]);
    assert(img->sections[4].virt_size == T && img->sections[6].virt_size == 0x10 && img->sections[8].virt_size == 0x10);
    assert(img->note_count == 3 && has_note(img, "3 sections have an alignment that is not a power of two") &&
           has_note(img, "1 sections have an alignment above 1 MiB") && has_note(img, "1 loaded sections are larger than 1 TiB"));
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("relocatable object layout: from 0x400000 in table order, pages or alignment, gaps in no section, odd alignments and sizes noted");
}

static eb_spec_t linked_spec(uint16_t etype) {
    eb_spec_t sp = blank(etype);
    int k = 0;
    sp.sec[k] = S(".text",    EB_SHT_PROGBITS, AX, 0x40,  16);  sp.sec[k++].addr = 0x401000;
    sp.sec[k] = S(".data",    EB_SHT_PROGBITS, AW, 0x20,  8);   sp.sec[k++].addr = 0x404000;
    sp.sec[k] = S(".bss",     EB_SHT_NOBITS,   AW, 0x100, 32);  sp.sec[k++].addr = 0x404020;
    sp.sec[k] = S(".comment", EB_SHT_PROGBITS, 0,  8,     1);   sp.sec[k++].addr = 0;
    sp.nsec = k;
    k = 0;
    sp.sym[k++] = Y("a.c",    EB_STB_LOCAL,  EB_STT_FILE,   EB_SHN_ABS, 0, 0);
    sp.sym[k++] = Y("main",   EB_STB_GLOBAL, EB_STT_FUNC,   1, 0x401020, 0x10);
    sp.sym[k++] = Y("counter", EB_STB_GLOBAL, EB_STT_OBJECT, 2, 0x404010, 8);
    sp.sym[k++] = Y("puts",   EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("inbss",  EB_STB_LOCAL,  EB_STT_OBJECT, 3, 0x404020, 4);
    sp.sym[k++] = Y("far",    EB_STB_GLOBAL, EB_STT_OBJECT, 1, 0x9000000, 4);                 /* outside its section: in a linked file the value is the address */
    sp.nsym = k;
    k = 0;
    sp.rel[k++] = RA(2, 0x404000, 4, EB_R_X86_64_64, 0);                                      /* .got-like slot for puts */
    sp.rel[k++] = RA(2, 0x404008, 3, 6, 0);                                                   /* GLOB_DAT */
    sp.rel[k++] = RA(1, 0x401005, 0, 8, 0x1234);                                              /* RELATIVE: no symbol */
    sp.rel[k++] = RA(4, 0x10, 4, EB_R_X86_64_PLT32, -4);                                      /* sh_info names a section that is not loaded: kept here */
    sp.nrel = k;
    sp.entry = 0x401020;
    return sp;
}

static void test_linked_files(void) {
    for (int variant = 0; variant < 3; variant++) {
        const uint16_t et = variant == 0 ? EB_ET_EXEC : variant == 1 ? EB_ET_DYN : EB_ET_CORE;
        eb_spec_t sp = linked_spec(et);
        eb_layout_t L; eb_file_t f;
        cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 0);

        /* sh_addr is the address, as it is; the entry point is e_entry */
        assert(img->sections[0].virt_addr == 0x401000 && img->sections[1].virt_addr == 0x404000 && img->sections[2].virt_addr == 0x404020);
        assert(img->sections[2].virt_size == 0x100 && img->sections[3].virt_addr == 0 && img->sections[3].virt_size == 0);
        assert(img->entry_point == 0x401020 && img->load_base == 0);
        assert(cbae_image_section_at_va(img, 0x401000) == &img->sections[0] && cbae_image_section_at_va(img, 0x401040) == NULL);
        assert(cbae_image_section_at_va(img, 0x404020) == &img->sections[2]);

        /* symbol values are addresses, wherever they point */
        assert(img->symbols[1].address == 0x401020 && img->symbols[2].address == 0x404010 && img->symbols[4].address == 0x404020);
        assert(img->symbols[5].address == 0x9000000 && img->symbols[3].address == CBAE_ADDR_INVALID && img->symbols[0].address == CBAE_ADDR_INVALID);
        assert(cbae_image_symbol_at_va(img, 0x401020) == &img->symbols[1] && cbae_image_symbol_at_va(img, 0x9000000) == &img->symbols[5]);

        /* r_offset is an address, no file position is claimed, every entry is kept */
        assert(img->reloc_count == 4 && img->import_count == 1);
        assert(img->relocations[0].target_va == 0x404000 && img->relocations[0].file_offset == (cbae_off_t)CBAE_ADDR_INVALID);
        assert(img->relocations[0].type == CBAE_RELOC_64 && img->relocations[0].references_import && img->relocations[0].sym_index == 3);
        assert(img->relocations[1].type == CBAE_RELOC_UNKNOWN && !img->relocations[1].references_import && img->relocations[1].sym_index == 2);
        assert(img->relocations[2].sym_index == NOSYM && img->relocations[2].addend == 0x1234 && !img->relocations[2].references_import);
        assert(img->relocations[3].target_va == 0x10 && img->relocations[3].references_import);
        assert(strcmp(img->imports[0].name, "puts") == 0 && img->imports[0].rela_offset == (cbae_off_t)CBAE_ADDR_INVALID && img->imports[0].rela_type == 1);
        assert(has_note(img, "e_type 4") == (et == EB_ET_CORE) && img->note_count == (et == EB_ET_CORE ? 1u : 0u));
        cbae_image_destroy(&img);
        eb_free(&f);

        sp.entry = 0;                                                                         /* no entry point is none, not address 0 */
        img = build_and_check(&sp, &L, &f, 0);
        assert(img->entry_point == CBAE_ADDR_INVALID);
        cbae_image_destroy(&img);
        eb_free(&f);
    }
    /* a relocatable object's e_entry means nothing */
    eb_spec_t sp = eb_spec_default();
    sp.entry = 0x1000;
    eb_layout_t L; eb_file_t f;
    cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 2);
    assert(img->entry_point == CBAE_ADDR_INVALID);
    cbae_image_destroy(&img);
    eb_free(&f);

    /* a section at the top of the address space: its range is cut so that it does not wrap */
    sp = linked_spec(EB_ET_EXEC);
    sp.sec[1].addr = UINT64_MAX - 0x0F;
    img = build_and_check(&sp, &L, &f, 0);
    assert(img->sections[1].virt_addr == UINT64_MAX - 0x0F && img->sections[1].virt_size == 0x0F);
    assert(has_note(img, "run past the top of the address space"));
    cbae_image_destroy(&img);
    eb_free(&f);

    /* the exact edge: a range that ends at UINT64_MAX does not wrap and is kept whole, one byte more is cut, and a section at
     * UINT64_MAX itself has no addresses and so no bytes either (it is loaded, and what it holds is not in the address space) */
    for (int v = 0; v < 3; v++) {
        sp = linked_spec(EB_ET_EXEC);
        sp.sec[1].addr = v == 0 ? UINT64_MAX - 0x20 : v == 1 ? UINT64_MAX - 0x1F : UINT64_MAX;       /* .data is 0x20 bytes */
        img = build_and_check(&sp, &L, &f, 0);
        assert(img->sections[1].virt_addr == sp.sec[1].addr);
        assert(img->sections[1].virt_size == (v == 0 ? 0x20u : v == 1 ? 0x1Fu : 0u) && img->sections[1].file_size == img->sections[1].virt_size);
        assert((img->sections[1].data == NULL) == (v == 2) && has_note(img, "run past the top of the address space") == (v != 0));
        assert(img->note_count == (v == 0 ? 0u : 1u));
        cbae_image_destroy(&img);
        eb_free(&f);
    }
    PASS("linked files (executable, shared object, other): sh_addr and st_value are addresses, r_offset is an address, entry point, top of memory");
}

static void test_section_quirks(void) {
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);

    /* e_shstrndx outside the table: no section has a name, and that is said */
    eb_file_t g = clone(&f);
    eb_w16(g.b, EB_E_SHSTRNDX, 200);
    cbae_binary_image_t *img = load_ok(&g);
    assert(img->section_count == 14 && cbae_image_section_by_name(img, ".text") == NULL);
    for (uint32_t i = 0; i < 14; i++) assert(img->sections[i].name[0] == '\0');
    assert(has_note(img, "e_shstrndx 200 is outside") && img->sections[0].virt_addr == 0x400000);
    cbae_image_destroy(&img);
    eb_free(&g);

    /* e_shstrndx 0 is legal: there is no name table */
    g = clone(&f);
    eb_w16(g.b, EB_E_SHSTRNDX, 0);
    img = load_ok(&g);
    assert(img->section_count == 14 && img->sections[0].name[0] == '\0' && has_note(img, "not in the section name table"));
    cbae_image_destroy(&img);
    eb_free(&g);

    /* the name table is not of type SHT_STRTAB, and does not end with a NUL: both said, nothing read out of bounds */
    g = clone(&f);
    eb_w16(g.b, EB_E_SHSTRNDX, 1);
    img = load_ok(&g);
    assert(has_note(img, "is not of type SHT_STRTAB") && has_note(img, "does not end with a NUL"));
    cbae_image_destroy(&img);
    eb_free(&g);

    /* a name that is not in the table (sh_name past its end) */
    g = clone(&f);
    eb_w32(g.b, eb_sh(&L, 2) + EB_SH_NAME, 0x10000);
    img = load_ok(&g);
    assert(img->sections[1].name[0] == '\0' && strcmp(img->sections[0].name, ".text") == 0 && has_note(img, "1 section names are not in the section name table"));
    cbae_image_destroy(&img);
    eb_free(&g);

    /* sh_name on the last byte of the name table (its NUL: the empty name, which is legal) and one past it (outside the table) */
    g = clone(&f);
    eb_w32(g.b, eb_sh(&L, 2) + EB_SH_NAME, L.shstrtab_size - 1);
    img = load_ok(&g);
    assert(img->sections[1].name[0] == '\0' && !has_note(img, "not in the section name table") && img->note_count == 1);   /* the one note every default file has */
    cbae_image_destroy(&img);
    eb_free(&g);
    g = clone(&f);
    eb_w32(g.b, eb_sh(&L, 2) + EB_SH_NAME, L.shstrtab_size);
    img = load_ok(&g);
    assert(img->sections[1].name[0] == '\0' && has_note(img, "1 section names are not in the section name table"));
    cbae_image_destroy(&img);
    eb_free(&g);

    /* a section that claims more than the file holds: what is there is used, and it is said */
    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, 2) + EB_SH_SIZE, 0x100000);                                          /* .rodata */
    img = load_ok(&g);
    assert(img->sections[1].virt_size == 0x100000 && img->sections[1].file_size == g.n - L.sec_off[2]);
    assert(img->sections[1].data == img->file_data + L.sec_off[2] && has_note(img, "bytes beyond the end of the file"));
    assert(img->sections[2].virt_addr == 0x501000);                                           /* the next one goes after the larger range */
    cbae_image_destroy(&img);
    eb_free(&g);

    /* a section whose contents start beyond the end of the file has none */
    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, 3) + EB_SH_OFFSET, g.n + 10);                                       /* .data */
    img = load_ok(&g);
    assert(img->sections[2].file_size == 0 && img->sections[2].data == NULL && img->sections[2].virt_size == 0x20 && has_note(img, "bytes beyond the end of the file"));
    assert(cbae_image_va_to_ptr(img, 0x402000) == NULL);
    cbae_image_destroy(&img);
    eb_free(&g);

    /* an offset that would wrap if added to a size */
    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, 3) + EB_SH_OFFSET, UINT64_MAX - 5);
    img = load_ok(&g);
    assert(img->sections[2].file_size == 0 && img->sections[2].data == NULL);
    cbae_image_destroy(&img);
    eb_free(&g);

    /* names of 40 characters are cut to 31, and noted */
    sp = blank(EB_ET_REL);
    sp.sec[0] = S("0123456789012345678901234567890123456789", EB_SHT_PROGBITS, EB_SHF_ALLOC, 8, 1);
    sp.nsec = 1;
    eb_layout_t L2; eb_file_t f2;
    img = build_and_check(&sp, &L2, &f2, 0);
    assert(strcmp(img->sections[0].name, "0123456789012345678901234567890") == 0 && has_note(img, "1 section names are longer than 31 bytes"));
    assert(cbae_image_section_by_name(img, "0123456789012345678901234567890") == &img->sections[0]);
    cbae_image_destroy(&img);
    eb_free(&f2);
    eb_free(&f);
    PASS("section quirks: no or damaged name table, names out of the table or too long, contents past the end of the file");
}

/* ---- symbols, relocations, imports ---- */

static void test_symbol_rules(void) {
    eb_spec_t sp = blank(EB_ET_REL);
    int k = 0;
    sp.sec[k++] = S(".text",    EB_SHT_PROGBITS, AX,           0x80, 16);
    sp.sec[k++] = S(".comment", EB_SHT_PROGBITS, 0,            0x10, 1);
    sp.nsec = k;
    char longname[200];
    memset(longname, 'n', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    k = 0;
    sp.sym[k++] = Y("at_end",     EB_STB_GLOBAL, EB_STT_NOTYPE, 1, 0x80, 0);                  /* one past the end: allowed (a label after the last instruction) */
    sp.sym[k++] = Y("beyond",     EB_STB_GLOBAL, EB_STT_NOTYPE, 1, 0x81, 0);                  /* beyond: no address */
    sp.sym[k++] = Y("in_comment", EB_STB_GLOBAL, EB_STT_OBJECT, 2, 4, 4);                     /* a section that is not loaded */
    sp.sym[k++] = Y("gone",       EB_STB_GLOBAL, EB_STT_FUNC,   500, 4, 4);                   /* a section that does not exist */
    sp.sym[k++] = Y("reserved",   EB_STB_GLOBAL, EB_STT_FUNC,   0xFF05, 4, 4);
    sp.sym[k++] = Y("absolute",   EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_ABS, 0xDEAD, 0);
    sp.sym[k++] = Y("common",     EB_STB_GLOBAL, EB_STT_COMMON, EB_SHN_COMMON, 8, 16);
    sp.sym[k++] = Y("tls",        EB_STB_GLOBAL, EB_STT_TLS,    1, 0, 8);
    sp.sym[k++] = Y(longname,     EB_STB_GLOBAL, EB_STT_FUNC,   1, 8, 4);                     /* longer than a symbol name may be */
    sp.sym[k++] = Y("via_table",  EB_STB_GLOBAL, EB_STT_FUNC,   1, 0x10, 4);                  /* section index from SHT_SYMTAB_SHNDX */
    sp.sym[k - 1].xindex = true;
    sp.nsym = k;
    eb_layout_t L; eb_file_t f;
    cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 0);
    const uint64_t T = 0x400000;
    assert(sym_named(img, "at_end")->address == T + 0x80 && sym_named(img, "beyond")->address == CBAE_ADDR_INVALID);
    assert(sym_named(img, "in_comment")->address == CBAE_ADDR_INVALID && sym_named(img, "gone")->address == CBAE_ADDR_INVALID);
    assert(sym_named(img, "reserved")->address == CBAE_ADDR_INVALID && sym_named(img, "absolute")->address == 0xDEAD);
    assert(sym_named(img, "common")->address == CBAE_ADDR_INVALID && sym_named(img, "tls")->address == CBAE_ADDR_INVALID);
    assert(sym_named(img, "via_table")->address == T + 0x10 && sym_named(img, "via_table")->section_idx == 1);
    assert(sym_named(img, "gone")->section_idx == 500 && sym_named(img, "reserved")->section_idx == 0xFF05);
    char cut[CBAE_SYM_NAME_MAX];
    memset(cut, 'n', sizeof cut - 1);
    cut[sizeof cut - 1] = '\0';
    assert(sym_named(img, cut) != NULL && strlen(cut) == 127);
    assert(has_note(img, "1 symbols lie beyond the end of their section") && has_note(img, "1 symbols are in sections that are not loaded"));
    assert(has_note(img, "1 symbols are in a section that does not exist") && has_note(img, "1 symbols have a reserved section index"));
    assert(has_note(img, "1 symbol names are longer than 127 bytes"));
    assert(img->note_count == 5);
    cbae_image_destroy(&img);

    /* st_name outside the string table: no name, said; a table that does not end with a NUL: said, and the last name is cut at its end */
    eb_file_t g = clone(&f);
    eb_w32(g.b, eb_sym(&L, 3) + EB_ST_NAME, 0x7FFFFFF);                                       /* ELF symbol 3 = in_comment */
    img = load_ok(&g);
    assert(sym_named(img, "in_comment") == NULL && img->symbols[2].name[0] == '\0' && has_note(img, "1 symbol names are not in the string table"));
    cbae_image_destroy(&img);
    eb_free(&g);

    g = clone(&f);
    g.b[L.strtab_off + L.strtab_size - 1] = 'Z';                                               /* the last byte of .strtab was the NUL ending "via_table" */
    img = load_ok(&g);
    assert(has_note(img, "symbol string table does not end with a NUL"));
    assert(sym_named(img, "via_tableZ") != NULL && sym_named(img, "via_table") == NULL);       /* the name ends where the table does */
    assert(img->symbol_count == 10);
    cbae_image_destroy(&img);
    eb_free(&g);
    eb_free(&f);

    /* 0xFFFF in st_shndx and no SHT_SYMTAB_SHNDX at all: nothing says which section, so nothing is placed, and it is said */
    eb_spec_t nt = blank(EB_ET_REL);
    nt.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x20, 16);
    nt.nsec = 1;
    nt.sym[0] = Y("no_table", EB_STB_GLOBAL, EB_STT_FUNC, 0xFFFF, 0x10, 4);
    nt.nsym = 1;
    eb_layout_t Ln; eb_file_t fn;
    img = build_and_check(&nt, &Ln, &fn, 0);
    assert(L.shndx_tab != 0 && Ln.shndx_tab == 0);
    assert(img->symbols[0].address == CBAE_ADDR_INVALID && img->symbols[0].section_idx == 0xFFFF && img->symbols[0].type == CBAE_SYM_EXPORT);
    assert(has_note(img, "1 symbols need the extended section index table, which is missing or too short") && img->note_count == 1);
    cbae_image_destroy(&img);
    eb_free(&fn);

    /* the symbol table: another entry size reads nothing; a count the file cannot back reads what is there; an odd size drops the tail */
    sp = eb_spec_default();
    f = eb_build(&sp, &L);
    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, L.symtab) + EB_SH_ENTSIZE, 16);
    img = load_ok(&g);
    assert(img->symbol_count == 3 && img->reloc_count == 14 && img->import_count == 0);        /* no symbol table was read: only the ksymtab names are symbols */
    assert(has_note(img, "has entry size 16, not 24: no symbols are read"));
    assert(has_note(img, "14 relocations name a symbol that is not in the symbol table that was read"));
    assert(strcmp(img->symbols[0].name, "my_export") == 0 && strcmp(img->symbols[1].name, "init_module") == 0 && strcmp(img->symbols[2].name, "other_export") == 0);
    for (uint32_t i = 0; i < 14; i++) assert(img->relocations[i].sym_index == NOSYM && !img->relocations[i].references_import);
    cbae_image_destroy(&img);
    eb_free(&g);

    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, L.symtab) + EB_SH_SIZE, 21 * 24 + 10);                              /* ten bytes more than whole entries */
    img = load_ok(&g);
    assert(img->symbol_count == 22 && has_note(img, "size is not a multiple of 24: the last 10 bytes are ignored"));
    cbae_image_destroy(&img);
    eb_free(&g);

    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, L.symtab) + EB_SH_SIZE, 0x100000);                                  /* more entries than the file has bytes for: those that are there are read */
    img = load_ok(&g);
    assert(has_note(img, "the symbol table has 43690 entries but only"));
    assert(img->symbol_count > 22 && img->symbol_count < g.n / 24 + 3);
    cbae_image_destroy(&img);
    eb_free(&g);

    g = clone(&f);
    eb_w64(g.b, eb_sh(&L, L.symtab) + EB_SH_ENTSIZE, 0);                                      /* entsize 0 means the fixed size */
    img = load_ok(&g);
    assert(img->symbol_count == 22);
    cbae_image_destroy(&img);
    eb_free(&g);
    eb_free(&f);
    PASS("symbols: addresses (end of section, beyond, not loaded, missing, reserved, absolute, common, TLS), extended indices, names too long or outside the table, table damage");
}

static void test_symbol_index_choices(void) {
    /* two symbols with one address, or one name: the resolved one, then the exported one, then the first */
    eb_spec_t sp = blank(EB_ET_REL);
    sp.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x40, 16);
    sp.nsec = 1;
    int k = 0;
    sp.sym[k++] = Y("alias_local",  EB_STB_LOCAL,  EB_STT_FUNC,   1, 0, 4);
    sp.sym[k++] = Y("real_global",  EB_STB_GLOBAL, EB_STT_FUNC,   1, 0, 4);
    sp.sym[k++] = Y("dup",          EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("dup",          EB_STB_LOCAL,  EB_STT_FUNC,   1, 8, 4);
    sp.sym[k++] = Y("twin",         EB_STB_GLOBAL, EB_STT_FUNC,   1, 0x10, 4);
    sp.sym[k++] = Y("twin",         EB_STB_GLOBAL, EB_STT_FUNC,   1, 0x20, 4);
    sp.nsym = k;
    eb_layout_t L; eb_file_t f;
    cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 0);
    assert(cbae_image_symbol_at_va(img, 0x400000) == &img->symbols[1]);                       /* the global, though the local comes first */
    assert(cbae_image_symbol_by_name(img, "dup") == &img->symbols[3]);                        /* the one with an address, though the import comes first */
    assert(cbae_image_symbol_by_name(img, "twin") == &img->symbols[4]);                       /* otherwise the first */
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("two symbols with one address or name: the resolved one, then the exported one, then the first");
}

static void test_relocation_rules(void) {
    eb_spec_t sp = blank(EB_ET_REL);
    int k = 0;
    sp.sec[k++] = S(".text",   EB_SHT_PROGBITS, AX,           0x40, 16);
    sp.sec[k++] = S(".bss",    EB_SHT_NOBITS,   AW,           0x20, 16);
    sp.sec[k++] = S(".debug",  EB_SHT_PROGBITS, 0,            0x40, 1);
    sp.nsec = k;
    k = 0;
    sp.sym[k++] = Y("ext", EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("fn",  EB_STB_GLOBAL, EB_STT_FUNC,   1, 0, 4);
    sp.nsym = k;
    k = 0;
    sp.rel[k++] = RA(1, 0x3F, 1, EB_R_X86_64_PLT32, -4);                                      /* the last byte of .text: kept */
    sp.rel[k++] = RA(1, 0x40, 1, EB_R_X86_64_PLT32, -4);                                      /* one past it: not */
    sp.rel[k++] = RA(1, UINT64_MAX - 2, 1, EB_R_X86_64_PLT32, -4);                            /* an offset that would wrap */
    sp.rel[k++] = RA(1, 0x10, 0, EB_R_X86_64_64, 0x77);                                       /* no symbol */
    sp.rel[k++] = RA(1, 0x18, 9, EB_R_X86_64_64, 0);                                          /* a symbol that is not in the table */
    sp.rel[k++] = RA(1, 0x20, 2, EB_R_X86_64_PC32, 5);
    sp.rel[k++] = RA(2, 0x08, 2, EB_R_X86_64_64, 0);                                          /* in .bss: an address but no bytes in the file */
    sp.rel[k++] = RA(3, 0x08, 1, EB_R_X86_64_64, 0);                                          /* .debug is not loaded: ignored */
    sp.rel[k++] = RA(77, 0x08, 1, EB_R_X86_64_64, 0);                                         /* applies to a section that does not exist */
    sp.nrel = k;
    eb_layout_t L; eb_file_t f;
    cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 0);
    assert(img->reloc_count == 5 && img->import_count == 1);
    assert(img->relocations[0].target_va == 0x40003F && img->relocations[0].file_offset == L.sec_off[1] + 0x3F && img->relocations[0].references_import);
    assert(img->relocations[1].target_va == 0x400010 && img->relocations[1].sym_index == NOSYM && img->relocations[1].addend == 0x77);
    assert(img->relocations[2].sym_index == NOSYM && !img->relocations[2].references_import);
    assert(img->relocations[3].sym_index == 1 && !img->relocations[3].references_import && img->relocations[3].addend == 5);
    assert(img->relocations[4].target_va == 0x401008 && img->relocations[4].file_offset == (cbae_off_t)CBAE_ADDR_INVALID);   /* .bss at the next page */
    assert(has_note(img, "1 relocations lie beyond the end of the section they patch") == false);
    assert(has_note(img, "2 relocations lie beyond the end of the section they patch"));
    assert(has_note(img, "1 relocations name a symbol that is not in the symbol table that was read"));
    assert(has_note(img, "1 relocation entries apply to sections that are not loaded") && has_note(img, "1 relocation entries apply to a section that does not exist"));
    assert(img->note_count == 4);
    assert(img->imports[0].rela_offset == L.sec_off[1] + 0x3F && img->imports[0].rela_type == 4);
    cbae_image_destroy(&img);
    eb_free(&f);

    /* SHT_REL has implicit addends this loader does not read; a RELA section with an entry size other than 24 is ignored;
     * one linked to a symbol table other than the one that was read names no symbols */
    sp.nrel = 0;
    static uint8_t ents[3 * 24];
    memset(ents, 0, sizeof ents);
    for (int i = 0; i < 3; i++) {
        eb_w64(ents, i * 24 + EB_R_OFFSET, 0x10 + 8u * (unsigned)i);
        eb_w64(ents, i * 24 + EB_R_INFO, EB_R_INFO_OF(1, EB_R_X86_64_PLT32));              /* symbol 1: ext, an import */
        eb_w64(ents, i * 24 + EB_R_ADDEND, (uint64_t)-4);
    }
    sp.sec[3] = S(".rel.text",       EB_SHT_REL,  0, sizeof ents, 8); sp.sec[3].info = 1; sp.sec[3].link = 0; sp.sec[3].data = ents;
    sp.sec[4] = S(".rela.shortent",  EB_SHT_RELA, 0, sizeof ents, 8); sp.sec[4].info = 1; sp.sec[4].link = 0; sp.sec[4].entsize = 16; sp.sec[4].data = ents;
    sp.sec[5] = S(".rela.otherlink", EB_SHT_RELA, 0, sizeof ents, 8); sp.sec[5].info = 1; sp.sec[5].link = 3; sp.sec[5].entsize = 24; sp.sec[5].data = ents;
    sp.nsec = 6;
    f = eb_build(&sp, &L);                                                                     /* (relocation sections the test made by hand are not in the model) */
    img = load_ok(&f);
    assert(img->reloc_count == 3 && img->import_count == 0);                                  /* only the third section's entries, naming no symbol */
    for (int i = 0; i < 3; i++) assert(img->relocations[i].sym_index == NOSYM && !img->relocations[i].references_import && img->relocations[i].target_va == 0x400010 + 8u * (unsigned)i);
    assert(has_note(img, "1 SHT_REL sections") && has_note(img, "1 relocation sections have an entry size other than 24") && has_note(img, "3 relocations name a symbol"));
    assert(img->sections[3].flags == RL_ && img->sections[4].flags == RL_ && img->sections[5].flags == RL_);
    cbae_image_destroy(&img);
    eb_free(&f);

    /* another machine: the type numbers mean nothing to this loader, except that 0 is "none" everywhere */
    sp = eb_spec_default();
    sp.machine = EB_EM_AARCH64;
    img = build_and_check(&sp, &L, &f, 2);
    assert(img->arch == CBAE_ARCH_ARM64 && img->relocations[0].type == CBAE_RELOC_UNKNOWN && img->relocations[10].type == CBAE_RELOC_NOP);
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("relocations: bounds, symbols (none, missing, other table), targets (not loaded, missing, .bss), SHT_REL, entry sizes, other machines");
}

static void test_import_rules(void) {
    eb_spec_t sp = blank(EB_ET_REL);
    sp.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x40, 16);
    sp.nsec = 1;
    char longname[160];
    memset(longname, 'q', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    int k = 0;
    sp.sym[k++] = Y("f1",        EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("w1",        EB_STB_WEAK,   EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("unused",    EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("secundef",  EB_STB_LOCAL,  EB_STT_SECTION, EB_SHN_UNDEF, 0, 0);       /* a section symbol with no section: names nothing */
    sp.sym[k++] = Y("fileundef", EB_STB_LOCAL,  EB_STT_FILE,   EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y(longname,    EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);
    sp.sym[k++] = Y("defined",   EB_STB_GLOBAL, EB_STT_FUNC,   1, 0, 4);
    sp.nsym = k;
    k = 0;
    sp.rel[k++] = RA(1, 0x08, 2, EB_R_X86_64_PLT32, -4);                                      /* w1 first */
    sp.rel[k++] = RA(1, 0x10, 1, EB_R_X86_64_PC32, -4);                                       /* then f1 */
    sp.rel[k++] = RA(1, 0x18, 2, EB_R_X86_64_PLT32, -4);                                      /* w1 again: still one import */
    sp.rel[k++] = RA(1, 0x20, 4, EB_R_X86_64_PC32, 0);                                        /* undefined section symbol: not an import */
    sp.rel[k++] = RA(1, 0x28, 5, EB_R_X86_64_PC32, 0);                                        /* undefined file symbol: not an import */
    sp.rel[k++] = RA(1, 0x30, 6, EB_R_X86_64_PLT32, -4);                                      /* the long name */
    sp.rel[k++] = RA(1, 0x38, 7, EB_R_X86_64_PLT32, -4);                                      /* a definition: not an import */
    sp.nrel = k;
    eb_layout_t L; eb_file_t f;
    cbae_binary_image_t *img = build_and_check(&sp, &L, &f, 0);
    assert(img->import_count == 3 && img->reloc_count == 7);
    assert(strcmp(img->imports[0].name, "w1") == 0 && img->imports[0].rela_offset == L.sec_off[1] + 0x08);   /* in order of first reference */
    assert(strcmp(img->imports[1].name, "f1") == 0 && img->imports[1].rela_offset == L.sec_off[1] + 0x10 && img->imports[1].rela_type == 2);
    assert(strlen(img->imports[2].name) == CBAE_IMPORT_NAME_MAX - 1 && strncmp(img->imports[2].name, longname, CBAE_IMPORT_NAME_MAX - 1) == 0);
    assert(!img->relocations[3].references_import && !img->relocations[4].references_import && !img->relocations[6].references_import);
    assert(img->symbols[2].type == CBAE_SYM_IMPORT && cbae_image_import_by_name(img, "unused") == NULL);   /* an import symbol nothing refers to makes no import */
    assert(img->symbols[3].type == CBAE_SYM_SECTION && img->symbols[4].type == CBAE_SYM_FILE);
    assert(img->symbols[0].binding == CBAE_BIND_GLOBAL && img->symbols[1].binding == CBAE_BIND_WEAK);
    assert(has_note(img, "1 symbol names are longer than 127 bytes"));
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("imports: once per undefined symbol at its first reference, weak ones too, none for section/file/defined symbols or unreferenced ones, long names cut");
}

static void test_no_symbol_table(void) {
    eb_spec_t sp = eb_spec_default();
    sp.no_symtab = true;                                                                      /* no .symtab, .strtab or relocation sections either */
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(&f);
    assert(img->section_count == 9 && img->symbol_count == 3 && img->reloc_count == 0 && img->import_count == 0);
    const char *const ks[3] = { "my_export", "init_module", "other_export" };                /* with no symbol table nothing says they are defined: all three are names only */
    for (int i = 0; i < 3; i++) assert(strcmp(img->symbols[i].name, ks[i]) == 0 && img->symbols[i].type == CBAE_SYM_EXPORT && img->symbols[i].address == CBAE_ADDR_INVALID);
    assert(img->meta.elf.has_ksymtab && img->note_count == 0 && strcmp(img->meta.elf.module_license, "GPL") == 0);
    cbae_image_destroy(&img);
    eb_free(&f);

    sp.nsec = 0;                                                                              /* no sections at all but the name table */
    f = eb_build(&sp, &L);
    img = load_ok(&f);
    assert(img->section_count == 1 && strcmp(img->sections[0].name, ".shstrtab") == 0 && img->symbol_count == 0 && img->reloc_count == 0);
    assert(cbae_image_symbol_at_va(img, 0x400000) == NULL && cbae_image_symbol_by_name(img, "x") == NULL);
    assert(cbae_image_section_at_va(img, 0x400000) == NULL && cbae_image_import_by_name(img, "x") == NULL && cbae_image_import_at_iat(img, 0x1000) == NULL);
    assert(cbae_image_va_to_ptr(img, 0) == NULL && cbae_image_offset_to_va(img, 0) == CBAE_ADDR_INVALID);
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("no symbol table (and none at all): the file still loads, and every lookup on the empty tables answers");
}

/* ---- extended numbering ---- */

static void test_extended_numbering(void) {
    /* forced: the extended form with the real values in section 0 */
    eb_spec_t sp = eb_spec_default();
    sp.ext_numbering = true;
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    assert(eb_r16(f.b, EB_E_SHNUM) == 0 && eb_r16(f.b, EB_E_SHSTRNDX) == 0xFFFF);              /* the builder wrote what it was asked to */
    assert(eb_r64(f.b, eb_sh(&L, 0) + EB_SH_SIZE) == 15 && eb_r32(f.b, eb_sh(&L, 0) + EB_SH_LINK) == L.shstrtab);
    cbae_binary_image_t *img = load_ok(&f);
    em_check(&sp, &L, img, 2);
    assert(img->section_count == 14 && strcmp(img->sections[13].name, ".shstrtab") == 0 && strcmp(img->sections[0].name, ".text") == 0);
    cbae_image_destroy(&img);

    /* shnum 0 with a section 0 that says nothing: there are no sections, and the file is refused */
    eb_w64(f.b, eb_sh(&L, 0) + EB_SH_SIZE, 0);
    assert(load_err(&f) == CBAE_ERR_PARSE);
    eb_free(&f);

    /* 70000 sections: e_shnum 0, e_shstrndx 0xFFFF, symbols in sections above 65535 through SHT_SYMTAB_SHNDX */
    sp = eb_spec_default();
    sp.pad_sections = 70000;
    sp.pad_flags = EB_SHF_ALLOC;
    int k = sp.nsym;
    sp.sym[k++] = Y("in_pad_low",  EB_STB_GLOBAL, EB_STT_OBJECT, 60000, 0, 0);                  /* stored in the table although it would fit st_shndx */
    sp.sym[k - 1].xindex = true;
    sp.sym[k++] = Y("in_pad_high", EB_STB_GLOBAL, EB_STT_OBJECT, 66000, 0, 0);
    sp.sym[k - 1].xindex = true;
    const uint32_t total = 1 + 8 + 70000 + 3 + 4;                                              /* null, user, pads, three .rela, .symtab, .strtab, .symtab_shndx, .shstrtab */
    sp.sym[k++] = Y("in_shstr",    EB_STB_GLOBAL, EB_STT_OBJECT, total - 1, 0, 0);             /* the last section: .shstrtab (not loaded) */
    sp.sym[k - 1].xindex = true;
    sp.nsym = k;
    f = eb_build(&sp, &L);
    assert(L.shnum == total && eb_r16(f.b, EB_E_SHNUM) == 0 && eb_r16(f.b, EB_E_SHSTRNDX) == 0xFFFF && L.shndx_tab != 0);
    assert(eb_r64(f.b, eb_sh(&L, 0) + EB_SH_SIZE) == total && eb_r32(f.b, eb_sh(&L, 0) + EB_SH_LINK) == L.shstrtab);
    img = load_ok(&f);
    assert(img->section_count == total - 1);
    assert(strcmp(img->sections[total - 2].name, ".shstrtab") == 0 && strcmp(img->sections[8].name, ".pad") == 0 && strcmp(img->sections[70007].name, ".pad") == 0);
    assert(strcmp(img->sections[70008].name, ".rela.text") == 0);
    em_sec_t *m = em_layout(&sp);
    const cbae_symbol_t *lo = sym_named(img, "in_pad_low"), *hi = sym_named(img, "in_pad_high"), *ss = sym_named(img, "in_shstr");
    assert(lo && hi && ss);
    assert(lo->section_idx == 60000 && hi->section_idx == 0xFFFF && ss->section_idx == 0xFFFF);   /* an index above 65535 does not fit the field */
    assert(lo->address == m[60000].va && hi->address == m[66000].va && lo->address == 0x406000);  /* every empty pad is at the page after __ksymtab_strings */
    assert(ss->address == CBAE_ADDR_INVALID);
    assert(img->sections[8 + 59999].virt_addr == 0x406000 && img->sections[8 + 59999].virt_size == 0);
    free(m);
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("extended numbering: e_shnum 0 and e_shstrndx 0xFFFF with the values in section 0, 70000 sections, extended symbol section indices");
}

/* ---- .modinfo and __ksymtab_strings ---- */

static eb_file_t modinfo_file(const uint8_t *data, size_t n, uint64_t flags, eb_spec_t *spp) {
    eb_spec_t sp = blank(EB_ET_REL);
    sp.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x10, 16);
    sp.sec[1] = S(".modinfo", EB_SHT_PROGBITS, flags, 0, 1);
    sp.sec[1].data = data;
    sp.sec[1].size = n;
    sp.nsec = 2;
    *spp = sp;
    eb_layout_t L;
    return eb_build(&sp, &L);
}

static void test_modinfo(void) {
    static const uint8_t a[] = "license=GPL\0license=MIT\0\0\0author=Me\0licensex=bad\0vermagic=6.8 SMP\0description\0depends=x\0description=late\0";
    eb_spec_t sp;
    eb_file_t f = modinfo_file(a, sizeof a - 1, EB_SHF_ALLOC, &sp);
    cbae_binary_image_t *img = load_ok(&f);
    assert(strcmp(img->meta.elf.module_license, "GPL") == 0 && strcmp(img->meta.elf.module_author, "Me") == 0);
    assert(strcmp(img->meta.elf.kernel_version, "6.8 SMP") == 0);
    assert(strcmp(img->meta.elf.module_description, "late") == 0);                            /* the one without '=' is not a field; the next one is */
    assert(!img->meta.elf.has_ksymtab && img->note_count == 0);
    cbae_image_destroy(&img);
    eb_free(&f);

    /* a key is the whole text before the first '=': longer keys that start like a real one are other keys, even when they come first */
    static const uint8_t ext[] = "vermagic2=bad\0licensed=bad\0authors=bad\0description2=bad\0vermagi=bad\0vermagic=1\0license=2\0author=3\0description=4\0";
    f = modinfo_file(ext, sizeof ext - 1, EB_SHF_ALLOC, &sp);
    img = load_ok(&f);
    assert(strcmp(img->meta.elf.kernel_version, "1") == 0 && strcmp(img->meta.elf.module_license, "2") == 0);
    assert(strcmp(img->meta.elf.module_author, "3") == 0 && strcmp(img->meta.elf.module_description, "4") == 0 && img->note_count == 0);
    cbae_image_destroy(&img);
    eb_free(&f);

    static uint8_t big[1200];                                                                  /* every value longer than its field */
    size_t n = 0;
    const struct { const char *key; size_t len; } fields[4] = { { "vermagic=", 100 }, { "license=", 40 }, { "author=", 200 }, { "description=", 300 } };
    for (int i = 0; i < 4; i++) {
        memcpy(big + n, fields[i].key, strlen(fields[i].key)); n += strlen(fields[i].key);
        memset(big + n, 'a' + i, fields[i].len); n += fields[i].len;
        big[n++] = 0;
    }
    f = modinfo_file(big, n, EB_SHF_ALLOC, &sp);
    img = load_ok(&f);
    assert(strlen(img->meta.elf.kernel_version) == sizeof img->meta.elf.kernel_version - 1 && img->meta.elf.kernel_version[0] == 'a');
    assert(strlen(img->meta.elf.module_license) == sizeof img->meta.elf.module_license - 1 && img->meta.elf.module_license[0] == 'b');
    assert(strlen(img->meta.elf.module_author) == sizeof img->meta.elf.module_author - 1 && img->meta.elf.module_author[0] == 'c');
    assert(strlen(img->meta.elf.module_description) == sizeof img->meta.elf.module_description - 1 && img->meta.elf.module_description[0] == 'd');
    assert(has_note(img, "4 .modinfo values are longer than their fields and were cut") && img->note_count == 1);
    cbae_image_destroy(&img);
    eb_free(&f);

    static const uint8_t unterminated[] = "author=X\0license=GPL";                              /* the last string has no NUL: it ends where the section does */
    f = modinfo_file(unterminated, sizeof unterminated - 1, EB_SHF_ALLOC, &sp);
    img = load_ok(&f);
    assert(strcmp(img->meta.elf.module_license, "GPL") == 0 && strcmp(img->meta.elf.module_author, "X") == 0);
    cbae_image_destroy(&img);
    eb_free(&f);

    static const uint8_t onlyseparators[] = "\0\0\0\0=\0=x\0";
    f = modinfo_file(onlyseparators, sizeof onlyseparators - 1, EB_SHF_ALLOC, &sp);
    img = load_ok(&f);
    assert(img->meta.elf.module_license[0] == '\0' && img->meta.elf.module_author[0] == '\0' && img->meta.elf.kernel_version[0] == '\0');
    cbae_image_destroy(&img);
    eb_free(&f);

    static const uint8_t notloaded[] = "license=Dual MIT/GPL\0";                               /* a .modinfo without SHF_ALLOC is read as well */
    f = modinfo_file(notloaded, sizeof notloaded - 1, 0, &sp);
    img = load_ok(&f);
    assert(strcmp(img->meta.elf.module_license, "Dual MIT/GPL") == 0 && img->sections[1].virt_size == 0);
    cbae_image_destroy(&img);
    eb_free(&f);

    f = modinfo_file(NULL, 0, EB_SHF_ALLOC, &sp);                                              /* empty */
    img = load_ok(&f);
    assert(img->meta.elf.module_license[0] == '\0' && img->note_count == 0);
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS(".modinfo: first value wins, exact keys, padding, values cut to their fields, unterminated last string, not loaded, empty");
}

static eb_file_t ksym_file(const uint8_t *data, size_t n, eb_spec_t *spp, eb_layout_t *Lp) {
    eb_spec_t sp = blank(EB_ET_REL);
    sp.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x40, 16);
    sp.sec[1] = S("__ksymtab_strings", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1);
    sp.sec[1].data = data;
    sp.sec[1].size = n;
    sp.nsec = 2;
    int k = 0;
    sp.sym[k++] = Y("b",      EB_STB_GLOBAL, EB_STT_FUNC,   1, 0, 4);                         /* defined and global: it has a symbol */
    sp.sym[k++] = Y("c",      EB_STB_LOCAL,  EB_STT_FUNC,   1, 8, 4);                         /* local: not an export */
    sp.sym[k++] = Y("a",      EB_STB_GLOBAL, EB_STT_NOTYPE, EB_SHN_UNDEF, 0, 0);              /* undefined: not a definition */
    sp.sym[k++] = Y("w",      EB_STB_WEAK,   EB_STT_FUNC,   1, 0x10, 4);                      /* weak and defined: an export */
    sp.sym[k++] = Y("secsym", EB_STB_LOCAL,  EB_STT_SECTION, 1, 0, 0);
    sp.sym[k++] = Y("d",      EB_STB_GLOBAL, EB_STT_SECTION, 1, 0, 0);                        /* a section symbol does not define the name it happens to carry */
    sp.sym[k++] = Y("e",      EB_STB_GLOBAL, EB_STT_FILE,    EB_SHN_ABS, 0, 0);               /* nor does a file symbol */
    sp.nsym = k;
    *spp = sp;
    return eb_build(&sp, Lp);
}

static void test_ksymtab(void) {
    eb_spec_t sp;
    eb_layout_t L;
    static const uint8_t a[] = "a\0b\0c\0w\0d\0d\0\0\0e\0";
    eb_file_t f = ksym_file(a, sizeof a - 1, &sp, &L);
    cbae_binary_image_t *img = load_ok(&f);
    em_check(&sp, &L, img, 5);
    assert(img->symbol_count == 7 + 5 && img->meta.elf.has_ksymtab && img->note_count == 0);
    const char *want[5] = { "a", "c", "d", "d", "e" };                                          /* b and w have symbols; the others are named only here */
    for (int i = 0; i < 5; i++) {
        const cbae_symbol_t *y = &img->symbols[7 + i];
        assert(strcmp(y->name, want[i]) == 0 && y->type == CBAE_SYM_EXPORT && y->binding == CBAE_BIND_GLOBAL && y->kind == CBAE_KIND_UNKNOWN);
        assert(y->address == CBAE_ADDR_INVALID && y->table_index == 7u + i && y->size == 0 && y->section_idx == 0);
    }
    assert(cbae_image_symbol_by_name(img, "b") == &img->symbols[0] && cbae_image_symbol_by_name(img, "w") == &img->symbols[3]);
    assert(cbae_image_symbol_by_name(img, "a") == &img->symbols[2]);                           /* the undefined symbol and the name-only export rank alike: the first */
    assert(cbae_image_symbol_by_name(img, "d") == &img->symbols[9]);                           /* the first of two; the section symbol that carries the name is not indexed */
    cbae_image_destroy(&img);
    eb_free(&f);

    static const uint8_t unterminated[] = "x\0y";                                              /* the last name has no NUL */
    f = ksym_file(unterminated, sizeof unterminated - 1, &sp, &L);
    img = load_ok(&f);
    assert(img->symbol_count == 7 + 2 && strcmp(img->symbols[7].name, "x") == 0 && strcmp(img->symbols[8].name, "y") == 0);
    assert(has_note(img, "the last string of __ksymtab_strings has no terminating NUL") && img->note_count == 1);
    cbae_image_destroy(&img);
    eb_free(&f);

    static uint8_t longn[300];
    memset(longn, 'z', 250);
    longn[250] = 0;
    f = ksym_file(longn, 251, &sp, &L);
    img = load_ok(&f);
    assert(img->symbol_count == 8 && strlen(img->symbols[7].name) == CBAE_SYM_NAME_MAX - 1 && has_note(img, "1 symbol names are longer than 127 bytes"));
    cbae_image_destroy(&img);
    eb_free(&f);

    f = ksym_file(NULL, 0, &sp, &L);                                                           /* present and empty: still a module that exports through __ksymtab */
    img = load_ok(&f);
    assert(img->symbol_count == 7 && img->meta.elf.has_ksymtab);
    cbae_image_destroy(&img);
    eb_free(&f);

    /* two sections of that name: the first is the one that is read, the second is just a section. (Two files: the search for both
     * names stops as soon as it has found one of each, so a duplicate can only be seen if the other name has not been found yet.) */
    {
        static const uint8_t first[] = "p\0", second[] = "q\0", mi1[] = "license=first\0", mi2[] = "license=second\0author=B\0";
        sp = blank(EB_ET_REL);
        sp.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x10, 16);
        sp.sec[1] = S("__ksymtab_strings", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1);
        sp.sec[1].data = first; sp.sec[1].size = sizeof first - 1;
        sp.sec[2] = S("__ksymtab_strings", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1);
        sp.sec[2].data = second; sp.sec[2].size = sizeof second - 1;
        sp.nsec = 3;
        f = eb_build(&sp, &L);
        img = load_ok(&f);
        assert(img->symbol_count == 1 && strcmp(img->symbols[0].name, "p") == 0 && img->meta.elf.has_ksymtab);
        cbae_image_destroy(&img);
        eb_free(&f);

        sp = blank(EB_ET_REL);
        sp.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x10, 16);
        sp.sec[1] = S(".modinfo", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1);
        sp.sec[1].data = mi1; sp.sec[1].size = sizeof mi1 - 1;
        sp.sec[2] = S(".modinfo", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1);
        sp.sec[2].data = mi2; sp.sec[2].size = sizeof mi2 - 1;
        sp.nsec = 3;
        f = eb_build(&sp, &L);
        img = load_ok(&f);
        assert(strcmp(img->meta.elf.module_license, "first") == 0 && img->meta.elf.module_author[0] == '\0');
        cbae_image_destroy(&img);
        eb_free(&f);
    }

    /* no symbol table: every name in it is an export without a symbol */
    static const uint8_t two[] = "p\0q\0";
    sp = blank(EB_ET_REL);
    sp.sec[0] = S("__ksymtab_strings", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1);
    sp.sec[0].data = two; sp.sec[0].size = sizeof two - 1;
    sp.nsec = 1;
    sp.no_symtab = true;
    f = eb_build(&sp, &L);
    img = load_ok(&f);
    assert(img->symbol_count == 2 && strcmp(img->symbols[0].name, "p") == 0 && strcmp(img->symbols[1].name, "q") == 0);
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("__ksymtab_strings: names only it has become exports without addresses, defined ones are not repeated, damaged strings noted");
}

/* ---- headers ---- */

/* ---- the edges of the tables: which section a link means, which table is the symbol table, where a table's last entry is ---- */

static void test_table_edges(void) {
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    eb_file_t g;
    cbae_binary_image_t *img;
    assert(L.shnum == 15 && L.symtab == 12 && L.nrelsec == 3 && L.nsyms == 21);

    /* the symbol table's strings are in the section sh_link names; the section after the last one does not exist */
    g = clone(&f);
    eb_w32(g.b, eb_sh(&L, L.symtab) + EB_SH_LINK, L.shnum);
    img = load_ok(&g);
    assert(img->symbol_count == 23 && has_note(img, "(sh_link 15) does not exist: symbols have no names"));
    for (uint32_t i = 0; i < 20; i++) assert((i >= 1 && i <= 3) ? img->symbols[i].name[0] == '.' : img->symbols[i].name[0] == '\0');   /* the section symbols are named for their sections */
    assert(strcmp(img->symbols[20].name, "my_export") == 0 && strcmp(img->symbols[21].name, "init_module") == 0);   /* init_module is now an export without a symbol: no defined symbol has the name */
    cbae_image_destroy(&img);
    eb_free(&g);

    /* the section sh_link names is read as the string table whatever its type, and the type is said */
    g = clone(&f);
    eb_w32(g.b, eb_sh(&L, L.symtab) + EB_SH_LINK, 1);                                          /* .text */
    img = load_ok(&g);
    assert(has_note(img, "the symbol string table (section 1) is not of type SHT_STRTAB") && img->symbol_count >= 20);
    cbae_image_destroy(&img);
    eb_free(&g);

    /* st_name: the last byte of the string table is its NUL (the empty name, legal); one past it is outside the table */
    g = clone(&f);
    eb_w32(g.b, eb_sym(&L, 5) + EB_ST_NAME, L.strtab_size - 1);
    img = load_ok(&g);
    assert(strcmp(img->symbols[4].name, "") == 0 && !has_note(img, "symbol names are not in the string table") && img->note_count == 1);
    cbae_image_destroy(&img);
    eb_free(&g);
    g = clone(&f);
    eb_w32(g.b, eb_sym(&L, 5) + EB_ST_NAME, L.strtab_size);
    img = load_ok(&g);
    assert(strcmp(img->symbols[4].name, "") == 0 && has_note(img, "1 symbol names are not in the string table: those symbols have no name"));
    cbae_image_destroy(&img);
    eb_free(&g);

    /* an index kept in SHT_SYMTAB_SHNDX: the table whose sh_link is the symbol table that was read, one entry per symbol */
    sp = eb_spec_default();
    sp.sym[sp.nsym] = Y("xsym", EB_STB_GLOBAL, EB_STT_FUNC, EB_S_TEXT, 8, 4);
    sp.sym[sp.nsym++].xindex = true;                                                           /* ELF symbol 21 */
    eb_layout_t L2;
    eb_file_t f2;
    img = build_and_check(&sp, &L2, &f2, 2);
    const cbae_symbol_t *x = sym_named(img, "xsym");
    assert(L2.nsyms == 22 && L2.shndx_tab != 0 && x && x->address == 0x400008 && x->section_idx == 1);
    cbae_image_destroy(&img);

    g = clone(&f2);                                                                            /* linked to some other section: not this symbol table's */
    eb_w32(g.b, eb_sh(&L2, L2.shndx_tab) + EB_SH_LINK, 1);
    img = load_ok(&g);
    x = sym_named(img, "xsym");
    assert(x && x->address == CBAE_ADDR_INVALID && x->section_idx == 0xFFFF && has_note(img, "1 symbols need the extended section index table"));
    cbae_image_destroy(&img);
    eb_free(&g);

    g = clone(&f2);                                                                            /* 21 entries (0..20): symbol 21 is the first without one */
    eb_w64(g.b, eb_sh(&L2, L2.shndx_tab) + EB_SH_SIZE, 21 * 4);
    img = load_ok(&g);
    x = sym_named(img, "xsym");
    assert(x && x->address == CBAE_ADDR_INVALID && x->section_idx == 0xFFFF && has_note(img, "1 symbols need the extended section index table"));
    cbae_image_destroy(&img);
    eb_free(&g);

    g = clone(&f2);                                                                            /* 22 entries: it has its own */
    eb_w64(g.b, eb_sh(&L2, L2.shndx_tab) + EB_SH_SIZE, 22 * 4);
    img = load_ok(&g);
    x = sym_named(img, "xsym");
    assert(x && x->address == 0x400008 && !has_note(img, "extended section index table"));
    cbae_image_destroy(&img);
    eb_free(&g);
    eb_free(&f2);

    /* two symbol tables: the first in the section table is the one that is read, and the others are said to be ignored */
    {
        static uint8_t decoy[2 * 24];
        memset(decoy, 0, sizeof decoy);
        decoy[24 + EB_ST_INFO] = EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_FUNC);
        eb_w16(decoy, 24 + EB_ST_SHNDX, 1);
        eb_w64(decoy, 24 + EB_ST_VALUE, 4);
        eb_spec_t s2 = blank(EB_ET_REL);
        s2.sec[0] = S(".text", EB_SHT_PROGBITS, AX, 0x20, 16);
        s2.sec[1] = S(".symtab.decoy", EB_SHT_SYMTAB, 0, sizeof decoy, 8);
        s2.sec[1].entsize = 24;
        s2.sec[1].data = decoy;
        s2.nsec = 2;
        s2.sym[0] = Y("real_a", EB_STB_GLOBAL, EB_STT_FUNC, 1, 0, 4);
        s2.sym[1] = Y("real_b", EB_STB_GLOBAL, EB_STT_FUNC, 1, 8, 4);
        s2.sym[2] = Y("real_c", EB_STB_GLOBAL, EB_STT_FUNC, 1, 16, 4);
        s2.nsym = 3;
        eb_layout_t L3;
        eb_file_t f3 = eb_build(&s2, &L3);
        assert(L3.symtab == 3);
        img = load_ok(&f3);
        assert(img->symbol_count == 1 && img->symbols[0].address == 0x400004 && img->symbols[0].type == CBAE_SYM_EXPORT);
        assert(has_note(img, "the file has 1 more symbol tables: only the first (section 2) is read") && strcmp(img->sections[1].name, ".symtab.decoy") == 0);
        cbae_image_destroy(&img);
        eb_free(&f3);
    }

    /* relocation sections: an entry size of 0 means the standard 24; one that claims more than the file holds is read as far as it goes */
    img = load_ok(&f);
    assert(img->reloc_count == 14 && img->import_count == 4);
    g = clone(&f);
    for (uint32_t k = 0; k < L.nrelsec; k++) eb_w64(g.b, eb_sh(&L, L.rela_idx[k]) + EB_SH_ENTSIZE, 0);
    cbae_binary_image_t *img0 = load_ok(&g);
    assert(img0->reloc_count == 14 && img0->import_count == 4 && img0->note_count == img->note_count && !has_note(img0, "entry size other than 24"));
    assert(memcmp(img0->relocations, img->relocations, 14 * sizeof img->relocations[0]) == 0);
    assert(memcmp(img0->imports, img->imports, 4 * sizeof img->imports[0]) == 0);
    cbae_image_destroy(&img0);
    eb_free(&g);

    g = clone(&f);                                                                             /* .rela.data: two entries, of which the file holds the last 24 bytes of the file, one */
    eb_w64(g.b, eb_sh(&L, L.rela_idx[1]) + EB_SH_OFFSET, g.n - 24);
    img0 = load_ok(&g);
    assert(has_note(img0, "1 relocation sections run past the end of the file: only the entries present are read") && img0->reloc_count == 12 + 1);
    {   /* the last 24 bytes of the file are the end of the last section header: sh_link 0 and sh_info 0 (r_offset 0), sh_addralign 1 (R_X86_64_64 against no symbol), sh_entsize 0 (addend) */
        const cbae_relocation_t *r = &img0->relocations[12];
        const cbae_section_t *data = cbae_image_section_by_name(img0, ".data");
        assert(data && r->target_va == data->virt_addr && r->type == CBAE_RELOC_64 && r->sym_index == NOSYM && r->addend == 0 && r->file_offset == L.sec_off[3]);
    }
    cbae_image_destroy(&img0);
    eb_free(&g);
    g = clone(&f);                                                                             /* none of it in the file */
    eb_w64(g.b, eb_sh(&L, L.rela_idx[1]) + EB_SH_OFFSET, g.n + 100);
    img0 = load_ok(&g);
    assert(has_note(img0, "1 relocation sections run past the end of the file") && img0->reloc_count == 12);
    cbae_image_destroy(&img0);
    eb_free(&g);
    cbae_image_destroy(&img);
    eb_free(&f);
    PASS("table edges: sh_link one past the last section, st_name at the end of the string table, the extended index table (its link, one entry short), two symbol tables, relocation entry size 0, relocations past the end");
}

static void test_rejections(void) {
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);

    for (size_t n = 0; n < 64; n++) assert(load_err_n(f.b, n) == CBAE_ERR_PARSE);              /* too short for a header: every length */
    eb_file_t g;
#define DAMAGE(stmt) do { g = clone(&f); stmt; assert(load_err(&g) == CBAE_ERR_PARSE); eb_free(&g); } while (0)
    for (int i = 0; i < 4; i++) DAMAGE(g.b[i] ^= 0xFF);                                        /* each byte of the magic */
    DAMAGE(g.b[EB_EI_CLASS] = EB_CLASS32);
    DAMAGE(g.b[EB_EI_CLASS] = 0);
    DAMAGE(g.b[EB_EI_CLASS] = 3);
    DAMAGE(g.b[EB_EI_DATA] = EB_DATA_MSB);
    DAMAGE(g.b[EB_EI_DATA] = 0);
    DAMAGE(g.b[EB_EI_DATA] = 3);
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, 0));                                                        /* no section header table */
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, g.n));                                                      /* at the end of the file */
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, g.n + 1));
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, g.n - 63));                                                 /* not even one header fits */
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, g.n - 64));                                                 /* one fits, 14 do not */
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, UINT64_MAX));                                               /* no wrap when 64 is added */
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, UINT64_MAX - 63));
    DAMAGE(eb_w64(g.b, EB_E_SHOFF, UINT64_C(1) << 63));
    DAMAGE(eb_w16(g.b, EB_E_SHENTSIZE, 0));                                                    /* a section header is 64 bytes */
    DAMAGE(eb_w16(g.b, EB_E_SHENTSIZE, 63));
    DAMAGE(eb_w16(g.b, EB_E_SHENTSIZE, 65));
    DAMAGE(eb_w16(g.b, EB_E_SHENTSIZE, 128));
    DAMAGE(eb_w16(g.b, EB_E_SHNUM, 16));                                                       /* one more header than the file has (it has 15, the null one included) */
    DAMAGE(eb_w16(g.b, EB_E_SHNUM, 0xFFFF));
    DAMAGE(eb_w16(g.b, EB_E_SHNUM, 0); eb_w64(g.b, eb_sh(&L, 0) + EB_SH_SIZE, 0));             /* "see section 0", which says 0 */
    DAMAGE(eb_w16(g.b, EB_E_SHNUM, 0); eb_w64(g.b, eb_sh(&L, 0) + EB_SH_SIZE, UINT64_C(1) << 40));
    DAMAGE(eb_w16(g.b, EB_E_SHNUM, 0); eb_w64(g.b, eb_sh(&L, 0) + EB_SH_SIZE, UINT64_MAX));    /* a count that would wrap the table's size */
    DAMAGE(eb_w16(g.b, EB_E_SHNUM, 0); eb_w64(g.b, eb_sh(&L, 0) + EB_SH_SIZE, UINT64_C(1) << 58));   /* x 64 wraps to 0 */
    /* e_shnum 0 says "the count is in section 0's sh_size", and e_shstrndx 0xFFFF "the index is in its sh_link": both need a
     * whole header to read, so a table that starts anywhere in the last 70 bytes of the file is refused without being read */
    for (size_t k = 1; k <= 70; k++) DAMAGE(eb_w16(g.b, EB_E_SHNUM, 0); eb_w16(g.b, EB_E_SHSTRNDX, 0xFFFF); eb_w64(g.b, EB_E_SHOFF, g.n - k));
#undef DAMAGE
    assert(cbae_elf_load_buffer(NULL, 5, "x", &(cbae_binary_image_t *){NULL}) == CBAE_ERR_INVALID);
    {
        cbae_binary_image_t *img = (cbae_binary_image_t *)1;
        assert(cbae_elf_load_buffer(f.b, f.n, "x", NULL) == CBAE_ERR_INVALID);
        assert(cbae_elf_load_buffer(NULL, 0, NULL, &img) == CBAE_ERR_PARSE && img == NULL);
    }

    /* the table's last header ends exactly at the end of the file: that is the default layout, and it loads;
     * one header fewer than the table says is fine too (the name table is then not in the table) */
    cbae_binary_image_t *img = load_ok(&f);
    assert(sp.nsec == 8 && L.shoff + 15 * 64 == f.n);
    cbae_image_destroy(&img);
    g = clone(&f);
    eb_w16(g.b, EB_E_SHNUM, 14);
    img = load_ok(&g);
    assert(img->section_count == 13 && has_note(img, "e_shstrndx 14 is outside the 14 sections") && img->sections[0].name[0] == '\0');
    cbae_image_destroy(&img);
    eb_free(&g);

    /* things that are only odd: noted, never refused */
    struct { const char *what; const char *note; } odd[] = { { "ident version", "e_ident gives ELF version 2" }, { "e_version", "e_version is 7" }, { "e_ehsize", "e_ehsize is 48, not 64" },
                                                            { "e_type 0", "e_type 0 is not" }, { "e_type 5", "e_type 5 is not" }, { "machine 3", "machine type 3 is neither" } };
    for (size_t i = 0; i < sizeof odd / sizeof odd[0]; i++) {
        g = clone(&f);
        switch (i) {
        case 0: g.b[EB_EI_VERSION] = 2; break;
        case 1: eb_w32(g.b, EB_E_VERSION, 7); break;
        case 2: eb_w16(g.b, EB_E_EHSIZE, 48); break;
        case 3: eb_w16(g.b, EB_E_TYPE, 0); break;
        case 4: eb_w16(g.b, EB_E_TYPE, 5); break;
        case 5: eb_w16(g.b, EB_E_MACHINE, 3); break;
        }
        img = load_ok(&g);
        assert(has_note(img, odd[i].note));
        assert(img->section_count == 14 && img->symbol_count == 22);
        if (i == 5) assert(img->arch == CBAE_ARCH_UNKNOWN);
        cbae_image_destroy(&img);
        eb_free(&g);
    }
    g = clone(&f);
    eb_w16(g.b, EB_E_MACHINE, EB_EM_AARCH64);
    img = load_ok(&g);
    assert(img->arch == CBAE_ARCH_ARM64 && !has_note(img, "machine type"));
    cbae_image_destroy(&img);
    eb_free(&g);
    eb_free(&f);
    PASS("headers: every kind of damage is refused with CBAE_ERR_PARSE and leaves no image; oddities are loaded and noted");
}

static void test_path_api(void) {
    char dir[] = "/tmp/cbae_elf_XXXXXX";
    assert(mkdtemp(dir));
    char path[160];
    snprintf(path, sizeof path, "%s/good.ko", dir);
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    assert(eb_write(path, &f));
    cbae_binary_image_t *img = NULL;
    assert(cbae_elf_load(path, &img) == CBAE_OK && img);
    elf_check_image(img, f.b, f.n);
    em_check(&sp, &L, img, 2);
    assert(strcmp(img->path, path) == 0 && img->import_count == 4);
    cbae_image_destroy(&img);

    char empty[160], missing[160], bad[160];
    snprintf(empty, sizeof empty, "%s/empty.ko", dir);
    snprintf(missing, sizeof missing, "%s/none.ko", dir);
    snprintf(bad, sizeof bad, "%s/bad.ko", dir);
    FILE *e = fopen(empty, "wb"); assert(e); fclose(e);
    eb_file_t junk = { (uint8_t *)calloc(1, 128), 128 };
    memset(junk.b, 0xCC, junk.n);
    assert(eb_write(bad, &junk));
    assert(cbae_elf_load(empty, &img) == CBAE_ERR_PARSE && img == NULL);
    assert(cbae_elf_load(missing, &img) == CBAE_ERR_NOT_FOUND && img == NULL);
    assert(cbae_elf_load(dir, &img) == CBAE_ERR_INVALID && img == NULL);
    assert(cbae_elf_load(bad, &img) == CBAE_ERR_PARSE && img == NULL);
    assert(cbae_elf_load(NULL, &img) == CBAE_ERR_INVALID && img == NULL);
    assert(cbae_elf_load(path, NULL) == CBAE_ERR_INVALID);
    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    assert(system(cmd) == 0);
    eb_free(&junk);
    eb_free(&f);
    PASS("loading from a path: success, empty file (parse), missing file (not found), directory (invalid), junk (parse), NULL arguments (invalid)");
}

/* ---- a model check: random specifications ---- */

static void test_model_random_specs(void) {
    const int iterations = getenv("CBAE_TEST_QUICK") ? 60 : 400;
    rng_t r = { UINT64_C(0x9E3779B97F4A7C15) };
    static elf_case_t c;
    int n_rel = 0, n_linked = 0, n_imports = 0, n_relocs = 0, n_xindex = 0, n_notes = 0, n_other_machine = 0, n_syms = 0, n_unloaded_rela = 0;
    for (int it = 0; it < iterations; it++) {
        er_random_case(&r, &c);
        eb_layout_t L;
        eb_file_t f = eb_build(&c.spec, &L);
        cbae_binary_image_t *img = load_ok(&f);
        em_check(&c.spec, &L, img, 0);
        n_rel += c.spec.etype == EB_ET_REL;
        n_linked += c.spec.etype != EB_ET_REL;
        n_imports += img->import_count > 0;
        n_relocs += img->reloc_count > 0;
        n_notes += img->note_count > 0;
        n_other_machine += c.spec.machine != EB_EM_X86_64;
        n_syms += img->symbol_count > 0;
        for (int i = 0; i < c.spec.nsym; i++) n_xindex += c.spec.sym[i].xindex;
        n_unloaded_rela += has_note(img, "apply to sections that are not loaded");
        cbae_image_destroy(&img);
        eb_free(&f);
    }
    assert(n_rel > iterations / 2 && n_linked > iterations / 10 && n_imports > iterations / 10 && n_relocs > iterations / 2);
    assert(n_xindex > iterations && n_notes > iterations / 4 && n_other_machine > iterations / 20 && n_syms > iterations / 2 && n_unloaded_rela > 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%d random specifications (%d relocatable, %d linked, %d with imports): every section, symbol, relocation and import matches the model", iterations, n_rel, n_linked, n_imports);
    PASS(msg);
}

/* ---- out of memory ---- */

typedef struct { const eb_file_t *f; const eb_spec_t *sp; const eb_layout_t *L; } oom_ctx_t;

static cbae_err_t oom_body(void *vctx, uint64_t failing) {
    const oom_ctx_t *c = (const oom_ctx_t *)vctx;
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_elf_load_buffer(c->f->b, c->f->n, "oom.ko", &img);
    if (rc != CBAE_OK) {
        assert(failing != 0 && img == NULL);                    /* an error leaves no image behind */
        return rc;
    }
    assert(img);
    ai_disarm();                                                /* the checks below allocate */
    elf_check_image(img, c->f->b, c->f->n);
    em_check(c->sp, c->L, img, 2);                              /* complete and correct, not partial */
    assert(img->section_count == 14 && img->symbol_count == 22 && img->import_count == 4 && img->reloc_count == 14 && img->note_count == 1);
    cbae_image_destroy(&img);
    return CBAE_OK;
}

static void test_oom_sweep(void) {
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    oom_ctx_t ctx = { &f, &sp, &L };
    const oom_report_t r = oom_sweep(oom_body, &ctx, false);
    assert(r.allocations > 6 && r.runs == 2 * r.allocations && r.reported > 0);
    eb_free(&f);
    char msg[256];
    snprintf(msg, sizeof msg, "out of memory at each of the %llu allocations of a load (alone, and with every later one failing): %llu errors, %llu complete results, no leak",
             (unsigned long long)r.allocations, (unsigned long long)r.reported, (unsigned long long)r.swallowed);
    PASS(msg);
}

int main(void) {
    printf("=== test_elf_loader ===\n");
    blob_init();
    test_default_file();
    test_layout_rel();
    test_linked_files();
    test_section_quirks();
    test_symbol_rules();
    test_symbol_index_choices();
    test_relocation_rules();
    test_import_rules();
    test_no_symbol_table();
    test_extended_numbering();
    test_modinfo();
    test_ksymtab();
    test_table_edges();
    test_rejections();
    test_path_api();
    test_model_random_specs();
    test_oom_sweep();
    printf("All ELF loader tests passed.\n");
    return 0;
}
