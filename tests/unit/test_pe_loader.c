/**
 * @file test_pe_loader.c
 * @brief PE32+ loader tests (audit A-030, A-047).
 *
 * Every file here is written by pe_builder.h from the PE/COFF specification, not from the loader's own
 * idea of the format. (The first version of this test built its files with a copy of the loader's header
 * struct, which was two bytes off, so the loader passed on files no linker produces.)
 *
 *   - the default file, checked field by field against numbers worked out from the specification
 *   - quirks real files have: fewer data directories, VirtualSize 0, tables in unaligned places,
 *     bigger optional headers, sections with a zero-filled tail or file padding
 *   - rejections: each kind of damage, with the error code it must give
 *   - the tables' edge cases: unmapped names, bad ordinals, forwarders, cut blocks, empty PDB paths
 *   - a model check: random specifications, the loader's output compared with what the spec says
 *   - an out-of-memory sweep over the whole load
 * The sweeps over damaged files are in test_pe_hostile.c.
 */
#include "loader/pe_loader.h"
#include "platform/file_io.h"
#include "platform/sha256.h"
#include "oom_sweep.h"
#include "pe_builder.h"
#include "pe_check.h"
#include "pe_random.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define IB UINT64_C(0x140000000)

/* ---- helpers ---- */

static cbae_binary_image_t *load_ok(const uint8_t *b, size_t n) {
    cbae_binary_image_t *img = NULL;
    const cbae_err_t rc = cbae_pe_load_buffer(b, n, "mem.sys", &img);
    if (rc != CBAE_OK) fprintf(stderr, "load failed: %s\n", cbae_last_error());
    assert(rc == CBAE_OK && img);
    pe_check_image(img, b, n);
    return img;
}

static cbae_err_t load_err(const uint8_t *b, size_t n) {
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_pe_load_buffer(b, n, "mem.sys", &img);
    assert(rc != CBAE_OK && img == NULL);
    return rc;
}

static bool has_note(const cbae_binary_image_t *img, const char *part) {
    const uint32_t kept = img->note_count < CBAE_IMAGE_NOTES_MAX ? img->note_count : CBAE_IMAGE_NOTES_MAX;
    for (uint32_t i = 0; i < kept; i++) if (strstr(img->notes[i], part)) return true;
    return false;
}

static uint8_t *pbdup(const pb_file_t *f) { uint8_t *c = (uint8_t *)malloc(f->n); assert(c); memcpy(c, f->b, f->n); return c; }

static const cbae_symbol_t *sym_named(const cbae_binary_image_t *img, const char *name) {
    for (uint32_t i = 0; i < img->symbol_count; i++) if (strcmp(img->symbols[i].name, name) == 0) return &img->symbols[i];
    return NULL;
}

/* ---- the default file, against numbers worked out from the specification ---- */

static void test_header_fields(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    assert(L.opt_size == 240 && L.coff == 0x84 && L.opt == 0x98 && L.sect_tab == 0x98 + 240);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->arch == CBAE_ARCH_X86_64);
    assert(img->load_base == IB && img->meta.pe.image_base == IB);
    assert(img->entry_point == IB + 0x1000);
    assert(img->meta.pe.image_size == 0x6000);
    assert(img->meta.pe.subsystem == 1 && img->meta.pe.is_driver);
    assert(img->meta.pe.dll_characteristics == 0x8160);
    assert(img->meta.pe.checksum == 0x0012ABCDu);
    assert(img->note_count == 0);
    assert(strcmp(img->path, "mem.sys") == 0);
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("optional header fields are read at their specified offsets (image base, entry, subsystem, size, checksum)");
}

static void test_sections(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    static const char *names[PB_NSEC] = { ".text", ".rdata", ".data", ".pdata", ".reloc" };
    static const uint32_t flags[PB_NSEC] = {
        CBAE_SEC_EXEC | CBAE_SEC_READ, CBAE_SEC_INIT | CBAE_SEC_READ, CBAE_SEC_INIT | CBAE_SEC_READ | CBAE_SEC_WRITE,
        CBAE_SEC_INIT | CBAE_SEC_READ, CBAE_SEC_INIT | CBAE_SEC_READ };
    assert(img->section_count == PB_NSEC);
    for (int i = 0; i < PB_NSEC; i++) {
        const cbae_section_t *s = &img->sections[i];
        assert(strcmp(s->name, names[i]) == 0);
        assert(s->virt_addr == IB + L.sec_rva[i]);
        assert(s->virt_size == L.sec_vsize[i]);
        assert(s->file_offset == L.sec_off[i]);
        /* the bytes of a section that are in the file AND in the image: SizeOfRawData is rounded up to the file
         * alignment, so the padding after VirtualSize is not part of the section */
        const uint32_t backed = L.sec_raw[i] < L.sec_vsize[i] ? L.sec_raw[i] : L.sec_vsize[i];
        assert(s->file_size == backed);
        assert(s->flags == flags[i]);
        assert(s->data == img->file_data + L.sec_off[i]);
    }
    assert(img->sections[PB_S_TEXT].virt_size == 0x200 && img->sections[PB_S_TEXT].file_size == 0x200);
    /* .data: 0x400 in memory, 0x200 in the file: the tail is zero-filled memory with no bytes behind it */
    assert(img->sections[PB_S_DATA].virt_size == 0x400 && img->sections[PB_S_DATA].file_size == 0x200);
    /* .pdata: 3 entries of 12 bytes in memory; the file has 0x200 bytes of it, 0x1DC of them padding */
    assert(img->sections[PB_S_PDATA].virt_size == 0x24 && img->sections[PB_S_PDATA].file_size == 0x24);
    /* addresses */
    const uint8_t *code = cbae_image_va_to_ptr(img, IB + 0x1000);
    assert(code && code[0] == 0x31 && code[1] == 0xC0 && code[2] == 0xC3);
    assert(cbae_image_va_to_ptr(img, IB + 0x3000) != NULL);
    assert(cbae_image_section_at_va(img, IB + 0x33FF) == &img->sections[PB_S_DATA]);       /* in the zero tail ... */
    assert(cbae_image_va_to_ptr(img, IB + 0x33FF) == NULL);                                  /* ... with no file bytes */
    assert(cbae_image_va_to_ptr(img, IB + 0x4024) == NULL && cbae_image_section_at_va(img, IB + 0x4024) == NULL);
    assert(cbae_image_section_at_va(img, IB + 0x0FFF) == NULL && cbae_image_section_at_va(img, IB) == NULL);
    assert(cbae_image_section_by_name(img, ".pdata") == &img->sections[PB_S_PDATA]);
    assert(cbae_image_offset_to_va(img, L.sec_off[PB_S_TEXT] + 5) == IB + 0x1005);
    assert(cbae_image_offset_to_va(img, L.sec_off[PB_S_PDATA] + 0x24) == CBAE_ADDR_INVALID);   /* file padding has no address */
    assert(cbae_image_offset_to_va(img, 0x10) == CBAE_ADDR_INVALID);                            /* neither do the headers */
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("sections: addresses, sizes, flags, data pointers; file padding and the zero-filled tail are not section bytes");
}

static void test_imports(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->import_count == 5);
    static const struct { const char *mod, *name; uint16_t hint, ord; cbae_import_state_t st; int dll, k; } want[5] = {
        { "ntoskrnl.exe", "IoCreateDevice", 0x0123, 0, CBAE_IMPORT_BY_NAME, 0, 0 },
        { "ntoskrnl.exe", "IoDeleteDevice", 0x0124, 0, CBAE_IMPORT_BY_NAME, 0, 1 },
        { "ntoskrnl.exe", "ord#1111", 0, 0x0457, CBAE_IMPORT_BY_ORDINAL, 0, 2 },
        { "ntoskrnl.exe", "ExAllocatePool2", 0x0041, 0, CBAE_IMPORT_BY_NAME, 0, 3 },
        { "HAL.dll", "KeStallExecutionProcessor", 0x0007, 0, CBAE_IMPORT_BY_NAME, 1, 0 },
    };
    for (int i = 0; i < 5; i++) {
        const cbae_import_entry_t *m = &img->imports[i];
        assert(strcmp(m->module, want[i].mod) == 0 && strcmp(m->name, want[i].name) == 0);
        assert(m->hint == want[i].hint && m->ordinal == want[i].ord && m->state == want[i].st);
        assert(m->iat_va == IB + L.imp_iat_rva[want[i].dll] + 8u * (uint32_t)want[i].k);   /* the IAT slot the code calls through */
        assert(!cbae_import_has_rela(m) && m->table_index == (uint32_t)i);
        assert(cbae_image_import_at_iat(img, m->iat_va) == m);
    }
    assert(cbae_image_import_by_name(img, "IoDeleteDevice") == &img->imports[1]);
    assert(cbae_image_import_by_name(img, "NoSuch") == NULL);
    char shown[CBAE_IMPORT_DISPLAY_MAX];
    assert(cbae_import_display(&img->imports[4], shown, sizeof shown) && strcmp(shown, "HAL.dll!KeStallExecutionProcessor") == 0);
    char cut[8];                                                                              /* a small buffer gets the beginning, terminated, and the answer is false */
    assert(!cbae_import_display(&img->imports[4], cut, sizeof cut) && strcmp(cut, "HAL.dll") == 0);
    char one[1] = { 'x' };
    assert(!cbae_import_display(&img->imports[4], one, 1) && one[0] == '\0');
    assert(!cbae_import_display(&img->imports[4], one, 0) && !cbae_import_display(&img->imports[4], NULL, 5) && !cbae_import_display(NULL, one, 1));
    cbae_import_entry_t o = img->imports[4];                                                   /* no name: by ordinal */
    o.name[0] = '\0'; o.ordinal = 65535;
    assert(cbae_import_display(&o, shown, sizeof shown) && strcmp(shown, "HAL.dll!ord#65535") == 0);
    memset(o.module, 'm', sizeof o.module - 1); o.module[sizeof o.module - 1] = '\0';          /* the longest names: nothing is lost in a full-size buffer */
    memset(o.name, 'n', sizeof o.name - 1); o.name[sizeof o.name - 1] = '\0';
    assert(cbae_import_display(&o, shown, sizeof shown) && strlen(shown) == (CBAE_IMPORT_MODULE_MAX - 1) + 1 + (CBAE_IMPORT_NAME_MAX - 1));
    assert(L.imp_ilt_rva[1] == 0);                         /* HAL.dll was built without a lookup table: its IAT was read */
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("imports: by name and by ordinal, hints, IAT addresses; a descriptor without a lookup table is read through its IAT");
}

static void test_exports(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->symbol_count == 6);
    /* names come in name-table order, then the slots that have no name, by ordinal */
    static const struct { const char *name; uint64_t addr; cbae_sym_kind_t kind; } want[6] = {
        { "DriverEntry",   IB + 0x1000, CBAE_KIND_FUNCTION },
        { "FwdFunc",       CBAE_ADDR_INVALID, CBAE_KIND_FUNCTION },
        { "MyHelper",      IB + 0x1010, CBAE_KIND_FUNCTION },
        { "MyHelperAlias", IB + 0x1010, CBAE_KIND_FUNCTION },
        { "g_Counter",     IB + 0x3000, CBAE_KIND_OBJECT },       /* an export in a data section is data */
        { "ord#7",         IB + 0x1020, CBAE_KIND_FUNCTION },      /* ordinal base 5 + slot 2 */
    };
    for (int i = 0; i < 6; i++) {
        const cbae_symbol_t *y = &img->symbols[i];
        assert(strcmp(y->name, want[i].name) == 0 && y->address == want[i].addr && y->kind == want[i].kind);
        assert(y->type == CBAE_SYM_EXPORT && y->binding == CBAE_BIND_GLOBAL && y->table_index == (uint32_t)i);
    }
    assert(strcmp(img->symbols[1].source, "fwd:NTDLL.RtlFoo") == 0);       /* a forwarder has no address, only a target */
    assert(!cbae_symbol_is_resolved(&img->symbols[1]));
    assert(img->symbols[0].source[0] == '\0');
    assert(cbae_image_symbol_by_name(img, "MyHelper") == &img->symbols[2]);
    assert(cbae_image_symbol_by_name(img, "NoSuchExport") == NULL);
    assert(cbae_image_symbol_at_va(img, IB + 0x1000) == &img->symbols[0]);
    assert(cbae_image_symbol_at_va(img, IB + 0x1010) == &img->symbols[2]);  /* an alias ties; the first in table order wins */
    assert(cbae_image_symbol_at_va(img, IB + 0x3000) == &img->symbols[4]);
    assert(cbae_image_symbol_at_va(img, IB + 0x1020) == &img->symbols[5]);
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("exports: named, alias, unnamed (ordinal = base + slot), forwarder, data export; lookups by name and address");
}

static void test_relocations(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->reloc_count == 6);
    static const struct { uint64_t va; cbae_reloc_type_t t; uint32_t page; } want[6] = {
        { IB + 0x1008, CBAE_RELOC_ABS64, 0x1000 }, { IB + 0x1010, CBAE_RELOC_ABS64, 0x1000 },
        { IB + 0x1020, CBAE_RELOC_ABS32, 0x1000 }, { IB + 0x1000, CBAE_RELOC_NOP, 0x1000 },
        { IB + 0x3000, CBAE_RELOC_ABS64, 0x3000 }, { IB + 0x3008, CBAE_RELOC_UNKNOWN, 0x3000 },   /* type 1 (HIGH) is not modelled */
    };
    for (int i = 0; i < 6; i++) {
        const cbae_relocation_t *r = &img->relocations[i];
        assert(r->target_va == want[i].va && r->type == want[i].t && r->page_rva == want[i].page);
        assert(!r->applied && !r->references_import && r->addend == 0);
    }
    assert(img->relocations[0].file_offset == L.sec_off[PB_S_TEXT] + 8);        /* where the fixup sits in the file */
    assert(img->relocations[4].file_offset == L.sec_off[PB_S_DATA]);
    assert(cbae_reloc_is_absolute(&img->relocations[0]) && !cbae_reloc_is_pc_relative(&img->relocations[0]));
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("base relocations: targets, types, pages, and the file offset of each fixup");
}

static void test_debug_and_identity(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(strcmp(img->meta.pe.pdb_path, "C:\\build\\mydrv.pdb") == 0);
    assert(strlen(img->sha256) == 64);                         /* pe_check_image compared it with SHA-256 of the file */
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("CodeView PDB path and the SHA-256 of the file");
}

/* ---- the same file, built the other ways real linkers build them ---- */

static void test_directory_count_variants(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f;
    cbae_binary_image_t *img;

    sp.num_dirs = 2;                                           /* export and import only: no relocation or debug directory */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->import_count == 5 && img->symbol_count == 6 && img->reloc_count == 0 && img->meta.pe.pdb_path[0] == '\0');
    assert(img->note_count == 0);
    cbae_image_destroy(&img); pb_free(&f);

    sp.num_dirs = 0;                                           /* no directories at all */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->import_count == 0 && img->symbol_count == 0 && img->reloc_count == 0 && img->section_count == PB_NSEC);
    cbae_image_destroy(&img); pb_free(&f);

    sp.num_dirs = 7;                                           /* the header has room for 7; it SAYS 16 */
    f = pb_build(&sp, &L);
    pb_w32(f.b, L.opt + PB_OPT_NUM_DIRS, 16);
    img = load_ok(f.b, f.n);
    assert(img->reloc_count == 6 && strcmp(img->meta.pe.pdb_path, "C:\\build\\mydrv.pdb") == 0);   /* dirs 5 and 6 are inside the 7 */
    assert(has_note(img, "room for 7"));
    cbae_image_destroy(&img); pb_free(&f);

    sp.num_dirs = 16;
    f = pb_build(&sp, &L);
    pb_w32(f.b, L.opt + PB_OPT_NUM_DIRS, 0x10000000);          /* absurd count, room for 16 */
    img = load_ok(f.b, f.n);
    assert(img->import_count == 5 && has_note(img, "only the first 16"));
    cbae_image_destroy(&img); pb_free(&f);

    f = pb_build(&sp, &L);
    pb_w32(f.b, L.opt + PB_OPT_DIRS + PB_DIR_IMPORT * 8 + 4, 0);     /* a directory with a size of 0 is not there */
    img = load_ok(f.b, f.n);
    assert(img->import_count == 0 && img->symbol_count == 6);
    cbae_image_destroy(&img); pb_free(&f);
    f = pb_build(&sp, &L);
    pb_w32(f.b, L.opt + PB_OPT_DIRS + PB_DIR_IMPORT * 8, 0);         /* ... nor one at RVA 0 */
    img = load_ok(f.b, f.n);
    assert(img->import_count == 0);
    cbae_image_destroy(&img); pb_free(&f);
    PASS("data directories: fewer than 16, none, a count that lies, size 0 or RVA 0");
}

static void test_virtual_size_zero(void) {
    pb_spec_t sp = pb_spec_default();
    sp.text_vsize_zero = true;
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    assert(pb_r32(f.b, L.sec_hdr[PB_S_TEXT] + PB_SEC_VSIZE) == 0);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->sections[PB_S_TEXT].virt_size == 0x200 && img->sections[PB_S_TEXT].file_size == 0x200);   /* the size in memory is SizeOfRawData */
    assert(cbae_image_va_to_ptr(img, IB + 0x11FF) != NULL && cbae_image_section_at_va(img, IB + 0x1200) == NULL);
    cbae_image_destroy(&img); pb_free(&f);
    PASS("VirtualSize 0 means the size in memory is SizeOfRawData");
}

static void test_bigger_optional_header(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    /* 16 bytes of something after the data directories, inside SizeOfOptionalHeader: the section table moves */
    memmove(f.b + L.sect_tab + 16, f.b + L.sect_tab, PB_NSEC * PB_SEC_HDR_SIZE);
    memset(f.b + L.sect_tab, 0xEE, 16);
    pb_w16(f.b, L.coff + PB_COFF_OPTSIZE, (uint16_t)(L.opt_size + 16));
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->section_count == PB_NSEC && strcmp(img->sections[PB_S_RDATA].name, ".rdata") == 0 && img->import_count == 5);
    cbae_image_destroy(&img); pb_free(&f);
    PASS("a SizeOfOptionalHeader larger than the fixed part locates the section table correctly");
}

static void test_section_quirks(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f;
    cbae_binary_image_t *img;

    f = pb_build(&sp, &L);                                     /* an 8-character name has no NUL */
    memcpy(f.b + L.sec_hdr[PB_S_DATA] + PB_SEC_NAME, "ABCDEFGH", 8);
    img = load_ok(f.b, f.n);
    assert(strcmp(img->sections[PB_S_DATA].name, "ABCDEFGH") == 0 && strlen(img->sections[PB_S_DATA].name) == 8);
    cbae_image_destroy(&img); pb_free(&f);

    f = pb_build(&sp, &L);                                     /* a section with no raw data: .bss */
    pb_w32(f.b, L.sec_hdr[PB_S_DATA] + PB_SEC_RAWSIZE, 0);
    pb_w32(f.b, L.sec_hdr[PB_S_DATA] + PB_SEC_RAWPTR, 0);
    img = load_ok(f.b, f.n);
    assert(img->sections[PB_S_DATA].file_size == 0 && img->sections[PB_S_DATA].data == NULL && img->sections[PB_S_DATA].virt_size == 0x400);
    assert(cbae_image_section_at_va(img, IB + 0x3010) == &img->sections[PB_S_DATA] && cbae_image_va_to_ptr(img, IB + 0x3010) == NULL);
    assert(img->reloc_count == 6 && img->relocations[4].file_offset == (cbae_off_t)CBAE_ADDR_INVALID);   /* a fixup in .bss has no file bytes */
    cbae_image_destroy(&img); pb_free(&f);

    f = pb_build(&sp, &L);                                     /* raw data pointer past the end of the file */
    pb_w32(f.b, L.sec_hdr[PB_S_RELOC] + PB_SEC_RAWPTR, (uint32_t)f.n + 0x1000);
    img = load_ok(f.b, f.n);
    assert(img->sections[PB_S_RELOC].file_size == 0 && img->reloc_count == 0 && has_note(img, "runs past the end"));
    cbae_image_destroy(&img); pb_free(&f);

    f = pb_build(&sp, &L);                                     /* the file is cut inside the last section: what is there is kept */
    const size_t cut = L.sec_off[PB_S_RELOC] + 10;
    img = load_ok(f.b, cut);
    assert(img->sections[PB_S_RELOC].file_size == 10 && img->sections[PB_S_RELOC].virt_size == 28);
    assert(has_note(img, ".reloc") && img->reloc_count == 1);   /* 10 bytes: a header and one entry of the first block */
    cbae_image_destroy(&img); pb_free(&f);

    f = pb_build(&sp, &L);                                     /* two sections that overlap in memory */
    pb_w32(f.b, L.sec_hdr[PB_S_DATA] + PB_SEC_RVA, L.sec_rva[PB_S_TEXT] + 0x100);
    img = load_ok(f.b, f.n);
    assert(has_note(img, "overlap"));
    cbae_image_destroy(&img); pb_free(&f);

    f = pb_build(&sp, &L);                                     /* no sections at all */
    pb_w16(f.b, L.coff + PB_COFF_NSECTIONS, 0);
    img = load_ok(f.b, f.n);
    assert(img->section_count == 0 && img->import_count == 0 && has_note(img, "entry point"));
    cbae_image_destroy(&img); pb_free(&f);
    PASS("section quirks: 8-character name, no raw data, raw data past the end, cut file, overlap, none");
}

static void test_machine_and_entry(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f;
    cbae_binary_image_t *img;

    sp.machine = PB_MACHINE_ARM64;
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->arch == CBAE_ARCH_ARM64 && !has_note(img, "machine"));
    cbae_image_destroy(&img); pb_free(&f);

    sp.machine = 0x01C4;                                       /* ARMNT: loaded, but it is not a machine the engine analyses */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->arch == CBAE_ARCH_UNKNOWN && has_note(img, "0x01c4"));
    cbae_image_destroy(&img); pb_free(&f);

    sp = pb_spec_default();
    sp.entry_rva = 0;                                          /* a DLL with no entry point */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->entry_point == CBAE_ADDR_INVALID && !has_note(img, "entry point"));
    cbae_image_destroy(&img); pb_free(&f);

    sp = pb_spec_default();
    sp.entry_rva = 0x3000;                                     /* in a data section */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->entry_point == IB + 0x3000 && has_note(img, "not in an executable section"));
    cbae_image_destroy(&img); pb_free(&f);

    sp = pb_spec_default();
    sp.subsystem = 3;                                          /* console: not a driver */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(!img->meta.pe.is_driver && img->meta.pe.subsystem == 3);
    cbae_image_destroy(&img); pb_free(&f);

    sp = pb_spec_default();
    sp.image_base = UINT64_C(0xFFFFF80000000000);              /* where a kernel image lives */
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(img->load_base == UINT64_C(0xFFFFF80000000000) && img->entry_point == UINT64_C(0xFFFFF80000001000));
    assert(img->sections[PB_S_TEXT].virt_addr == UINT64_C(0xFFFFF80000001000));
    cbae_image_destroy(&img); pb_free(&f);
    PASS("machine types, no entry point, entry point outside code, subsystem, a kernel-space image base");
}

/* ---- rejections ---- */

static void test_rejections(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    uint8_t *b;

    assert(load_err(NULL, 0) == CBAE_ERR_PARSE);               /* an empty file */
    assert(load_err(f.b, 1) == CBAE_ERR_PARSE && load_err(f.b, 63) == CBAE_ERR_PARSE);
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    assert(cbae_pe_load_buffer(NULL, 5, "x", &img) == CBAE_ERR_INVALID && img == NULL);
    assert(cbae_pe_load_buffer(f.b, f.n, "x", NULL) == CBAE_ERR_INVALID);
    assert(cbae_pe_load(NULL, &img) == CBAE_ERR_INVALID && cbae_pe_load("/x", NULL) == CBAE_ERR_INVALID);

    b = pbdup(&f); b[0] = 'Z'; b[1] = 'M';                       /* ZM is not MZ */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);

    b = pbdup(&f); pb_w32(b, PB_DOS_E_LFANEW, (uint32_t)f.n);    /* e_lfanew at the end of the file */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE);
    pb_w32(b, PB_DOS_E_LFANEW, 0xFFFFFFFFu);                   /* and one that would wrap a 32-bit sum */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE);
    pb_w32(b, PB_DOS_E_LFANEW, (uint32_t)f.n - 25);            /* exactly one byte short of the COFF header and a magic */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);

    b = pbdup(&f); b[L.e_lfanew + 2] = 'X';                      /* PE\0\0 -> PEX\0 */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);

    b = pbdup(&f); pb_w16(b, L.opt + PB_OPT_MAGIC, PB_MAGIC_PE32);   /* 32-bit */
    assert(load_err(b, f.n) == CBAE_ERR_UNSUPPORTED);
    pb_w16(b, L.opt + PB_OPT_MAGIC, 0x107);                    /* ROM image */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE);
    pb_w16(b, L.opt + PB_OPT_MAGIC, 0); assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);

    static const uint16_t badopt[] = { 0, 1, 2, 111, 0xFFFF };
    for (size_t i = 0; i < sizeof badopt / sizeof badopt[0]; i++) {
        b = pbdup(&f); pb_w16(b, L.coff + PB_COFF_OPTSIZE, badopt[i]);
        assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);
    }
    b = pbdup(&f); pb_w16(b, L.coff + PB_COFF_OPTSIZE, (uint16_t)(f.n - L.opt + 1));   /* one byte past the end of the file */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);

    b = pbdup(&f); pb_w16(b, L.coff + PB_COFF_NSECTIONS, 97);    /* more than the Windows loader accepts */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE); free(b);
    {                                                          /* 96 sections is allowed: the table has to fit in the file, and a byte less does not */
        const size_t need = L.sect_tab + 96 * PB_SEC_HDR_SIZE;
        b = (uint8_t *)calloc(1, need + 16);
        assert(b);
        memcpy(b, f.b, f.n < need + 16 ? f.n : need + 16);        /* the table's tail overlays section data: junk entries, which the loader must cope with */
        pb_w16(b, L.coff + PB_COFF_NSECTIONS, 96);
        cbae_binary_image_t *ok96 = load_ok(b, need);
        assert(ok96->section_count == 96);
        cbae_image_destroy(&ok96);
        assert(load_err(b, need - 1) == CBAE_ERR_PARSE);
        free(b);
    }

    b = pbdup(&f); pb_w64(b, L.opt + PB_OPT_IMAGE_BASE, UINT64_MAX);
    assert(load_err(b, f.n) == CBAE_ERR_PARSE);
    pb_w64(b, L.opt + PB_OPT_IMAGE_BASE, UINT64_C(0xFFFFFFFF00000000));
    assert(load_err(b, f.n) == CBAE_ERR_PARSE);
    pb_w64(b, L.opt + PB_OPT_IMAGE_BASE, UINT64_MAX - 2 * (uint64_t)UINT32_MAX + 1);   /* the first base that would wrap */
    assert(load_err(b, f.n) == CBAE_ERR_PARSE);
    pb_w64(b, L.opt + PB_OPT_IMAGE_BASE, UINT64_MAX - 2 * (uint64_t)UINT32_MAX);       /* the last one that does not */
    img = load_ok(b, f.n);
    assert(img->sections[PB_NSEC - 1].virt_addr > img->load_base);
    cbae_image_destroy(&img); free(b);

    pb_free(&f);
    PASS("rejections: empty, short, MZ, e_lfanew, PE signature, PE32, optional header size, section count and table, image base");
}

static void test_path_api(void) {
    char dir[] = "/tmp/cbae_pe_XXXXXX";
    assert(mkdtemp(dir));
    char path[160];
    snprintf(path, sizeof path, "%s/good.sys", dir);
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    assert(pb_write(path, &f));
    cbae_binary_image_t *img = NULL;
    assert(cbae_pe_load(path, &img) == CBAE_OK && img);
    pe_check_image(img, f.b, f.n);
    assert(strcmp(img->path, path) == 0 && img->import_count == 5);
    cbae_image_destroy(&img);

    char empty[160], missing[160];
    snprintf(empty, sizeof empty, "%s/empty.sys", dir);
    snprintf(missing, sizeof missing, "%s/none.sys", dir);
    FILE *e = fopen(empty, "wb"); assert(e); fclose(e);
    assert(cbae_pe_load(empty, &img) == CBAE_ERR_PARSE && img == NULL);
    assert(cbae_pe_load(missing, &img) == CBAE_ERR_NOT_FOUND && img == NULL);
    assert(cbae_pe_load(dir, &img) == CBAE_ERR_INVALID && img == NULL);
    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    assert(system(cmd) == 0);
    pb_free(&f);
    PASS("loading from a path: success, empty file (parse), missing file (not found), directory (invalid)");
}

/* ---- the tables' edge cases ---- */

static void test_import_edge_cases(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    uint8_t *b;
    cbae_binary_image_t *img;

    b = pbdup(&f);                                               /* a hint/name RVA that is in no section */
    pb_w64(b, pb_rva_to_off(&L, L.imp_ilt_rva[0]) + 8, 0x7FFFFF00);
    img = load_ok(b, f.n);
    assert(img->import_count == 5 && img->imports[1].name[0] == '\0' && img->imports[1].state == CBAE_IMPORT_UNRESOLVED);
    assert(has_note(img, "not in the file") && strcmp(img->imports[0].name, "IoCreateDevice") == 0 && strcmp(img->imports[3].name, "ExAllocatePool2") == 0);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a DLL name that is in no section: the entries are kept */
    pb_w32(b, pb_rva_to_off(&L, L.imp_dir_rva) + 12, 0x7FFFFF00);
    img = load_ok(b, f.n);
    assert(img->import_count == 5 && img->imports[0].module[0] == '\0' && strcmp(img->imports[0].name, "IoCreateDevice") == 0);
    assert(strcmp(img->imports[4].module, "HAL.dll") == 0);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* an ILT RVA that is in no section: that DLL contributes nothing */
    pb_w32(b, pb_rva_to_off(&L, L.imp_dir_rva), 0x7FFFFF00);
    img = load_ok(b, f.n);
    assert(img->import_count == 1 && strcmp(img->imports[0].module, "HAL.dll") == 0 && has_note(img, "lookup table"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* the import directory RVA is in no section */
    pb_w32(b, L.dir_entry[PB_DIR_IMPORT], 0x7FFFFF00);
    img = load_ok(b, f.n);
    assert(img->import_count == 0 && has_note(img, "import directory"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* the descriptor array loses its terminator: the walk stops at the end of the data */
    memset(b + pb_rva_to_off(&L, L.imp_dir_rva) + 2 * PB_IMPORT_DESC_SIZE, 0, PB_IMPORT_DESC_SIZE);
    pb_w32(b, pb_rva_to_off(&L, L.imp_dir_rva) + 2 * PB_IMPORT_DESC_SIZE + 12, 0);   /* (still zero: this IS the terminator) */
    img = load_ok(b, f.n);
    assert(img->import_count == 5);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* an ordinal import's high bits are ignored; only the low 16 are the ordinal */
    pb_w64(b, pb_rva_to_off(&L, L.imp_ilt_rva[0]) + 16, (UINT64_C(1) << 63) | UINT64_C(0xABCD0000) | 0x0457);
    img = load_ok(b, f.n);
    assert(img->imports[2].ordinal == 0x0457 && img->imports[2].state == CBAE_IMPORT_BY_ORDINAL);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a name longer than the field is cut, and noted */
    {
        const uint32_t hn = pb_rva_to_off(&L, L.imp_hintname_rva[0][0]) + 2;
        const uint32_t room = L.sec_off[PB_S_RDATA] + L.sec_vsize[PB_S_RDATA] - hn;
        assert(room > 200);
        /* IoCreateDevice\0 is followed by IoDeleteDevice\0 ...: overwrite the NUL so the name runs on for 200+ bytes */
        memset(b + hn, 'A', 200);
        b[hn + 200] = 0;
    }
    img = load_ok(b, f.n);
    assert(strlen(img->imports[0].name) == CBAE_IMPORT_NAME_MAX - 1 && has_note(img, "was cut"));
    cbae_image_destroy(&img); free(b);
    pb_free(&f);
    PASS("imports: unmapped names, DLL names and tables are kept or skipped as documented, long names are cut, never read past");
}

static void test_export_edge_cases(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    uint8_t *b;
    cbae_binary_image_t *img;
    const uint32_t names_off = pb_rva_to_off(&L, L.exp_names_rva), ords_off = pb_rva_to_off(&L, L.exp_ords_rva);
    const uint32_t eat_off = pb_rva_to_off(&L, L.exp_eat_rva), dir_off = pb_rva_to_off(&L, L.exp_dir_rva);

    b = pbdup(&f);                                               /* an ordinal index outside the address table */
    pb_w16(b, ords_off, 0x7FFF);
    img = load_ok(b, f.n);
    assert(img->symbol_count == 6 && sym_named(img, "DriverEntry") == NULL && sym_named(img, "ord#5") != NULL);   /* the function is still listed, by ordinal */
    assert(sym_named(img, "ord#5")->address == IB + 0x1000 && has_note(img, "ordinal index"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a name pointer that is in no section */
    pb_w32(b, names_off + 4, 0x7FFF0000);
    img = load_ok(b, f.n);
    assert(img->symbol_count == 6 && sym_named(img, "FwdFunc") == NULL && sym_named(img, "ord#8") != NULL && has_note(img, "listed by ordinal"));
    assert(strcmp(sym_named(img, "ord#8")->source, "fwd:NTDLL.RtlFoo") == 0);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a name for an empty slot: the name is dropped */
    pb_w32(b, eat_off + 0, 0);
    img = load_ok(b, f.n);
    assert(img->symbol_count == 5 && sym_named(img, "DriverEntry") == NULL && sym_named(img, "ord#5") == NULL);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a forwarder string outside the directory's range is just an address */
    pb_w32(b, L.dir_entry[PB_DIR_EXPORT] + 4, PB_EXPORT_DIR_SIZE + 5 * 4 + 5 * 4 + 5 * 2);   /* the tables, not the strings */
    img = load_ok(b, f.n);
    assert(sym_named(img, "FwdFunc") && cbae_symbol_is_resolved(sym_named(img, "FwdFunc")) && sym_named(img, "FwdFunc")->source[0] == '\0');
    cbae_image_destroy(&img); free(b);

    {                                                          /* the forwarder range is [directory, directory + size): its first and last byte are in, the bytes around it are out */
        const uint32_t lo = L.exp_dir_rva, hi = L.exp_dir_rva + L.exp_dir_size;
        const struct { uint32_t target; bool forwarder; } edge[] = { { lo - 1, false }, { lo, true }, { hi - 1, true }, { hi, false } };
        for (size_t i = 0; i < sizeof edge / sizeof edge[0]; i++) {
            b = pbdup(&f);
            pb_w32(b, eat_off + 0, edge[i].target);            /* DriverEntry's slot */
            img = load_ok(b, f.n);
            const cbae_symbol_t *y = sym_named(img, "DriverEntry");
            assert(y && (strncmp(y->source, "fwd:", 4) == 0) == edge[i].forwarder);
            assert(cbae_symbol_is_resolved(y) == !edge[i].forwarder && (edge[i].forwarder || y->address == IB + edge[i].target));
            cbae_image_destroy(&img); free(b);
        }
    }

    b = pbdup(&f);                                               /* NumberOfFunctions and NumberOfNames far past the end of the file */
    pb_w32(b, dir_off + 20, 0xFFFFFFFFu);
    pb_w32(b, dir_off + 24, 0xFFFFFFFFu);
    img = load_ok(b, f.n);
    assert(img->symbol_count >= 6 && img->symbol_count <= 0x10000 + 0x10000 && has_note(img, "declares 4294967295 functions"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a huge ordinal base is only a number */
    pb_w32(b, dir_off + 16, 0xFFFFFFFFu);
    img = load_ok(b, f.n);
    assert(sym_named(img, "ord#4294967297") != NULL);          /* base + slot 2, in 64 bits: no wrap to 1 */
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* the export directory is in no section */
    pb_w32(b, L.dir_entry[PB_DIR_EXPORT], 0x7FFFFF00);
    img = load_ok(b, f.n);
    assert(img->symbol_count == 0 && has_note(img, "export directory"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a name that does not fit its field is cut */
    {
        const uint32_t nm = pb_rva_to_off(&L, pb_r32(b, names_off));          /* DriverEntry */
        memset(b + nm, 'N', 11);                                              /* keep its NUL where it was */
    }
    img = load_ok(b, f.n);
    assert(sym_named(img, "NNNNNNNNNNN") != NULL);
    cbae_image_destroy(&img); free(b);
    pb_free(&f);

    /* the largest table an export directory can declare: 0x10000 slots, all used */
    pb_mini_t m = pb_mini(0x10000 * 4 + 0x100);
    const uint32_t eat_rva = m.sec_rva + 0x40;
    pb_w32(m.b, m.sec_off + 20, 0x10000);                      /* NumberOfFunctions */
    pb_w32(m.b, m.sec_off + 16, 1);                            /* base */
    pb_w32(m.b, m.sec_off + 28, eat_rva);
    for (uint32_t i = 0; i < 0x10000; i++) pb_w32(m.b, m.sec_off + 0x40 + i * 4, 0x1000 + i);
    pb_mini_dir(&m, PB_DIR_EXPORT, m.sec_rva, 40);
    img = load_ok(m.b, m.n);
    assert(img->symbol_count == 0x10000 && strcmp(img->symbols[0xFFFF].name, "ord#65536") == 0);
    assert(img->note_count == 0);                              /* exactly the limit is not over it */
    cbae_image_destroy(&img);
    pb_w32(m.b, m.sec_off + 20, 0x20000);                      /* declare twice that: only 0x10000 are read */
    img = load_ok(m.b, m.n);
    assert(img->symbol_count == 0x10000 && has_note(img, "only the first 65536"));
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("exports: bad ordinal index, unmapped name, empty slot, forwarder range, huge counts and base, cut names, 64K slots");
}

static void test_reloc_edge_cases(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    uint8_t *b;
    cbae_binary_image_t *img;
    const uint32_t rel_off = L.sec_off[PB_S_RELOC];

    b = pbdup(&f);                                               /* second block claims 4 bytes: smaller than its header */
    pb_w32(b, rel_off + 16 + 4, 4);
    img = load_ok(b, f.n);
    assert(img->reloc_count == 4 && has_note(img, "less than its 8-byte header"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* first block claims 0 bytes */
    pb_w32(b, rel_off + 4, 0);
    img = load_ok(b, f.n);
    assert(img->reloc_count == 0);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* second block claims more than the directory holds: it is cut */
    pb_w32(b, rel_off + 16 + 4, 0x1000);
    img = load_ok(b, f.n);
    assert(img->reloc_count == 4 + 2 && has_note(img, "declares 4096 bytes"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a directory size larger than its section's data */
    pb_w32(b, L.dir_entry[PB_DIR_BASERELOC] + 4, 0x100000);
    img = load_ok(b, f.n);
    assert(img->reloc_count >= 6 && has_note(img, "base relocation directory"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a directory size that ends inside the first block's entries */
    pb_w32(b, L.dir_entry[PB_DIR_BASERELOC] + 4, 12);
    img = load_ok(b, f.n);
    assert(img->reloc_count == 2);                             /* the block says 16 bytes, 12 are there: 2 entries fit after the header */
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* unknown types and the highest page */
    pb_w32(b, rel_off + 16, 0xFFFFF000u);
    pb_w16(b, rel_off + 16 + 8, (uint16_t)((5 << 12) | 0xFFF));
    img = load_ok(b, f.n);
    assert(img->relocations[4].target_va == IB + 0xFFFFF000u + 0xFFF && img->relocations[4].type == CBAE_RELOC_UNKNOWN);
    assert(img->relocations[4].file_offset == (cbae_off_t)CBAE_ADDR_INVALID);
    cbae_image_destroy(&img); free(b);
    pb_free(&f);

    /* more relocations than the old fixed 8 MiB arena could hold at 64 bytes each */
    const uint32_t blocks = 200, per = 1024;
    pb_mini_t m = pb_mini(blocks * (8 + per * 2));
    for (uint32_t k = 0; k < blocks; k++) {
        const uint32_t at = m.sec_off + k * (8 + per * 2);
        pb_w32(m.b, at, 0x10000 + k * 0x1000);
        pb_w32(m.b, at + 4, 8 + per * 2);
        for (uint32_t e = 0; e < per; e++) pb_w16(m.b, at + 8 + e * 2, (uint16_t)((PB_REL_DIR64 << 12) | (e & 0xFFF)));
    }
    pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, blocks * (8 + per * 2));
    img = load_ok(m.b, m.n);
    assert(img->reloc_count == blocks * per && (uint64_t)img->reloc_count * sizeof(cbae_relocation_t) > 8u * 1024 * 1024);
    assert(img->relocations[blocks * per - 1].target_va == UINT64_C(0x10000000) + 0x10000 + (blocks - 1) * 0x1000 + (per - 1));
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("relocations: bad block sizes, cut blocks, oversized directory, unknown types, a table bigger than the old 8 MiB arena");
}

static void test_debug_edge_cases(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f;
    cbae_binary_image_t *img;

    sp.ndebug = 3;                                             /* an RSDS with an empty path, then one with a path */
    sp.debug[0] = (pb_debug_t){ 2, true, NULL };
    sp.debug[1] = (pb_debug_t){ 13, false, NULL };
    sp.debug[2] = (pb_debug_t){ 2, true, "D:\\second.pdb" };
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(strcmp(img->meta.pe.pdb_path, "D:\\second.pdb") == 0);        /* an empty path does not end the search */
    cbae_image_destroy(&img); pb_free(&f);

    sp = pb_spec_default();
    sp.ndebug = 2;
    sp.debug[0] = (pb_debug_t){ 2, true, "first.pdb" };
    sp.debug[1] = (pb_debug_t){ 2, true, "second.pdb" };
    f = pb_build(&sp, &L);
    img = load_ok(f.b, f.n);
    assert(strcmp(img->meta.pe.pdb_path, "first.pdb") == 0);              /* the first non-empty one wins */
    cbae_image_destroy(&img); pb_free(&f);

    sp = pb_spec_default();
    f = pb_build(&sp, &L);
    uint8_t *b = pbdup(&f);                                      /* PointerToRawData past the end of the file */
    pb_w32(b, pb_rva_to_off(&L, L.debug_rva) + PB_DEBUG_ENTRY_SIZE + 24, (uint32_t)f.n + 5);
    img = load_ok(b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0' && has_note(img, "past the end of the file"));
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* SizeOfData too small to hold the RSDS header */
    pb_w32(b, pb_rva_to_off(&L, L.debug_rva) + PB_DEBUG_ENTRY_SIZE + 16, 20);
    img = load_ok(b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0');
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* the record is cut at the end of the file: a path with no NUL is the bytes there */
    img = load_ok(b, L.cv_off[1] + 24 + 5);
    assert(strcmp(img->meta.pe.pdb_path, "C:\\bu") == 0);
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* a path longer than the field */
    {
        const uint32_t at = L.cv_off[1] + 24;
        const uint32_t room = L.sec_off[PB_S_RDATA] + L.sec_vsize[PB_S_RDATA] - at;
        assert(room >= 18);
        pb_w32(b, pb_rva_to_off(&L, L.debug_rva) + PB_DEBUG_ENTRY_SIZE + 16, 24 + 400);   /* SizeOfData claims 400 bytes of path */
        memset(b + at, 'p', room);                                                         /* ... and the section holds only `room` */
    }
    img = load_ok(b, f.n);
    assert(strlen(img->meta.pe.pdb_path) <= sizeof img->meta.pe.pdb_path - 1 && img->meta.pe.pdb_path[0] == 'p');
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* the signature is not RSDS */
    memcpy(b + L.cv_off[1], "NB10", 4);
    img = load_ok(b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0');
    cbae_image_destroy(&img); free(b);

    b = pbdup(&f);                                               /* debug directory size that is not a whole number of entries: floor */
    pb_w32(b, L.dir_entry[PB_DIR_DEBUG] + 4, 2 * PB_DEBUG_ENTRY_SIZE - 1);
    img = load_ok(b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0');                  /* only entry 0 (COFF, not CodeView) remains */
    cbae_image_destroy(&img); free(b);
    pb_free(&f);
    PASS("debug directory: empty path skipped, first wins, record bounds, signature, size not a multiple");
}

static void test_tables_in_headers(void) {
    /* a tiny PE keeps its import table inside the headers, below SizeOfHeaders: RVA == file offset there */
    pb_mini_t m = pb_mini(0x200);
    const uint32_t imp = 0x300, ilt = 0x320, name = 0x340, hn = 0x350;     /* all < 0x400 */
    pb_w32(m.b, imp + 0, ilt);
    pb_w32(m.b, imp + 12, name);
    pb_w32(m.b, imp + 16, ilt);
    pb_w64(m.b, ilt, hn);
    memcpy(m.b + name, "tiny.dll", 9);
    pb_w16(m.b, hn, 0x55);
    memcpy(m.b + hn + 2, "TinyFn", 7);
    pb_mini_dir(&m, PB_DIR_IMPORT, imp, 40);
    /* the optional header and section table end at 0x188 + 40; 0x300 is free */
    cbae_binary_image_t *img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && strcmp(img->imports[0].module, "tiny.dll") == 0 && strcmp(img->imports[0].name, "TinyFn") == 0);
    assert(img->imports[0].hint == 0x55 && img->imports[0].iat_va == UINT64_C(0x10000000) + ilt);
    cbae_image_destroy(&img);
    pb_w32(m.b, m.opt + PB_OPT_SIZE_OF_HDRS, 0x330);           /* the name now lies above SizeOfHeaders: not mapped */
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && img->imports[0].module[0] == '\0');
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("a table inside the headers is read; SizeOfHeaders bounds what counts as headers");
}

/* ---- model check: random specifications, loader output against what the specification says ---- */

static int m_sec_of_rva(const pb_layout_t *L, uint32_t rva) {
    for (int i = 0; i < PB_NSEC; i++) if (rva >= L->sec_rva[i] && rva - L->sec_rva[i] < L->sec_vsize[i]) return i;
    return -1;
}
static uint32_t m_off(const pb_layout_t *L, uint32_t rva) {            /* file offset of an RVA, UINT32_MAX if no file bytes are behind it */
    const int i = m_sec_of_rva(L, rva);
    if (i < 0) return rva < PB_HEADERS_SIZE ? rva : UINT32_MAX;
    const uint32_t backed = L->sec_raw[i] < L->sec_vsize[i] ? L->sec_raw[i] : L->sec_vsize[i];
    return rva - L->sec_rva[i] < backed ? L->sec_off[i] + (rva - L->sec_rva[i]) : UINT32_MAX;
}

static void model_check(const pb_spec_t *sp, const pb_layout_t *L, const cbae_binary_image_t *img) {
    const uint64_t ib = sp->image_base;
    assert(img->load_base == ib && img->meta.pe.image_base == ib);
    assert(img->entry_point == (sp->entry_rva ? ib + sp->entry_rva : CBAE_ADDR_INVALID));
    assert(img->meta.pe.subsystem == sp->subsystem && img->meta.pe.is_driver == (sp->subsystem == 1));
    assert(img->meta.pe.dll_characteristics == sp->dll_chars && img->meta.pe.checksum == sp->checksum);
    assert(img->arch == (sp->machine == PB_MACHINE_AMD64 ? CBAE_ARCH_X86_64 : sp->machine == PB_MACHINE_ARM64 ? CBAE_ARCH_ARM64 : CBAE_ARCH_UNKNOWN));

    assert(img->section_count == PB_NSEC);
    for (int i = 0; i < PB_NSEC; i++) {
        const cbae_section_t *s = &img->sections[i];
        const uint32_t backed = L->sec_raw[i] < L->sec_vsize[i] ? L->sec_raw[i] : L->sec_vsize[i];
        assert(s->virt_addr == ib + L->sec_rva[i] && s->virt_size == L->sec_vsize[i] && s->file_size == backed && s->file_offset == L->sec_off[i]);
    }

    uint32_t ni = 0;
    for (int d = 0; d < sp->ndll; d++)
        for (int k = 0; k < sp->dll[d].nfn; k++, ni++) {
            const pb_import_t *fn = &sp->dll[d].fn[k];
            assert(ni < img->import_count);
            const cbae_import_entry_t *m = &img->imports[ni];
            assert(strcmp(m->module, sp->dll[d].dll) == 0 && m->iat_va == ib + L->imp_iat_rva[d] + 8u * (uint32_t)k);
            if (fn->by_ordinal) {
                char want[32];
                snprintf(want, sizeof want, "ord#%u", fn->ordinal);
                assert(m->state == CBAE_IMPORT_BY_ORDINAL && m->ordinal == fn->ordinal && strcmp(m->name, want) == 0);
            } else {
                assert(m->state == CBAE_IMPORT_BY_NAME && m->hint == fn->hint && strcmp(m->name, fn->name) == 0);
            }
        }
    assert(ni == img->import_count);

    uint32_t ns = 0;
    if (sp->exports.present) {
        const pb_exports_t *E = &sp->exports;
        bool named[PB_MAX] = { false };
        for (int i = 0; i < E->nnames; i++) {
            const pb_slot_t *sl = &E->slot[E->name[i].slot];
            if (!sl->forward && sl->rva == 0) continue;                              /* a name on an empty slot is dropped */
            named[E->name[i].slot] = true;
            assert(ns < img->symbol_count);
            const cbae_symbol_t *y = &img->symbols[ns++];
            assert(strcmp(y->name, E->name[i].name) == 0);
            if (sl->forward) { char src[64]; snprintf(src, sizeof src, "fwd:%.56s", sl->forward); assert(y->address == CBAE_ADDR_INVALID && strcmp(y->source, src) == 0 && y->kind == CBAE_KIND_FUNCTION); }
            else { const int sec = m_sec_of_rva(L, sl->rva); assert(y->address == ib + sl->rva && y->kind == (sec < 0 ? CBAE_KIND_NOTYPE : sec == PB_S_TEXT ? CBAE_KIND_FUNCTION : CBAE_KIND_OBJECT)); }
        }
        for (int s = 0; s < E->nslots; s++) {
            const pb_slot_t *sl = &E->slot[s];
            if (named[s] || (!sl->forward && sl->rva == 0)) continue;
            assert(ns < img->symbol_count);
            const cbae_symbol_t *y = &img->symbols[ns++];
            char want[40];
            snprintf(want, sizeof want, "ord#%llu", (unsigned long long)E->base + (unsigned)s);
            assert(strcmp(y->name, want) == 0);
            if (sl->forward) assert(y->address == CBAE_ADDR_INVALID); else assert(y->address == ib + sl->rva);
        }
    }
    assert(ns == img->symbol_count);

    uint32_t nr = 0;
    for (int b = 0; b < sp->nblocks; b++) {
        const pb_block_t *B = &sp->block[b];
        const int entries = B->nfix + (B->nfix & 1);                                  /* the builder pads a block to 4 bytes with an ABSOLUTE entry */
        for (int e = 0; e < entries; e++) {
            assert(nr < img->reloc_count);
            const cbae_relocation_t *r = &img->relocations[nr++];
            const uint8_t type = e < B->nfix ? B->fix[e].type : PB_REL_ABSOLUTE;
            const uint16_t off = e < B->nfix ? B->fix[e].offset : 0;
            assert(r->page_rva == B->page_rva && r->target_va == ib + B->page_rva + (off & 0xFFF));
            assert(r->type == (type == PB_REL_ABSOLUTE ? CBAE_RELOC_NOP : type == PB_REL_HIGHLOW ? CBAE_RELOC_ABS32 : type == PB_REL_DIR64 ? CBAE_RELOC_ABS64 : CBAE_RELOC_UNKNOWN));
            const uint32_t fo = m_off(L, B->page_rva + (off & 0xFFF));
            assert(r->file_offset == (fo == UINT32_MAX ? (cbae_off_t)CBAE_ADDR_INVALID : fo));
        }
    }
    assert(nr == img->reloc_count);

    const char *pdb = "";
    for (int i = 0; i < sp->ndebug; i++)
        if (sp->debug[i].type == 2 && sp->debug[i].rsds && sp->debug[i].pdb && sp->debug[i].pdb[0]) { pdb = sp->debug[i].pdb; break; }
    assert(strcmp(img->meta.pe.pdb_path, pdb) == 0);
}

static void test_model_random_specs(void) {
    const int iterations = getenv("CBAE_TEST_QUICK") ? 60 : 400;
    rng_t r = { UINT64_C(0x9E3779B97F4A7C15) };
    for (int it = 0; it < iterations; it++) {
        pb_spec_t sp = random_spec(&r);
        pb_layout_t L;
        pb_file_t f = pb_build(&sp, &L);
        cbae_binary_image_t *img = load_ok(f.b, f.n);
        model_check(&sp, &L, img);
        cbae_image_destroy(&img);
        pb_free(&f);
    }
    char msg[256];
    snprintf(msg, sizeof msg, "%d random specifications: every import, export, relocation and field matches the specification", iterations);
    PASS(msg);
}

/* ---- out of memory ---- */

typedef struct { const uint8_t *b; size_t n; } oom_ctx_t;

static cbae_err_t oom_body(void *vctx, uint64_t failing) {
    const oom_ctx_t *c = (const oom_ctx_t *)vctx;
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_pe_load_buffer(c->b, c->n, "oom.sys", &img);
    if (rc != CBAE_OK) {
        assert(failing != 0 && img == NULL);                    /* an error leaves no image behind */
        return rc;
    }
    assert(img);
    ai_disarm();                                                /* the checks below allocate */
    pe_check_image(img, c->b, c->n);
    assert(img->section_count == PB_NSEC && img->import_count == 5 && img->symbol_count == 6 && img->reloc_count == 6);   /* complete, not partial */
    cbae_image_destroy(&img);
    return CBAE_OK;
}

static void test_oom_sweep(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    oom_ctx_t ctx = { f.b, f.n };
    const oom_report_t r = oom_sweep(oom_body, &ctx, false);
    assert(r.allocations > 5 && r.runs == 2 * r.allocations && r.reported > 0);
    pb_free(&f);
    char msg[256];
    snprintf(msg, sizeof msg, "out of memory at each of the %llu allocations of a load (alone, and with every later one failing): %llu errors, %llu complete results, no leak",
             (unsigned long long)r.allocations, (unsigned long long)r.reported, (unsigned long long)r.swallowed);
    PASS(msg);
}

int main(void) {
    printf("=== test_pe_loader ===\n");
    test_header_fields();
    test_sections();
    test_imports();
    test_exports();
    test_relocations();
    test_debug_and_identity();
    test_directory_count_variants();
    test_virtual_size_zero();
    test_bigger_optional_header();
    test_section_quirks();
    test_machine_and_entry();
    test_rejections();
    test_path_api();
    test_import_edge_cases();
    test_export_edge_cases();
    test_reloc_edge_cases();
    test_debug_edge_cases();
    test_tables_in_headers();
    test_model_random_specs();
    test_oom_sweep();
    printf("All PE loader tests passed.\n");
    return 0;
}
