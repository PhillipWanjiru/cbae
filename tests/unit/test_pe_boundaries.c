/**
 * @file test_pe_boundaries.c
 * @brief PE loader: every limit tested exactly at its edge (audit A-030, A-036, A-038).
 *
 * The random and damage sweeps (test_pe_hostile.c, test_pe_real.c) find crashes and images that are not
 * self-consistent. They cannot find an off-by-one: a file one byte either side of a limit looks the same to
 * a checker that only asks whether the image is consistent. The mutation campaign over the loader
 * (tools/mutation/run_mut.py pe) found exactly those gaps, so each is closed here by a test that states the
 * exact answer at the edge:
 *
 *   - the last byte of a section, and the first byte of the next one
 *   - a table that fills its span to the last byte (no note), and one that is a byte short (a note)
 *   - a name one character under, and one character over, the size of its field
 *   - the smallest header that is accepted, and the largest one that is refused
 *   - what the loader must NOT say: a clean file at a limit has no notes at all
 *   - the two defects the campaign led to: a relocation whose RVA passes 4 GiB (the old code wrapped it to a
 *     header offset), and an export forwarder whose string is not in the file (the old code dropped it silently)
 *
 * Every file is built from the PE/COFF specification by pe_builder.h or by cs_build() below; none of them
 * uses a structure of the loader's.
 */
#include "loader/pe_loader.h"
#include "pe_builder.h"
#include "pe_check.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define MINI_IB UINT64_C(0x10000000)
#define INVALID ((cbae_off_t)CBAE_ADDR_INVALID)
#define FIX(type, off) ((uint16_t)(((type) << 12) | (off)))
#define CS_RO   (PB_SCN_INIT_DATA | PB_SCN_READ)
#define CS_CODE (PB_SCN_CODE | PB_SCN_EXEC | PB_SCN_READ)

/* ---- loading and looking at notes ---- */

static void dump_notes(const cbae_binary_image_t *img) {
    const uint32_t kept = img->note_count < CBAE_IMAGE_NOTES_MAX ? img->note_count : CBAE_IMAGE_NOTES_MAX;
    fprintf(stderr, "  the image has %u notes:\n", img->note_count);
    for (uint32_t i = 0; i < kept; i++) fprintf(stderr, "    [%u] %s\n", i, img->notes[i]);
}

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

/* The image has exactly @p n notes, and note i contains want[i]. */
static void expect_notes(const cbae_binary_image_t *img, const char *const *want, uint32_t n) {
    bool ok = img->note_count == n;
    for (uint32_t i = 0; ok && i < n; i++) ok = strstr(img->notes[i], want[i]) != NULL;
    if (!ok) {
        dump_notes(img);
        fprintf(stderr, "  expected %u notes, each containing, in order:\n", n);
        for (uint32_t i = 0; i < n; i++) fprintf(stderr, "    [%u] %s\n", i, want[i]);
    }
    assert(ok);
}
#define EXPECT_NOTES(img, ...) do { const char *w_[] = { __VA_ARGS__ }; expect_notes((img), w_, (uint32_t)(sizeof w_ / sizeof w_[0])); } while (0)
#define EXPECT_NO_NOTES(img)   do { if ((img)->note_count) dump_notes(img); assert((img)->note_count == 0); } while (0)

/* ---- a builder with free sections: the headers of a driver, then sections exactly as the caller says ---- */

typedef struct { const char *name; uint32_t vsize, rva, raw, ptr, chars; } cs_sec_t;
typedef struct { uint8_t *b; size_t n; uint32_t opt; } cs_file_t;

static cs_file_t cs_build(size_t file_size, uint32_t opt_size, const cs_sec_t *sec, int nsec) {
    assert(nsec >= 0 && nsec <= 8 && file_size >= PB_HEADERS_SIZE);
    if (!opt_size) opt_size = PB_OPT_PE32P_SIZE;
    const uint32_t coff = PB_E_LFANEW_DEFAULT + 4;
    cs_file_t f = { (uint8_t *)calloc(1, file_size), file_size, coff + PB_COFF_SIZE };
    assert(f.b);
    uint8_t *b = f.b;
    pb_w16(b, 0, 0x5A4D);
    pb_w32(b, PB_DOS_E_LFANEW, PB_E_LFANEW_DEFAULT);
    memcpy(b + PB_E_LFANEW_DEFAULT, "PE\0\0", 4);
    pb_w16(b, coff + PB_COFF_MACHINE, PB_MACHINE_AMD64);
    pb_w16(b, coff + PB_COFF_NSECTIONS, (uint16_t)nsec);
    pb_w16(b, coff + PB_COFF_OPTSIZE, (uint16_t)opt_size);
    pb_w16(b, f.opt + PB_OPT_MAGIC, PB_MAGIC_PE32P);
    pb_w64(b, f.opt + PB_OPT_IMAGE_BASE, MINI_IB);
    pb_w32(b, f.opt + PB_OPT_SECT_ALIGN, PB_SECT_ALIGN);
    pb_w32(b, f.opt + PB_OPT_FILE_ALIGN, PB_FILE_ALIGN);
    pb_w32(b, f.opt + PB_OPT_SIZE_OF_HDRS, PB_HEADERS_SIZE);
    pb_w16(b, f.opt + PB_OPT_SUBSYSTEM, 1);
    pb_w32(b, f.opt + PB_OPT_NUM_DIRS, 16);
    const uint32_t tab = f.opt + opt_size;
    assert(tab + (uint32_t)nsec * PB_SEC_HDR_SIZE <= PB_HEADERS_SIZE);
    for (int i = 0; i < nsec; i++) {
        const uint32_t h = tab + (uint32_t)i * PB_SEC_HDR_SIZE;
        memcpy(b + h + PB_SEC_NAME, sec[i].name, strlen(sec[i].name));
        pb_w32(b, h + PB_SEC_VSIZE, sec[i].vsize);
        pb_w32(b, h + PB_SEC_RVA, sec[i].rva);
        pb_w32(b, h + PB_SEC_RAWSIZE, sec[i].raw);
        pb_w32(b, h + PB_SEC_RAWPTR, sec[i].ptr);
        pb_w32(b, h + PB_SEC_CHARS, sec[i].chars);
    }
    return f;
}

static void cs_dir(cs_file_t *f, int idx, uint32_t rva, uint32_t size) {
    pb_w32(f->b, f->opt + PB_OPT_DIRS + (uint32_t)idx * 8, rva);
    pb_w32(f->b, f->opt + PB_OPT_DIRS + (uint32_t)idx * 8 + 4, size);
}

/* a string of @p len characters (not counting the NUL), recognisable: a, b, c ... */
static void fill_name(char *dst, size_t len, char first) {
    for (size_t i = 0; i < len; i++) dst[i] = (char)(first + (char)(i % 26));
    dst[len] = '\0';
}

/* ================================================================================================
 * Sections: where one ends and the next begins
 * ============================================================================================== */

static void test_adjacent_sections(void) {
    /* .a is code at [0x1000, 0x1100), .b is data at [0x1100, 0x1200): the first byte of .b is not .a's */
    const cs_sec_t sec[2] = {
        { ".a", 0x100, 0x1000, 0x100, 0x400, CS_CODE },
        { ".b", 0x100, 0x1100, 0x100, 0x500, CS_RO },
    };

    /* an import directory in .a whose DLL name is the very first byte of .b */
    cs_file_t f = cs_build(0x600, 0, sec, 2);
    pb_w32(f.b, 0x400 + 0, 0x1030);
    pb_w32(f.b, 0x400 + 12, 0x1100);
    pb_w32(f.b, 0x400 + 16, 0x1030);
    pb_w64(f.b, 0x430, 0x1110);
    memcpy(f.b + 0x500, "adj.dll", 8);
    pb_w16(f.b, 0x510, 0x1234);
    memcpy(f.b + 0x512, "Fn", 3);
    cs_dir(&f, PB_DIR_IMPORT, 0x1000, 40);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->import_count == 1);
    assert(strcmp(img->imports[0].module, "adj.dll") == 0 && strcmp(img->imports[0].name, "Fn") == 0 && img->imports[0].hint == 0x1234);
    assert(img->imports[0].iat_va == MINI_IB + 0x1030);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(f.b);

    /* export targets on both sides of every edge: kind comes from the section that owns the address */
    f = cs_build(0x600, 0, sec, 2);
    pb_w32(f.b, 0x580 + 16, 1);                                   /* ordinal base */
    pb_w32(f.b, 0x580 + 20, 5);                                   /* five functions, no names */
    pb_w32(f.b, 0x580 + 28, 0x11A8);
    const uint32_t target[5] = { 0x10FF, 0x1100, 0x11FF, 0x1200, 0x0FFF };
    const cbae_sym_kind_t kind[5] = { CBAE_KIND_FUNCTION, CBAE_KIND_OBJECT, CBAE_KIND_OBJECT, CBAE_KIND_NOTYPE, CBAE_KIND_NOTYPE };
    for (int i = 0; i < 5; i++) pb_w32(f.b, 0x5A8 + 4 * (size_t)i, target[i]);
    cs_dir(&f, PB_DIR_EXPORT, 0x1180, 40);
    img = load_ok(f.b, f.n);
    assert(img->symbol_count == 5);
    for (int i = 0; i < 5; i++) {
        char want[16];
        snprintf(want, sizeof want, "ord#%d", i + 1);
        assert(strcmp(img->symbols[i].name, want) == 0);
        assert(img->symbols[i].address == MINI_IB + target[i]);
        assert(img->symbols[i].kind == kind[i]);                  /* 0x1100 is .b's, 0x1200 is nobody's */
    }
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);

    /* the entry point has the same edges: .a's last byte is code, .b's first byte is data, 0x1200 is nothing */
    pb_w32(f.b, f.opt + PB_OPT_ENTRY_RVA, 0x10FF);
    img = load_ok(f.b, f.n);
    assert(img->entry_point == MINI_IB + 0x10FF && !has_note(img, "entry point"));
    cbae_image_destroy(&img);
    pb_w32(f.b, f.opt + PB_OPT_ENTRY_RVA, 0x1100);
    img = load_ok(f.b, f.n);
    assert(has_note(img, "the entry point (RVA 0x1100) is not in an executable section"));
    cbae_image_destroy(&img);
    pb_w32(f.b, f.opt + PB_OPT_ENTRY_RVA, 0x1200);
    img = load_ok(f.b, f.n);
    assert(has_note(img, "the entry point (RVA 0x1200) is not in an executable section"));
    cbae_image_destroy(&img);
    free(f.b);
    PASS("adjacent sections: the first byte of the next section is the next section's; kind and entry point agree at every edge");
}

static void test_header_span_edges(void) {
    /* SizeOfHeaders is 0x400: RVAs below it are file bytes, 0x400 itself is nothing (the section starts at 0x1000) */
    pb_mini_t m = pb_mini(0x200);
    uint8_t *s = m.b + m.sec_off;
    pb_w32(s, 0, 0x0000);  pb_w32(s, 4, 16);                       /* block 1: page 0 */
    pb_w16(s, 8,  FIX(PB_REL_DIR64, 0x3FF));
    pb_w16(s, 10, FIX(PB_REL_DIR64, 0x400));
    pb_w16(s, 12, FIX(PB_REL_ABSOLUTE, 0x3FE));
    pb_w16(s, 14, FIX(PB_REL_ABSOLUTE, 0x3FD));
    pb_w32(s, 16, 0x1000); pb_w32(s, 20, 16);                      /* block 2: the section's own first and last bytes */
    pb_w16(s, 24, FIX(PB_REL_DIR64, 0x000));
    pb_w16(s, 26, FIX(PB_REL_DIR64, 0x1FF));
    pb_w16(s, 28, FIX(PB_REL_DIR64, 0x200));                       /* one past the section */
    pb_w16(s, 30, FIX(PB_REL_ABSOLUTE, 0));
    pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, 32);
    cbae_binary_image_t *img = load_ok(m.b, m.n);
    const uint32_t rva[8] = { 0x3FF, 0x400, 0x3FE, 0x3FD, 0x1000, 0x11FF, 0x1200, 0x1000 };
    const cbae_off_t off[8] = { 0x3FF, INVALID, 0x3FE, 0x3FD, 0x400, 0x5FF, INVALID, 0x400 };
    assert(img->reloc_count == 8);
    for (int i = 0; i < 8; i++) {
        assert(img->relocations[i].target_va == MINI_IB + rva[i]);
        assert(img->relocations[i].file_offset == off[i]);
    }
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* a lookup table that starts in the headers and would run on into the section if the headers' span did
     * not end at SizeOfHeaders: one entry fits below 0x400, the next 8 bytes belong to the section */
    m = pb_mini(0x200);
    s = m.b + m.sec_off;
    pb_w32(s, 0, 0x3F8); pb_w32(s, 12, m.sec_rva + 0x40); pb_w32(s, 16, 0x3F8);
    memcpy(s + 0x40, "edge.dll", 9);
    pb_w64(m.b, 0x3F8, m.sec_rva + 0x60);
    pb_w16(s, 0x60, 7); memcpy(s + 0x62, "HdrFn", 6);
    pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, 40);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && strcmp(img->imports[0].module, "edge.dll") == 0 && strcmp(img->imports[0].name, "HdrFn") == 0);
    EXPECT_NOTES(img, "the import lookup table of edge.dll has no terminating zero entry inside the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("the headers end at SizeOfHeaders: a relocation there is a file byte, the next RVA is nothing, a table does not run on into a section");
}

static void test_section_flags(void) {
    static const struct { uint32_t chars, flags; } T[7] = {
        { PB_SCN_EXEC,        CBAE_SEC_EXEC },
        { PB_SCN_READ,        CBAE_SEC_READ },
        { PB_SCN_WRITE,       CBAE_SEC_WRITE },
        { PB_SCN_INIT_DATA,   CBAE_SEC_INIT },
        { PB_SCN_UNINIT_DATA, CBAE_SEC_BSS },
        { PB_SCN_CODE | PB_SCN_DISCARDABLE | 0x00100000u, 0 },     /* bits that mean something else map to nothing */
        { PB_SCN_EXEC | PB_SCN_READ | PB_SCN_WRITE | PB_SCN_INIT_DATA | PB_SCN_UNINIT_DATA,
          CBAE_SEC_EXEC | CBAE_SEC_READ | CBAE_SEC_WRITE | CBAE_SEC_INIT | CBAE_SEC_BSS },
    };
    cs_sec_t sec[7];
    static const char *const names[7] = { "s0", "s1", "s2", "s3", "s4", "s5", "s6" };
    for (uint32_t i = 0; i < 7; i++) sec[i] = (cs_sec_t){ names[i], 0x10, 0x1000 * (i + 1), 0, 0, T[i].chars };
    cs_file_t f = cs_build(PB_HEADERS_SIZE, 0, sec, 7);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    assert(img->section_count == 7);
    for (uint32_t i = 0; i < 7; i++) assert(img->sections[i].flags == T[i].flags);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(f.b);
    PASS("section characteristics: each of the five maps to its own flag and to nothing else");
}

static void test_section_extents(void) {
    cbae_binary_image_t *img;
    cs_file_t f;

    /* the file ends 0x100 bytes into 0x200 raw bytes, but the section's memory is only 0x100: the missing bytes
     * are padding, not data, so nothing is said */
    cs_sec_t pad = { ".rdata", 0x100, 0x1000, 0x200, 0x400, CS_RO };
    f = cs_build(0x500, 0, &pad, 1);
    img = load_ok(f.b, f.n);
    assert(img->sections[0].file_size == 0x100 && img->sections[0].virt_size == 0x100);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(f.b);

    /* the same cut with 0x300 bytes of memory: now real data is missing, and the note says how much is there */
    pad.vsize = 0x300;
    f = cs_build(0x500, 0, &pad, 1);
    img = load_ok(f.b, f.n);
    assert(img->sections[0].file_size == 0x100 && img->sections[0].virt_size == 0x300);
    EXPECT_NOTES(img, "section .rdata: raw data (0x200 bytes at file offset 0x400) runs past the end of the file; 256 bytes are present");
    cbae_image_destroy(&img);
    free(f.b);

    /* raw data that ends exactly at the end of the file is all there */
    f = cs_build(0x600, 0, &pad, 1);
    img = load_ok(f.b, f.n);
    assert(img->sections[0].file_size == 0x200);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(f.b);
    PASS("a raw size past the end of the file is noted only when bytes of the section are missing, not when only padding is");
}

static void overlap_case(const cs_sec_t *sec, int nsec, bool overlaps) {
    cs_file_t f = cs_build(PB_HEADERS_SIZE, 0, sec, nsec);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    if (overlaps) EXPECT_NOTES(img, "overlap in memory");
    else EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(f.b);
}

static void test_section_overlap(void) {
    /* sizes in memory only (no raw data): the question is about addresses */
    const cs_sec_t touch_up[2]   = { { ".a", 0x1000, 0x1000, 0, 0, CS_RO }, { ".b", 0x1000, 0x2000, 0, 0, CS_RO } };
    const cs_sec_t touch_down[2] = { { ".a", 0x1000, 0x2000, 0, 0, CS_RO }, { ".b", 0x1000, 0x1000, 0, 0, CS_RO } };
    const cs_sec_t over_up[2]    = { { ".a", 0x1001, 0x1000, 0, 0, CS_RO }, { ".b", 0x1000, 0x2000, 0, 0, CS_RO } };
    const cs_sec_t over_down[2]  = { { ".a", 0x1000, 0x2000, 0, 0, CS_RO }, { ".b", 0x1001, 0x1000, 0, 0, CS_RO } };
    const cs_sec_t nested[2]     = { { ".a", 0x3000, 0x1000, 0, 0, CS_RO }, { ".b", 0x0100, 0x2000, 0, 0, CS_RO } };
    const cs_sec_t empty_in[2]   = { { ".a", 0x1000, 0x1000, 0, 0, CS_RO }, { ".b", 0,      0x1800, 0, 0, CS_RO } };
    const cs_sec_t same[2]       = { { ".a", 0x1000, 0x1000, 0, 0, CS_RO }, { ".b", 0x1000, 0x1000, 0, 0, CS_RO } };
    overlap_case(touch_up, 2, false);                              /* [0x1000, 0x2000) and [0x2000, 0x3000) touch: they do not overlap */
    overlap_case(touch_down, 2, false);                            /* the same, the higher one first in the table */
    overlap_case(over_up, 2, true);                                /* one byte shared */
    overlap_case(over_down, 2, true);
    overlap_case(nested, 2, true);
    overlap_case(empty_in, 2, false);                              /* a section of no size is nowhere, so it overlaps nothing */
    overlap_case(same, 2, true);

    /* three that all overlap each other are one note, naming the first pair */
    const cs_sec_t three[3] = { { ".a", 0x3000, 0x1000, 0, 0, CS_RO }, { ".b", 0x3000, 0x2000, 0, 0, CS_RO }, { ".c", 0x3000, 0x3000, 0, 0, CS_RO } };
    cs_file_t f = cs_build(PB_HEADERS_SIZE, 0, three, 3);
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    EXPECT_NOTES(img, "sections .a and .b overlap in memory");
    cbae_image_destroy(&img);
    free(f.b);
    PASS("section overlap: touching is not overlapping, one shared byte is, an empty section overlaps nothing, one note however many pairs");
}

/* ================================================================================================
 * The headers: the smallest and the largest sizes at each limit
 * ============================================================================================== */

static void tiny_header(uint8_t *t, size_t n, uint16_t optsz, uint16_t magic) {
    memset(t, 0, n);
    pb_w16(t, 0, 0x5A4D);
    pb_w32(t, PB_DOS_E_LFANEW, 0x40);
    memcpy(t + 0x40, "PE\0\0", 4);
    pb_w16(t, 0x44 + PB_COFF_MACHINE, PB_MACHINE_AMD64);
    pb_w16(t, 0x44 + PB_COFF_OPTSIZE, optsz);
    pb_w16(t, 0x58, magic);
}

static void test_header_limits(void) {
    cs_file_t f = cs_build(0x600, 0, &(cs_sec_t){ ".rdata", 0x100, 0x1000, 0x100, 0x400, CS_RO }, 1);

    /* the signature is two letters, and both count */
    f.b[1] = 'X';
    assert(load_err(f.b, f.n) == CBAE_ERR_PARSE);
    f.b[1] = 'Z'; f.b[0] = 'X';
    assert(load_err(f.b, f.n) == CBAE_ERR_PARSE);
    f.b[0] = 'M';
    cbae_binary_image_t *img = load_ok(f.b, f.n);
    cbae_image_destroy(&img);
    free(f.b);

    /* "PE\0\0", the COFF header and the two bytes of the optional header's magic are the least a file may hold:
     * with exactly that much the magic is read (here it says PE32, which is refused as unsupported), with one
     * byte less the header runs past the end */
    uint8_t t[0x80];
    tiny_header(t, sizeof t, 2, PB_MAGIC_PE32);
    assert(load_err(t, 0x5A) == CBAE_ERR_UNSUPPORTED);
    assert(load_err(t, 0x59) == CBAE_ERR_PARSE);

    /* an optional header of 1 byte, or none, cannot hold a magic, whatever the bytes after it say */
    tiny_header(t, sizeof t, 1, PB_MAGIC_PE32);
    assert(load_err(t, sizeof t) == CBAE_ERR_PARSE);
    tiny_header(t, sizeof t, 0, PB_MAGIC_PE32);
    assert(load_err(t, sizeof t) == CBAE_ERR_PARSE);

    /* the smallest PE32+ there is: the 112-byte optional header, no data directories, no sections, and the file
     * ends with the optional header. A loader that wants one more byte refuses it. */
    uint8_t z[0x58 + 112];
    tiny_header(z, sizeof z, 112, PB_MAGIC_PE32P);
    pb_w64(z, 0x58 + PB_OPT_IMAGE_BASE, MINI_IB);
    img = load_ok(z, sizeof z);
    assert(img->section_count == 0 && img->symbol_count == 0 && img->import_count == 0 && img->reloc_count == 0);
    assert(img->arch == CBAE_ARCH_X86_64 && img->load_base == MINI_IB && img->entry_point == CBAE_ADDR_INVALID);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    assert(load_err(z, sizeof z - 1) == CBAE_ERR_PARSE);

    /* an optional header that has room for two data directories and 4 bytes of a third: the 4 bytes are not a
     * directory, so a file that declares three is told it has room for two */
    cs_file_t g = cs_build(0x600, 112 + 16 + 4, &(cs_sec_t){ ".rdata", 0x100, 0x1000, 0x100, 0x400, CS_RO }, 1);
    pb_w32(g.b, g.opt + PB_OPT_NUM_DIRS, 3);
    img = load_ok(g.b, g.n);
    EXPECT_NOTES(img, "NumberOfRvaAndSizes is 3 but the optional header has room for 2");
    cbae_image_destroy(&img);
    pb_w32(g.b, g.opt + PB_OPT_NUM_DIRS, 2);
    img = load_ok(g.b, g.n);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(g.b);
    PASS("headers: both letters of MZ, the smallest accepted file, a 1-byte optional header, a partial directory entry is not an entry");
}

/* ================================================================================================
 * Imports
 * ============================================================================================== */

/* One DLL, one import, in a section of @p raw bytes: descriptor at 0, its terminator at 20, lookup table at 0x30
 * (the entry, then the zero), DLL name at 0x50, hint and name at 0x100. */
static pb_mini_t one_import(uint32_t raw, const char *dll, uint16_t hint, const char *fn) {
    pb_mini_t m = pb_mini(raw);
    uint8_t *s = m.b + m.sec_off;
    pb_w32(s, 0, m.sec_rva + 0x30);
    pb_w32(s, 12, m.sec_rva + 0x50);
    pb_w32(s, 16, m.sec_rva + 0x30);
    pb_w64(s, 0x30, m.sec_rva + 0x100);
    memcpy(s + 0x50, dll, strlen(dll) + 1);
    pb_w16(s, 0x100, hint);
    memcpy(s + 0x102, fn, strlen(fn) + 1);
    pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, 40);
    return m;
}

static void test_no_directory_means_nothing(void) {
    /* The first 40 bytes of a file are a DOS header. With no import, export, relocation or debug directory, a
     * loader that read the table at RVA 0 anyway would take them for one. Fill them with bytes that make a
     * plausible descriptor and a plausible export directory. */
    pb_mini_t m = pb_mini(0x100);
    for (size_t i = 0x0C; i < 0x28; i++) m.b[i] = 0x01;
    cbae_binary_image_t *img = load_ok(m.b, m.n);
    assert(img->import_count == 0 && img->symbol_count == 0 && img->reloc_count == 0 && img->meta.pe.pdb_path[0] == '\0');
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("no data directory, no table: bytes at RVA 0 are not read as one");
}

static void test_import_tail_edges(void) {
    const uint32_t R = 0x200;
    cbae_binary_image_t *img;
    pb_mini_t m;
    uint8_t *s;

    /* the only descriptor is the last 20 bytes of the section: it is read, and the missing terminator is noted */
    m = pb_mini(R);
    s = m.b + m.sec_off;
    pb_w32(s, R - 20 + 0, m.sec_rva + 0x20);
    pb_w32(s, R - 20 + 12, m.sec_rva + 0x40);
    pb_w32(s, R - 20 + 16, m.sec_rva + 0x20);
    pb_w64(s, 0x20, m.sec_rva + 0x60);
    memcpy(s + 0x40, "t.dll", 6);
    pb_w16(s, 0x60, 0x42); memcpy(s + 0x62, "Fn", 3);
    pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva + R - 20, 20);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1);
    assert(strcmp(img->imports[0].module, "t.dll") == 0 && strcmp(img->imports[0].name, "Fn") == 0 && img->imports[0].hint == 0x42);
    assert(img->imports[0].iat_va == MINI_IB + m.sec_rva + 0x20);
    EXPECT_NOTES(img, "the import directory has no terminating descriptor inside the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* a lookup table that is the last 8 bytes of the section: one entry, read, and no terminator */
    m = pb_mini(R);
    s = m.b + m.sec_off;
    pb_w32(s, 0, m.sec_rva + R - 8); pb_w32(s, 12, m.sec_rva + 0x40); pb_w32(s, 16, m.sec_rva + R - 8);
    memcpy(s + 0x40, "t.dll", 6);
    pb_w64(s, R - 8, m.sec_rva + 0x60);
    pb_w16(s, 0x60, 1); memcpy(s + 0x62, "Fn", 3);
    pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, 40);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && strcmp(img->imports[0].name, "Fn") == 0);
    EXPECT_NOTES(img, "the import lookup table of t.dll has no terminating zero entry inside the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* the last 16 bytes: both entries are read */
    m = pb_mini(R);
    s = m.b + m.sec_off;
    pb_w32(s, 0, m.sec_rva + R - 16); pb_w32(s, 12, m.sec_rva + 0x40); pb_w32(s, 16, m.sec_rva + R - 16);
    memcpy(s + 0x40, "t.dll", 6);
    pb_w64(s, R - 16, m.sec_rva + 0x60);
    pb_w64(s, R - 8, m.sec_rva + 0x70);
    pb_w16(s, 0x60, 1); memcpy(s + 0x62, "Fn", 3);
    pb_w16(s, 0x70, 2); memcpy(s + 0x72, "Gn", 3);
    pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, 40);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 2 && strcmp(img->imports[0].name, "Fn") == 0 && strcmp(img->imports[1].name, "Gn") == 0);
    assert(img->imports[1].iat_va == MINI_IB + m.sec_rva + R - 16 + 8);
    EXPECT_NOTES(img, "has no terminating zero entry inside the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* a hint and nothing after it: the last 2 bytes of the section are a complete hint/name entry with an empty name */
    m = pb_mini(R);
    s = m.b + m.sec_off;
    pb_w32(s, 0, m.sec_rva + 0x20); pb_w32(s, 12, m.sec_rva + 0x40); pb_w32(s, 16, m.sec_rva + 0x20);
    pb_w64(s, 0x20, m.sec_rva + R - 2);
    memcpy(s + 0x40, "t.dll", 6);
    pb_w16(s, R - 2, 0x4455);
    pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, 40);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && img->imports[0].state == CBAE_IMPORT_BY_NAME && img->imports[0].hint == 0x4455 && img->imports[0].name[0] == '\0');
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    /* and with the entry one byte later there is no room for a hint: the entry is not in the file */
    pb_w64(s, 0x20, m.sec_rva + R - 1);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && img->imports[0].state != CBAE_IMPORT_BY_NAME);
    assert(has_note(img, "an import name entry (RVA 0x11ff, from t.dll) is not in the file"));
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("import tables ending exactly at the end of their section: read in full, the missing terminator noted, nothing more");
}

static void test_import_entry_forms(void) {
    cbae_binary_image_t *img;
    pb_mini_t m = one_import(0x400, "t.dll", 9, "Fn");

    /* bit 31 of a by-name entry is not part of the RVA */
    pb_w64(m.b + m.sec_off, 0x30, UINT64_C(0x80000000) | (m.sec_rva + 0x100));
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && strcmp(img->imports[0].name, "Fn") == 0 && img->imports[0].hint == 9);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* an import name of 127 characters fits its field; of 128 it is cut, and said so */
    char name[200];
    fill_name(name, 127, 'a');
    m = one_import(0x400, "t.dll", 1, name);
    img = load_ok(m.b, m.n);
    assert(strlen(img->imports[0].name) == 127 && strcmp(img->imports[0].name, name) == 0);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    fill_name(name, 128, 'a');
    m = one_import(0x400, "t.dll", 1, name);
    img = load_ok(m.b, m.n);
    assert(strlen(img->imports[0].name) == 127 && strncmp(img->imports[0].name, name, 127) == 0);
    EXPECT_NOTES(img, "an import name from t.dll is longer than 127 bytes and was cut");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* a DLL name of 63 characters fits; of 64 it is cut */
    fill_name(name, 63, 'A');
    m = one_import(0x400, name, 1, "Fn");
    img = load_ok(m.b, m.n);
    assert(strlen(img->imports[0].module) == 63 && strcmp(img->imports[0].module, name) == 0);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    fill_name(name, 64, 'A');
    m = one_import(0x400, name, 1, "Fn");
    img = load_ok(m.b, m.n);
    assert(strlen(img->imports[0].module) == 63 && strncmp(img->imports[0].module, name, 63) == 0);
    EXPECT_NOTES(img, "import descriptor 0: the DLL name is longer than 63 bytes and was cut");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* a DLL name that is not in the file: said so, and the imports are still listed, with no module */
    m = one_import(0x400, "t.dll", 1, "Fn");
    pb_w32(m.b + m.sec_off, 12, 0x5000);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 1 && img->imports[0].module[0] == '\0' && strcmp(img->imports[0].name, "Fn") == 0);
    EXPECT_NOTES(img, "import descriptor 0: the DLL name (RVA 0x5000) is not in the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* a lookup table that is not in the file: said so (and its module is named in the note) */
    m = one_import(0x400, "t.dll", 1, "Fn");
    pb_w32(m.b + m.sec_off, 0, 0x6000);
    pb_w32(m.b + m.sec_off, 16, 0x6000);
    img = load_ok(m.b, m.n);
    assert(img->import_count == 0);
    EXPECT_NOTES(img, "import descriptor 0 (t.dll): the lookup table (RVA 0x6000) is not in the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("import entries: bit 31 of a name RVA, names one character under and over their fields, DLL name and table not in the file");
}

/* ================================================================================================
 * Exports
 * ============================================================================================== */

static void test_export_tail_edges(void) {
    cbae_binary_image_t *img;

    /* an export directory that is the last 40 bytes of its section is a whole directory */
    const uint32_t R = 0x200;
    pb_mini_t m = pb_mini(R);
    uint8_t *s = m.b + m.sec_off;
    const uint32_t d = R - 40;
    pb_w32(s, d + 16, 1);                                         /* base */
    pb_w32(s, d + 20, 1);                                         /* one function, no name */
    pb_w32(s, d + 28, m.sec_rva + 0x40);                          /* the address table */
    pb_w32(s, 0x40, m.sec_rva + 0x10);
    pb_mini_dir(&m, PB_DIR_EXPORT, m.sec_rva + d, 40);
    img = load_ok(m.b, m.n);
    assert(img->symbol_count == 1 && strcmp(img->symbols[0].name, "ord#1") == 0 && img->symbols[0].address == MINI_IB + m.sec_rva + 0x10);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* three tables that each end exactly at the end of their section: nothing is missing, so nothing is said.
     * Then the same file declaring more entries than there are: each table says how many it holds. */
    const cs_sec_t sec[3] = {
        { ".a", 0x200, 0x1000, 0x200, 0x400, CS_RO },
        { ".b", 0x100, 0x2000, 0x100, 0x600, CS_RO },
        { ".c", 0x100, 0x3000, 0x100, 0x700, CS_RO },
    };
    cs_file_t f = cs_build(0x800, 0, sec, 3);
    uint8_t *b = f.b;
    pb_w32(b, 0x400 + 16, 1);
    pb_w32(b, 0x400 + 20, 4);                                     /* functions */
    pb_w32(b, 0x400 + 24, 3);                                     /* names */
    pb_w32(b, 0x400 + 28, 0x11F0);                                /* address table: the last 16 bytes of .a */
    pb_w32(b, 0x400 + 32, 0x20F4);                                /* name pointers: the last 12 bytes of .b */
    pb_w32(b, 0x400 + 36, 0x30FA);                                /* ordinals: the last 6 bytes of .c */
    memcpy(b + 0x400 + 0x80, "Alpha", 6); memcpy(b + 0x400 + 0x90, "Beta", 5); memcpy(b + 0x400 + 0xA0, "Gamma", 6);
    for (uint32_t i = 0; i < 4; i++) pb_w32(b, 0x400 + 0x1F0 + 4 * i, 0x1100 + 0x10 * i);
    pb_w32(b, 0x600 + 0xF4, 0x1080); pb_w32(b, 0x600 + 0xF8, 0x1090); pb_w32(b, 0x600 + 0xFC, 0x10A0);
    pb_w16(b, 0x700 + 0xFA, 0); pb_w16(b, 0x700 + 0xFC, 1); pb_w16(b, 0x700 + 0xFE, 2);
    cs_dir(&f, PB_DIR_EXPORT, 0x1000, 40);
    img = load_ok(f.b, f.n);
    assert(img->symbol_count == 4);
    assert(strcmp(img->symbols[0].name, "Alpha") == 0 && img->symbols[0].address == MINI_IB + 0x1100);
    assert(strcmp(img->symbols[1].name, "Beta") == 0 && img->symbols[1].address == MINI_IB + 0x1110);
    assert(strcmp(img->symbols[2].name, "Gamma") == 0 && img->symbols[2].address == MINI_IB + 0x1120);
    assert(strcmp(img->symbols[3].name, "ord#4") == 0 && img->symbols[3].address == MINI_IB + 0x1130);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);

    pb_w32(b, 0x400 + 20, 10);                                    /* ten functions declared, four there */
    pb_w32(b, 0x400 + 24, 5);                                     /* five names declared, three there */
    img = load_ok(f.b, f.n);
    assert(img->symbol_count == 4);
    EXPECT_NOTES(img, "the export address table (10 entries) runs past the end of the file: 4 are present",
                      "the export name tables (5 entries) run past the end of the file: 3 are present");
    cbae_image_destroy(&img);
    free(f.b);
    PASS("export tables ending exactly at the end of their section: all read, nothing said; declared past the end: each says how many are there");
}

static void test_export_names_and_forwarders(void) {
    cbae_binary_image_t *img;
    char name[200];

    /* an export name of 127 characters fits; of 128 it is cut and said so */
    for (int len = 127; len <= 128; len++) {
        pb_mini_t m = pb_mini(0x400);
        uint8_t *s = m.b + m.sec_off;
        pb_w32(s, 16, 1); pb_w32(s, 20, 1); pb_w32(s, 24, 1);
        pb_w32(s, 28, m.sec_rva + 0x40); pb_w32(s, 32, m.sec_rva + 0x48); pb_w32(s, 36, m.sec_rva + 0x4C);
        pb_w32(s, 0x40, m.sec_rva + 0x200);                       /* the function: in the section, outside the directory */
        pb_w32(s, 0x48, m.sec_rva + 0x100);
        pb_w16(s, 0x4C, 0);
        fill_name(name, (size_t)len, 'a');
        memcpy(s + 0x100, name, (size_t)len + 1);
        pb_mini_dir(&m, PB_DIR_EXPORT, m.sec_rva, 40);
        img = load_ok(m.b, m.n);
        assert(img->symbol_count == 1 && strlen(img->symbols[0].name) == 127 && strncmp(img->symbols[0].name, name, 127) == 0);
        if (len == 127) EXPECT_NO_NOTES(img);
        else EXPECT_NOTES(img, "has a name longer than 127 bytes and was cut");
        cbae_image_destroy(&img);
        pb_mini_free(&m);
    }

    /* forwarder strings of 20, 56 and 100 characters: the source keeps 56 of them */
    pb_mini_t m = pb_mini(0x400);
    uint8_t *s = m.b + m.sec_off;
    pb_w32(s, 16, 1); pb_w32(s, 20, 3); pb_w32(s, 28, m.sec_rva + 0x40);
    const size_t len[3] = { 20, 56, 100 };
    const uint32_t at[3] = { 0x100, 0x140, 0x180 };
    char fwd[3][128];
    for (int i = 0; i < 3; i++) {
        fill_name(fwd[i], len[i], 'a');
        memcpy(s + at[i], fwd[i], len[i] + 1);
        pb_w32(s, 0x40 + 4 * (size_t)i, m.sec_rva + at[i]);
    }
    pb_mini_dir(&m, PB_DIR_EXPORT, m.sec_rva, 0x200);             /* the forwarder strings are inside the directory */
    img = load_ok(m.b, m.n);
    assert(img->symbol_count == 3);
    for (int i = 0; i < 3; i++) {
        char want[80];
        snprintf(want, sizeof want, "fwd:%.56s", fwd[i]);
        assert(strcmp(img->symbols[i].source, want) == 0 && img->symbols[i].address == CBAE_ADDR_INVALID && img->symbols[i].kind == CBAE_KIND_FUNCTION);
    }
    assert(strlen(img->symbols[0].source) == 4 + 20 && strlen(img->symbols[1].source) == 4 + 56 && strlen(img->symbols[2].source) == 4 + 56);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* forwarders whose strings are not in the file: the export is kept with an empty forwarder, and the
     * loader says so once (the old loader said nothing). The third forwarder is in the file. */
    m = pb_mini(0x400);
    s = m.b + m.sec_off;
    pb_w32(s, 16, 1); pb_w32(s, 20, 3); pb_w32(s, 28, m.sec_rva + 0x40);
    pb_w32(s, 0x40, 0x1800); pb_w32(s, 0x44, 0x2800); pb_w32(s, 0x48, m.sec_rva + 0x100);
    memcpy(s + 0x100, "KERNEL32.Real", 14);
    pb_mini_dir(&m, PB_DIR_EXPORT, m.sec_rva, 0x2000);            /* [0x1000, 0x3000): 0x1800 and 0x2800 are inside, in no section */
    img = load_ok(m.b, m.n);
    assert(img->symbol_count == 3);
    assert(strcmp(img->symbols[0].name, "ord#1") == 0 && strcmp(img->symbols[0].source, "fwd:") == 0 && img->symbols[0].address == CBAE_ADDR_INVALID);
    assert(strcmp(img->symbols[1].name, "ord#2") == 0 && strcmp(img->symbols[1].source, "fwd:") == 0 && img->symbols[1].address == CBAE_ADDR_INVALID);
    assert(strcmp(img->symbols[2].name, "ord#3") == 0 && strcmp(img->symbols[2].source, "fwd:KERNEL32.Real") == 0);
    EXPECT_NOTES(img, "export ord#1: the forwarder string (RVA 0x1800) is not in the file");
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("export names and forwarders: 127/128 characters, the 56-character forwarder cut, a forwarder string that is not in the file is noted once");
}

/* ================================================================================================
 * Base relocations
 * ============================================================================================== */

static void test_reloc_rva_past_32_bits(void) {
    /* A block's page RVA plus a 12-bit offset can pass 4 GiB: 0xFFFFFFFF + 0x00F is 0x10000000E, not 0x0E. The
     * old loader added them in 32 bits, so the address was right (64 bits) but the file offset was looked up
     * with the wrapped RVA and landed in the headers. */
    pb_mini_t m = pb_mini(0x100);
    uint8_t *s = m.b + m.sec_off;
    pb_w32(s, 0, 0xFFFFFFFFu); pb_w32(s, 4, 12);
    pb_w16(s, 8, FIX(PB_REL_DIR64, 0x00F));
    pb_w16(s, 10, FIX(PB_REL_DIR64, 0x000));
    pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, 12);
    cbae_binary_image_t *img = load_ok(m.b, m.n);
    assert(img->reloc_count == 2);
    assert(img->relocations[0].target_va == MINI_IB + UINT64_C(0x10000000E) && img->relocations[0].file_offset == INVALID);
    assert(img->relocations[1].target_va == MINI_IB + UINT64_C(0xFFFFFFFF) && img->relocations[1].file_offset == INVALID);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* and the last RVA that still fits in 32 bits is looked up: 0xFFFFFFFF is the last byte of a section */
    const cs_sec_t sec[2] = {
        { ".reloc", 0x100, 0x1000,     0x100, 0x400, CS_RO },
        { ".hi",    0x200, 0xFFFFFE00, 0x200, 0x500, CS_RO },
    };
    cs_file_t f = cs_build(0x700, 0, sec, 2);
    pb_w32(f.b, 0x400, 0xFFFFF000u); pb_w32(f.b, 0x404, 16);
    pb_w16(f.b, 0x408, FIX(PB_REL_DIR64, 0xFFF));                 /* RVA 0xFFFFFFFF: the section's last byte */
    pb_w16(f.b, 0x40A, FIX(PB_REL_DIR64, 0xE00));                 /* RVA 0xFFFFFE00: its first */
    pb_w16(f.b, 0x40C, FIX(PB_REL_DIR64, 0x1FF));                 /* RVA 0xFFFFF1FF: in no section */
    pb_w16(f.b, 0x40E, FIX(PB_REL_ABSOLUTE, 0));
    cs_dir(&f, PB_DIR_BASERELOC, 0x1000, 16);
    img = load_ok(f.b, f.n);
    assert(img->reloc_count == 4);
    assert(img->relocations[0].target_va == MINI_IB + UINT64_C(0xFFFFFFFF) && img->relocations[0].file_offset == 0x6FF);
    assert(img->relocations[1].target_va == MINI_IB + UINT64_C(0xFFFFFE00) && img->relocations[1].file_offset == 0x500);
    assert(img->relocations[2].file_offset == INVALID);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    free(f.b);
    PASS("a relocation RVA past 4 GiB has no file offset (no wrap into the headers); the last RVA below it still has one");
}

static void test_reloc_block_edges(void) {
    cbae_binary_image_t *img;
    pb_mini_t m;
    uint8_t *s;

    /* a directory of 8 bytes is one block header: what it claims for its size decides */
    static const struct { uint32_t bsz; const char *note; } T[3] = {
        { 16, "a base relocation block at offset 0x0 declares 16 bytes but 8 remain: it is cut" },
        {  4, "a base relocation block at offset 0x0 has size 4 (less than its 8-byte header): the rest are ignored" },
        {  8, NULL },                                              /* a block of no entries: fine */
    };
    for (int i = 0; i < 3; i++) {
        m = pb_mini(0x100);
        s = m.b + m.sec_off;
        pb_w32(s, 0, 0x2000); pb_w32(s, 4, T[i].bsz);
        pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, 8);
        img = load_ok(m.b, m.n);
        assert(img->reloc_count == 0);
        if (T[i].note) EXPECT_NOTES(img, T[i].note); else EXPECT_NO_NOTES(img);
        cbae_image_destroy(&img);
        pb_mini_free(&m);
    }

    /* a block of 7 bytes cannot even hold its header: the table ends there (it is not 2^31 entries) */
    m = pb_mini(0x100);
    s = m.b + m.sec_off;
    pb_w32(s, 0, 0x2000); pb_w32(s, 4, 16);
    for (uint32_t e = 0; e < 4; e++) pb_w16(s, 8 + 2 * e, FIX(PB_REL_DIR64, e));
    pb_w32(s, 16, 0x3000); pb_w32(s, 20, 7);
    pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, 0x40);
    img = load_ok(m.b, m.n);
    assert(img->reloc_count == 4);
    EXPECT_NOTES(img, "a base relocation block at offset 0x10 has size 7 (less than its 8-byte header): the rest are ignored");
    cbae_image_destroy(&img);
    pb_mini_free(&m);

    /* an odd block size: 11 bytes is a header and one whole entry; the half entry after it is not one */
    m = pb_mini(0x100);
    s = m.b + m.sec_off;
    pb_w32(s, 0, 0x2000); pb_w32(s, 4, 11);
    pb_w16(s, 8, FIX(PB_REL_DIR64, 0x10)); pb_w16(s, 10, FIX(PB_REL_DIR64, 0x20));
    pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, 11);
    img = load_ok(m.b, m.n);
    assert(img->reloc_count == 1 && img->relocations[0].target_va == MINI_IB + 0x2010);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_mini_free(&m);
    PASS("relocation blocks: a lone 8-byte header (cut, short, empty), a 7-byte block ends the table, an odd size drops the half entry");
}

/* ================================================================================================
 * The debug directory
 * ============================================================================================== */

static pb_file_t build_debug(const pb_debug_t *d, int nd, pb_layout_t *L) {
    pb_spec_t sp = pb_spec_default();
    sp.ndebug = nd;
    for (int i = 0; i < nd; i++) sp.debug[i] = d[i];
    return pb_build(&sp, L);
}

static void test_debug_edges(void) {
    cbae_binary_image_t *img;
    pb_layout_t L;

    /* only a CodeView entry (type 2) names the PDB: a record of another type is not read, even if it looks like one */
    const pb_debug_t wrong_then_right[2] = { { 1, true, "C:\\wrong.pdb" }, { 2, true, "C:\\right.pdb" } };
    pb_file_t f = build_debug(wrong_then_right, 2, &L);
    img = load_ok(f.b, f.n);
    assert(strcmp(img->meta.pe.pdb_path, "C:\\right.pdb") == 0);
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_free(&f);
    const pb_debug_t only_wrong[1] = { { 1, true, "C:\\wrong.pdb" } };
    f = build_debug(only_wrong, 1, &L);
    img = load_ok(f.b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0');
    cbae_image_destroy(&img);
    pb_free(&f);

    /* a directory declared bigger than the file holds: said so, and the entries that are there are still read */
    pb_spec_t sp = pb_spec_default();
    f = pb_build(&sp, &L);
    pb_w32(f.b, L.dir_entry[PB_DIR_DEBUG] + 4, 0x10000);
    img = load_ok(f.b, f.n);
    assert(strcmp(img->meta.pe.pdb_path, "C:\\build\\mydrv.pdb") == 0);
    assert(has_note(img, "the debug directory (65536 bytes at RVA 0x"));
    cbae_image_destroy(&img);
    pb_free(&f);
    PASS("debug: only type 2 names the PDB, a directory declared too big is noted");
}

static void test_debug_record_edges(void) {
    cbae_binary_image_t *img;
    pb_layout_t L;
    pb_spec_t sp = pb_spec_default();
    pb_file_t f = pb_build(&sp, &L);
    const uint32_t e1 = pb_rva_to_off(&L, L.debug_rva) + PB_DEBUG_ENTRY_SIZE;     /* the CodeView entry */
    assert(pb_r32(f.b, e1 + 12) == 2);

    /* a record that starts at the end of the file is past it; one byte before the end is in the file, with too
     * few bytes to be a record (and nothing to say about that) */
    pb_w32(f.b, e1 + 24, (uint32_t)f.n);
    img = load_ok(f.b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0');
    char want[96];
    snprintf(want, sizeof want, "a CodeView debug record is at file offset 0x%x, past the end of the file", (unsigned)f.n);
    EXPECT_NOTES(img, want);
    cbae_image_destroy(&img);
    pb_w32(f.b, e1 + 24, (uint32_t)f.n - 1);
    img = load_ok(f.b, f.n);
    assert(img->meta.pe.pdb_path[0] == '\0');
    EXPECT_NO_NOTES(img);
    cbae_image_destroy(&img);
    pb_free(&f);

    /* a PDB path of 255 characters fills its field; 256 are cut, and said so */
    for (int len = 255; len <= 256; len++) {
        char path[300];
        fill_name(path, (size_t)len, 'a');
        const pb_debug_t d[1] = { { 2, true, path } };
        f = build_debug(d, 1, &L);
        img = load_ok(f.b, f.n);
        assert(strlen(img->meta.pe.pdb_path) == 255 && strncmp(img->meta.pe.pdb_path, path, 255) == 0);
        if (len == 255) EXPECT_NO_NOTES(img);
        else EXPECT_NOTES(img, "the PDB path is longer than 255 bytes and was cut");
        cbae_image_destroy(&img);
        pb_free(&f);
    }
    PASS("debug records: at the end of the file, one byte before it, a PDB path of 255 and of 256 characters");
}

/* ================================================================================================
 * The arena limit, to the byte
 * ============================================================================================== */

#if defined(__SANITIZE_THREAD__)
#define CBAE_HEAVY_OK 0
#else
#define CBAE_HEAVY_OK 1
#endif

static void test_arena_limit_exact(void) {
    if (getenv("CBAE_TEST_QUICK") || !CBAE_HEAVY_OK) { printf("  [SKIP] the arena limit to the byte (needs a 1 GiB table: not in quick mode, not under ThreadSanitizer)\n"); return; }
    /* The tables of an image take 16 + n * sizeof(element) bytes each (the 16 is slack for alignment); the limit
     * is 2^30 bytes in all. With three sections, no symbols and no imports:
     *   3 * 80 + 16  +  16  +  16  +  r * 48 + 16  =  2^30   for r = 22,369,615.
     * That image fits exactly and must load; one relocation more must be refused. */
    const uint32_t r = 22369615u;
    for (int over = 0; over <= 1; over++) {
        const uint32_t nrel = r + (uint32_t)over;
        const uint32_t bytes = 8 + 2 * nrel;
        const uint32_t hi = 0x1000 + ((bytes + 0xFFF) & ~0xFFFu);
        const cs_sec_t sec[3] = {
            { ".reloc", bytes, 0x1000, bytes, 0x400, CS_RO },
            { ".b",     0x10,  hi,          0, 0, CS_RO },
            { ".c",     0x10,  hi + 0x1000, 0, 0, CS_RO },
        };
        cs_file_t f = cs_build((size_t)0x400 + bytes, 0, sec, 3);
        pb_w32(f.b, 0x400, 0x2000); pb_w32(f.b, 0x404, bytes);
        for (uint32_t i = 0; i < nrel; i++) pb_w16(f.b, 0x408 + 2 * (size_t)i, FIX(PB_REL_DIR64, i & 0xFFF));
        cs_dir(&f, PB_DIR_BASERELOC, 0x1000, bytes);
        if (!over) {
            cbae_binary_image_t *img = load_ok(f.b, f.n);
            assert(img->reloc_count == nrel);
            assert(img->arena.capacity == (cbae_size_t)1 << 30);
            assert(img->relocations[nrel - 1].target_va == MINI_IB + 0x2000 + ((nrel - 1) & 0xFFF));
            EXPECT_NO_NOTES(img);
            cbae_image_destroy(&img);
        } else {
            assert(load_err(f.b, f.n) == CBAE_ERR_OVERFLOW);
        }
        free(f.b);
    }
    PASS("a table set of exactly 2^30 bytes loads; 48 bytes more is refused as too large");
}

int main(void) {
    printf("PE boundary tests\n");
    test_adjacent_sections();
    test_header_span_edges();
    test_section_flags();
    test_section_extents();
    test_section_overlap();
    test_header_limits();
    test_no_directory_means_nothing();
    test_import_tail_edges();
    test_import_entry_forms();
    test_export_tail_edges();
    test_export_names_and_forwarders();
    test_reloc_rva_past_32_bits();
    test_reloc_block_edges();
    test_debug_edges();
    test_debug_record_edges();
    test_arena_limit_exact();
    printf("All PE boundary tests passed.\n");
    return 0;
}
