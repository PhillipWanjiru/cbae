/*
 * pe_builder.h - builds PE32+ files byte by byte, straight from the Microsoft PE/COFF specification.
 *
 * This is deliberately NOT built on the loader's structures or headers: every field is written at its
 * documented offset (the PB_* constants below, taken from the specification, not from src/loader), so
 * a loader that misreads the format cannot also misread the test's files in the same way. That is
 * exactly the mistake the first PE loader made: its header struct and its test's copy of that struct
 * shared one wrong layout, so the loader passed its own test on files no real linker produces.
 *
 * pb_spec_default() describes a small driver-like image:
 *   .text   RVA 0x1000  code, VirtualSize == SizeOfRawData == 0x200
 *   .rdata  imports (ntoskrnl.exe: 3 by name + 1 by ordinal, HAL.dll: 1 by name), exports (named,
 *           unnamed, alias, forwarder, data), debug directory (COFF entry, CodeView RSDS entry)
 *   .data   VirtualSize 0x400 > SizeOfRawData 0x200 (an uninitialised tail)
 *   .pdata  3 RUNTIME_FUNCTION entries: VirtualSize 0x24, SizeOfRawData 0x200 (file padding)
 *   .reloc  two base-relocation blocks
 * and pb_build() returns the bytes plus a pb_layout_t that says where everything went, so a test can
 * damage one field of an otherwise valid file ("a good file plus one lie").
 */
#ifndef CBAE_TEST_PE_BUILDER_H
#define CBAE_TEST_PE_BUILDER_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- offsets from the specification (https://learn.microsoft.com/windows/win32/debug/pe-format) ---- */
#define PB_DOS_E_LFANEW       0x3C
#define PB_COFF_MACHINE       0     /* from the end of the "PE\0\0" signature */
#define PB_COFF_NSECTIONS     2
#define PB_COFF_TIMESTAMP     4
#define PB_COFF_SYMPTR        8
#define PB_COFF_NSYMS         12
#define PB_COFF_OPTSIZE       16
#define PB_COFF_CHARS         18
#define PB_COFF_SIZE          20
#define PB_OPT_MAGIC          0     /* from the start of the optional header */
#define PB_OPT_MAJOR_LINKER   2
#define PB_OPT_MINOR_LINKER   3
#define PB_OPT_SIZE_OF_CODE   4
#define PB_OPT_SIZE_INIT      8
#define PB_OPT_SIZE_UNINIT    12
#define PB_OPT_ENTRY_RVA      16
#define PB_OPT_BASE_OF_CODE   20
#define PB_OPT_IMAGE_BASE     24    /* 8 bytes: PE32+ has no BaseOfData */
#define PB_OPT_SECT_ALIGN     32
#define PB_OPT_FILE_ALIGN     36
#define PB_OPT_SIZE_OF_IMAGE  56
#define PB_OPT_SIZE_OF_HDRS   60
#define PB_OPT_CHECKSUM       64
#define PB_OPT_SUBSYSTEM      68
#define PB_OPT_DLL_CHARS      70
#define PB_OPT_STACK_RESERVE  72
#define PB_OPT_LOADER_FLAGS   104
#define PB_OPT_NUM_DIRS       108
#define PB_OPT_DIRS           112
#define PB_OPT_FIXED_SIZE     112   /* up to the data directories */
#define PB_OPT_PE32P_SIZE     240   /* with 16 data directories */
#define PB_DIR_EXPORT         0
#define PB_DIR_IMPORT         1
#define PB_DIR_EXCEPTION      3
#define PB_DIR_BASERELOC      5
#define PB_DIR_DEBUG          6
#define PB_SEC_NAME           0     /* from the start of a section header (40 bytes) */
#define PB_SEC_VSIZE          8
#define PB_SEC_RVA            12
#define PB_SEC_RAWSIZE        16
#define PB_SEC_RAWPTR         20
#define PB_SEC_CHARS          36
#define PB_SEC_HDR_SIZE       40
#define PB_MACHINE_AMD64      0x8664
#define PB_MACHINE_ARM64      0xAA64
#define PB_MAGIC_PE32P        0x20B
#define PB_MAGIC_PE32         0x10B
#define PB_SCN_CODE           0x00000020u
#define PB_SCN_INIT_DATA      0x00000040u
#define PB_SCN_UNINIT_DATA    0x00000080u
#define PB_SCN_DISCARDABLE    0x02000000u
#define PB_SCN_EXEC           0x20000000u
#define PB_SCN_READ           0x40000000u
#define PB_SCN_WRITE          0x80000000u
#define PB_IMPORT_DESC_SIZE   20
#define PB_EXPORT_DIR_SIZE    40
#define PB_DEBUG_ENTRY_SIZE   28
#define PB_REL_ABSOLUTE       0
#define PB_REL_HIGH           1
#define PB_REL_HIGHLOW        3
#define PB_REL_DIR64          10

#define PB_FILE_ALIGN         0x200u
#define PB_SECT_ALIGN         0x1000u
#define PB_HEADERS_SIZE       0x400u
#define PB_E_LFANEW_DEFAULT   0x80u
#define PB_MAX                32

/* ---- little-endian writers and readers at explicit offsets ---- */
static inline void pb_w8 (uint8_t *b, size_t o, uint8_t v)  { b[o] = v; }
static inline void pb_w16(uint8_t *b, size_t o, uint16_t v) { b[o] = (uint8_t)v; b[o + 1] = (uint8_t)(v >> 8); }
static inline void pb_w32(uint8_t *b, size_t o, uint32_t v) { for (int i = 0; i < 4; i++) b[o + i] = (uint8_t)(v >> (8 * i)); }
static inline void pb_w64(uint8_t *b, size_t o, uint64_t v) { for (int i = 0; i < 8; i++) b[o + i] = (uint8_t)(v >> (8 * i)); }
static inline uint16_t pb_r16(const uint8_t *b, size_t o) { return (uint16_t)(b[o] | (b[o + 1] << 8)); }
static inline uint32_t pb_r32(const uint8_t *b, size_t o) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | b[o + i]; return v; }
static inline uint64_t pb_r64(const uint8_t *b, size_t o) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | b[o + i]; return v; }
static inline uint32_t pb_align(uint32_t v, uint32_t a) { return (v + a - 1) / a * a; }

/* ---- what to build ---- */
typedef struct { const char *name; uint16_t hint; uint16_t ordinal; bool by_ordinal; } pb_import_t;
typedef struct { const char *dll; pb_import_t fn[PB_MAX]; int nfn; bool no_ilt; } pb_dll_t;

typedef struct {
    uint32_t    rva;            /* of the code or data; ignored for a forwarder */
    const char *forward;        /* "DLL.Function" or "DLL.#12": the entry is a forwarder */
} pb_slot_t;
typedef struct { const char *name; uint16_t slot; } pb_export_name_t;
typedef struct {
    bool              present;
    const char       *dll_name;
    uint32_t          base;     /* the ordinal of slot 0 */
    pb_slot_t         slot[PB_MAX];
    int               nslots;
    pb_export_name_t  name[PB_MAX];
    int               nnames;
} pb_exports_t;

typedef struct { uint8_t type; uint16_t offset; } pb_fixup_t;
typedef struct { uint32_t page_rva; pb_fixup_t fix[PB_MAX]; int nfix; } pb_block_t;

typedef struct { uint32_t type; bool rsds; const char *pdb; } pb_debug_t;

typedef struct {
    uint16_t machine;
    uint64_t image_base;
    uint32_t entry_rva;
    uint16_t subsystem;
    uint16_t dll_chars;
    uint32_t checksum;
    uint32_t e_lfanew;
    uint16_t optional_magic;
    uint32_t num_dirs;          /* NumberOfRvaAndSizes as written; the optional header is sized for it */
    pb_dll_t dll[4];
    int      ndll;
    pb_exports_t exports;
    pb_block_t   block[4];
    int          nblocks;
    pb_debug_t   debug[4];
    int          ndebug;
    int          npdata;        /* RUNTIME_FUNCTION entries in .pdata */
    bool         text_vsize_zero;   /* VirtualSize 0: the section's size in memory is SizeOfRawData */
} pb_spec_t;

typedef struct {
    uint8_t *b;
    size_t   n;
} pb_file_t;

/* ---- where it went ---- */
#define PB_NSEC 5
enum { PB_S_TEXT, PB_S_RDATA, PB_S_DATA, PB_S_PDATA, PB_S_RELOC };
typedef struct {
    uint32_t e_lfanew, coff, opt, opt_size, sect_tab;
    uint32_t sec_hdr[PB_NSEC];      /* file offset of each section header */
    uint32_t sec_rva[PB_NSEC], sec_off[PB_NSEC], sec_raw[PB_NSEC], sec_vsize[PB_NSEC];
    uint32_t dir_entry[16];         /* file offset of each data directory entry (0 if not present) */
    uint32_t imp_dir_rva, imp_dir_size;
    uint32_t imp_ilt_rva[4], imp_iat_rva[4];
    uint32_t imp_hintname_rva[4][PB_MAX];
    uint32_t exp_dir_rva, exp_dir_size, exp_eat_rva, exp_names_rva, exp_ords_rva;
    uint32_t reloc_rva, reloc_size;
    uint32_t debug_rva, debug_size;
    uint32_t cv_off[4];             /* file offset of each debug entry's raw data (0 if none) */
    uint32_t pdata_rva, pdata_size;
} pb_layout_t;

static inline pb_spec_t pb_spec_default(void) {
    pb_spec_t s;
    memset(&s, 0, sizeof s);
    s.machine = PB_MACHINE_AMD64;
    s.image_base = UINT64_C(0x140000000);
    s.entry_rva = 0x1000;
    s.subsystem = 1;                            /* IMAGE_SUBSYSTEM_NATIVE: a driver */
    s.dll_chars = 0x8160;
    s.checksum = 0x0012ABCDu;
    s.e_lfanew = PB_E_LFANEW_DEFAULT;
    s.optional_magic = PB_MAGIC_PE32P;
    s.num_dirs = 16;
    s.ndll = 2;
    s.dll[0] = (pb_dll_t){ "ntoskrnl.exe", { { "IoCreateDevice", 0x0123, 0, false },
                                              { "IoDeleteDevice", 0x0124, 0, false },
                                              { NULL, 0, 0x0457, true },
                                              { "ExAllocatePool2", 0x0041, 0, false } }, 4, false };
    s.dll[1] = (pb_dll_t){ "HAL.dll", { { "KeStallExecutionProcessor", 0x0007, 0, false } }, 1, true };   /* no ILT: the IAT is read */
    s.exports.present = true;
    s.exports.dll_name = "mydrv.sys";
    s.exports.base = 5;
    s.exports.nslots = 5;
    s.exports.slot[0] = (pb_slot_t){ 0x1000, NULL };            /* DriverEntry */
    s.exports.slot[1] = (pb_slot_t){ 0x1010, NULL };            /* MyHelper (and an alias) */
    s.exports.slot[2] = (pb_slot_t){ 0x1020, NULL };            /* no name: ordinal 7 */
    s.exports.slot[3] = (pb_slot_t){ 0, "NTDLL.RtlFoo" };       /* forwarder */
    s.exports.slot[4] = (pb_slot_t){ 0x3000, NULL };            /* data in .data */
    s.exports.nnames = 5;
    s.exports.name[0] = (pb_export_name_t){ "DriverEntry", 0 };
    s.exports.name[1] = (pb_export_name_t){ "FwdFunc", 3 };
    s.exports.name[2] = (pb_export_name_t){ "MyHelper", 1 };
    s.exports.name[3] = (pb_export_name_t){ "MyHelperAlias", 1 };
    s.exports.name[4] = (pb_export_name_t){ "g_Counter", 4 };   /* sorted by name, as a linker writes them */
    s.nblocks = 2;
    s.block[0] = (pb_block_t){ 0x1000, { { PB_REL_DIR64, 0x008 }, { PB_REL_DIR64, 0x010 }, { PB_REL_HIGHLOW, 0x020 }, { PB_REL_ABSOLUTE, 0 } }, 4 };
    s.block[1] = (pb_block_t){ 0x3000, { { PB_REL_DIR64, 0x000 }, { PB_REL_HIGH, 0x008 } }, 2 };
    s.ndebug = 2;
    s.debug[0] = (pb_debug_t){ 1, false, NULL };                /* a COFF debug entry: not CodeView */
    s.debug[1] = (pb_debug_t){ 2, true, "C:\\build\\mydrv.pdb" };
    s.npdata = 3;
    return s;
}

/* ---- the builder ---- */
typedef struct { uint8_t *b; uint32_t n, cap; } pb_blob_t;      /* a growing section body */

static inline uint32_t pb_blob_reserve(pb_blob_t *x, uint32_t n) {
    uint32_t at = x->n;
    if (x->n + n > x->cap) {
        x->cap = (x->n + n) * 2 + 64;
        x->b = (uint8_t *)realloc(x->b, x->cap);
        assert(x->b);
    }
    memset(x->b + x->n, 0, n);
    x->n += n;
    return at;
}
static inline uint32_t pb_blob_str(pb_blob_t *x, const char *s) {
    uint32_t at = pb_blob_reserve(x, (uint32_t)strlen(s) + 1);
    memcpy(x->b + at, s, strlen(s));
    return at;
}
static inline void pb_blob_even(pb_blob_t *x) { if (x->n & 1) pb_blob_reserve(x, 1); }
static inline void pb_blob_align4(pb_blob_t *x) { while (x->n & 3) pb_blob_reserve(x, 1); }

static inline pb_file_t pb_build(const pb_spec_t *sp, pb_layout_t *out_lay) {
    pb_layout_t L;
    memset(&L, 0, sizeof L);
    const uint32_t rdata_rva = 0x2000;

    /* ---- .rdata ----
     * The tables follow one another with no padding, so the import lookup tables and the export arrays
     * land at addresses that are not multiples of their element size, which a PE is allowed to do. */
    pb_blob_t rd = { NULL, 0, 0 };
    uint32_t imp_desc_at = 0;
    if (sp->ndll > 0) {
        imp_desc_at = pb_blob_reserve(&rd, (uint32_t)(sp->ndll + 1) * PB_IMPORT_DESC_SIZE);
        L.imp_dir_rva = rdata_rva + imp_desc_at;
        L.imp_dir_size = (uint32_t)(sp->ndll + 1) * PB_IMPORT_DESC_SIZE;
    }
    uint32_t ilt_at[4] = {0}, iat_at[4] = {0};
    for (int d = 0; d < sp->ndll; d++) {
        const uint32_t ents = (uint32_t)sp->dll[d].nfn + 1;
        if (!sp->dll[d].no_ilt) { ilt_at[d] = pb_blob_reserve(&rd, ents * 8); L.imp_ilt_rva[d] = rdata_rva + ilt_at[d]; }
        iat_at[d] = pb_blob_reserve(&rd, ents * 8);
        L.imp_iat_rva[d] = rdata_rva + iat_at[d];
    }
    uint32_t hn_at[4][PB_MAX];
    for (int d = 0; d < sp->ndll; d++)
        for (int k = 0; k < sp->dll[d].nfn; k++) {
            const pb_import_t *f = &sp->dll[d].fn[k];
            if (f->by_ordinal) { hn_at[d][k] = 0; continue; }
            pb_blob_even(&rd);
            hn_at[d][k] = pb_blob_reserve(&rd, 2);
            pb_w16(rd.b, hn_at[d][k], f->hint);
            pb_blob_str(&rd, f->name);
            L.imp_hintname_rva[d][k] = rdata_rva + hn_at[d][k];
        }
    uint32_t dllname_at[4];
    for (int d = 0; d < sp->ndll; d++) dllname_at[d] = pb_blob_str(&rd, sp->dll[d].dll);
    for (int d = 0; d < sp->ndll; d++) {
        const pb_dll_t *D = &sp->dll[d];
        for (int k = 0; k < D->nfn; k++) {
            uint64_t e = D->fn[k].by_ordinal ? (UINT64_C(1) << 63) | D->fn[k].ordinal : (uint64_t)(rdata_rva + hn_at[d][k]);
            if (!D->no_ilt) pb_w64(rd.b, ilt_at[d] + (uint32_t)k * 8, e);
            pb_w64(rd.b, iat_at[d] + (uint32_t)k * 8, e);          /* the IAT holds the same on disk */
        }
        const uint32_t desc = imp_desc_at + (uint32_t)d * PB_IMPORT_DESC_SIZE;
        pb_w32(rd.b, desc + 0,  D->no_ilt ? 0 : rdata_rva + ilt_at[d]);
        pb_w32(rd.b, desc + 12, rdata_rva + dllname_at[d]);
        pb_w32(rd.b, desc + 16, rdata_rva + iat_at[d]);
    }

    /* exports: directory, address table, name pointers, ordinals, strings; the forwarder strings are
     * inside [directory, directory + size), which is how a loader tells a forwarder from code */
    if (sp->exports.present) {
        pb_blob_align4(&rd);
        const pb_exports_t *E = &sp->exports;
        const uint32_t dir = pb_blob_reserve(&rd, PB_EXPORT_DIR_SIZE);
        const uint32_t eat = pb_blob_reserve(&rd, (uint32_t)E->nslots * 4);
        const uint32_t npt = pb_blob_reserve(&rd, (uint32_t)E->nnames * 4);
        const uint32_t ord = pb_blob_reserve(&rd, (uint32_t)E->nnames * 2);
        pb_blob_align4(&rd);
        const uint32_t dllname = pb_blob_str(&rd, E->dll_name);
        for (int i = 0; i < E->nnames; i++) {
            const uint32_t at = pb_blob_str(&rd, E->name[i].name);
            pb_w32(rd.b, npt + (uint32_t)i * 4, rdata_rva + at);
            pb_w16(rd.b, ord + (uint32_t)i * 2, E->name[i].slot);
        }
        for (int i = 0; i < E->nslots; i++) {
            if (E->slot[i].forward) pb_w32(rd.b, eat + (uint32_t)i * 4, rdata_rva + pb_blob_str(&rd, E->slot[i].forward));
            else                    pb_w32(rd.b, eat + (uint32_t)i * 4, E->slot[i].rva);
        }
        pb_w32(rd.b, dir + 12, rdata_rva + dllname);
        pb_w32(rd.b, dir + 16, E->base);
        pb_w32(rd.b, dir + 20, (uint32_t)E->nslots);
        pb_w32(rd.b, dir + 24, (uint32_t)E->nnames);
        pb_w32(rd.b, dir + 28, rdata_rva + eat);
        pb_w32(rd.b, dir + 32, rdata_rva + npt);
        pb_w32(rd.b, dir + 36, rdata_rva + ord);
        L.exp_dir_rva = rdata_rva + dir;
        L.exp_dir_size = rd.n - dir;
        L.exp_eat_rva = rdata_rva + eat; L.exp_names_rva = rdata_rva + npt; L.exp_ords_rva = rdata_rva + ord;
    }

    /* debug directory and its raw data (CodeView RSDS: signature, GUID, age, NUL-terminated path) */
    if (sp->ndebug > 0) {
        pb_blob_align4(&rd);
        const uint32_t dd = pb_blob_reserve(&rd, (uint32_t)sp->ndebug * PB_DEBUG_ENTRY_SIZE);
        L.debug_rva = rdata_rva + dd;
        L.debug_size = (uint32_t)sp->ndebug * PB_DEBUG_ENTRY_SIZE;
        for (int i = 0; i < sp->ndebug; i++) {
            const uint32_t e = dd + (uint32_t)i * PB_DEBUG_ENTRY_SIZE;
            pb_w32(rd.b, e + 4, 0x5A5A0000u + (uint32_t)i);             /* TimeDateStamp */
            pb_w32(rd.b, e + 12, sp->debug[i].type);
            if (sp->debug[i].rsds) {
                pb_blob_align4(&rd);
                const uint32_t at = pb_blob_reserve(&rd, 24);
                memcpy(rd.b + at, "RSDS", 4);
                for (int g = 0; g < 16; g++) rd.b[at + 4 + (uint32_t)g] = (uint8_t)(0xA0 + g);
                pb_w32(rd.b, at + 20, 3);                               /* age */
                if (sp->debug[i].pdb) pb_blob_str(&rd, sp->debug[i].pdb); else pb_blob_reserve(&rd, 1);
                pb_w32(rd.b, e + 16, rd.n - at);                        /* SizeOfData */
                pb_w32(rd.b, e + 20, rdata_rva + at);                   /* AddressOfRawData */
                L.cv_off[i] = at;                                       /* made absolute below */
            }
        }
    }
    pb_blob_align4(&rd);

    /* ---- the other sections ---- */
    uint8_t text[0x200];
    for (size_t i = 0; i < sizeof text; i++) text[i] = (uint8_t)(i * 7 + 1);       /* recognisable bytes: a test compares them with what it reads back */
    text[0] = 0x31; text[1] = 0xC0; text[2] = 0xC3;                     /* xor eax,eax; ret */

    pb_blob_t rel = { NULL, 0, 0 };
    for (int i = 0; i < sp->nblocks; i++) {
        const pb_block_t *B = &sp->block[i];
        uint32_t sz = 8 + (uint32_t)B->nfix * 2;
        sz = pb_align(sz, 4);
        const uint32_t at = pb_blob_reserve(&rel, sz);
        pb_w32(rel.b, at, B->page_rva);
        pb_w32(rel.b, at + 4, sz);
        for (int k = 0; k < B->nfix; k++)
            pb_w16(rel.b, at + 8 + (uint32_t)k * 2, (uint16_t)((B->fix[k].type << 12) | (B->fix[k].offset & 0xFFF)));
    }
    L.reloc_size = rel.n;

    /* section table: name, VirtualSize, SizeOfRawData, characteristics */
    struct { const char *name; uint32_t vsize, raw, chars; const uint8_t *body; uint32_t body_n; } S[PB_NSEC] = {
        { ".text",  sp->text_vsize_zero ? 0 : 0x200, 0x200, PB_SCN_CODE | PB_SCN_EXEC | PB_SCN_READ, text, sizeof text },
        { ".rdata", rd.n,  pb_align(rd.n, PB_FILE_ALIGN), PB_SCN_INIT_DATA | PB_SCN_READ, rd.b, rd.n },
        { ".data",  0x400, 0x200, PB_SCN_INIT_DATA | PB_SCN_READ | PB_SCN_WRITE, NULL, 0 },
        { ".pdata", (uint32_t)sp->npdata * 12, 0x200, PB_SCN_INIT_DATA | PB_SCN_READ, NULL, 0 },
        { ".reloc", rel.n, pb_align(rel.n ? rel.n : 1, PB_FILE_ALIGN), PB_SCN_INIT_DATA | PB_SCN_READ | PB_SCN_DISCARDABLE, rel.b, rel.n },
    };
    uint32_t rva = 0x1000, off = PB_HEADERS_SIZE;
    for (int i = 0; i < PB_NSEC; i++) {
        L.sec_rva[i] = rva; L.sec_off[i] = off; L.sec_raw[i] = S[i].raw;
        L.sec_vsize[i] = S[i].vsize ? S[i].vsize : S[i].raw;
        rva += pb_align(L.sec_vsize[i], PB_SECT_ALIGN);
        off += S[i].raw;
    }
    const uint32_t size_of_image = rva;
    L.pdata_rva = L.sec_rva[PB_S_PDATA];
    L.pdata_size = (uint32_t)sp->npdata * 12;
    L.reloc_rva = L.sec_rva[PB_S_RELOC];
    for (int i = 0; i < sp->ndebug; i++)
        if (L.cv_off[i]) {
            L.cv_off[i] += L.sec_off[PB_S_RDATA];                       /* now a file offset: PointerToRawData is only known after layout */
            pb_w32(rd.b, (L.debug_rva - rdata_rva) + (uint32_t)i * PB_DEBUG_ENTRY_SIZE + 24, L.cv_off[i]);
        }

    /* ---- headers ---- */
    pb_file_t f;
    f.n = off;
    f.b = (uint8_t *)calloc(1, f.n);
    assert(f.b);
    uint8_t *b = f.b;
    pb_w16(b, 0, 0x5A4D);                                               /* "MZ" */
    pb_w32(b, PB_DOS_E_LFANEW, sp->e_lfanew);
    L.e_lfanew = sp->e_lfanew;
    L.coff = sp->e_lfanew + 4;
    const uint32_t ndirs_written = sp->num_dirs < 16 ? sp->num_dirs : 16;
    L.opt_size = PB_OPT_FIXED_SIZE + ndirs_written * 8;
    L.opt = L.coff + PB_COFF_SIZE;
    L.sect_tab = L.opt + L.opt_size;
    assert(L.sect_tab + PB_NSEC * PB_SEC_HDR_SIZE <= PB_HEADERS_SIZE);
    memcpy(b + sp->e_lfanew, "PE\0\0", 4);
    pb_w16(b, L.coff + PB_COFF_MACHINE, sp->machine);
    pb_w16(b, L.coff + PB_COFF_NSECTIONS, PB_NSEC);
    pb_w32(b, L.coff + PB_COFF_TIMESTAMP, 0x5F5E1000u);
    pb_w16(b, L.coff + PB_COFF_OPTSIZE, (uint16_t)L.opt_size);
    pb_w16(b, L.coff + PB_COFF_CHARS, 0x0022);                          /* executable, large address aware */
    pb_w16(b, L.opt + PB_OPT_MAGIC, sp->optional_magic);
    pb_w8 (b, L.opt + PB_OPT_MAJOR_LINKER, 14);
    pb_w8 (b, L.opt + PB_OPT_MINOR_LINKER, 29);
    pb_w32(b, L.opt + PB_OPT_SIZE_OF_CODE, 0x200);
    pb_w32(b, L.opt + PB_OPT_SIZE_INIT, S[1].raw + S[2].raw + S[3].raw + S[4].raw);
    pb_w32(b, L.opt + PB_OPT_SIZE_UNINIT, 0);
    pb_w32(b, L.opt + PB_OPT_ENTRY_RVA, sp->entry_rva);
    pb_w32(b, L.opt + PB_OPT_BASE_OF_CODE, 0x1000);
    pb_w64(b, L.opt + PB_OPT_IMAGE_BASE, sp->image_base);
    pb_w32(b, L.opt + PB_OPT_SECT_ALIGN, PB_SECT_ALIGN);
    pb_w32(b, L.opt + PB_OPT_FILE_ALIGN, PB_FILE_ALIGN);
    pb_w16(b, L.opt + 40, 6); pb_w16(b, L.opt + 48, 6);                 /* OS and subsystem versions */
    pb_w32(b, L.opt + PB_OPT_SIZE_OF_IMAGE, size_of_image);
    pb_w32(b, L.opt + PB_OPT_SIZE_OF_HDRS, PB_HEADERS_SIZE);
    pb_w32(b, L.opt + PB_OPT_CHECKSUM, sp->checksum);
    pb_w16(b, L.opt + PB_OPT_SUBSYSTEM, sp->subsystem);
    pb_w16(b, L.opt + PB_OPT_DLL_CHARS, sp->dll_chars);
    pb_w64(b, L.opt + PB_OPT_STACK_RESERVE, 0x100000);
    pb_w64(b, L.opt + PB_OPT_STACK_RESERVE + 8, 0x1000);
    pb_w64(b, L.opt + PB_OPT_STACK_RESERVE + 16, 0x100000);
    pb_w64(b, L.opt + PB_OPT_STACK_RESERVE + 24, 0x1000);
    pb_w32(b, L.opt + PB_OPT_NUM_DIRS, sp->num_dirs);
    for (uint32_t i = 0; i < ndirs_written; i++) L.dir_entry[i] = L.opt + PB_OPT_DIRS + i * 8;
#define PB_DIR(idx, r, s) do { if ((idx) < ndirs_written && (r)) { pb_w32(b, L.dir_entry[idx], (r)); pb_w32(b, L.dir_entry[idx] + 4, (s)); } } while (0)
    PB_DIR(PB_DIR_EXPORT, L.exp_dir_rva, L.exp_dir_size);
    PB_DIR(PB_DIR_IMPORT, L.imp_dir_rva, L.imp_dir_size);
    PB_DIR(PB_DIR_EXCEPTION, L.pdata_rva, L.pdata_size);
    PB_DIR(PB_DIR_BASERELOC, rel.n ? L.reloc_rva : 0, L.reloc_size);
    PB_DIR(PB_DIR_DEBUG, L.debug_rva, L.debug_size);
#undef PB_DIR
    for (int i = 0; i < PB_NSEC; i++) {
        const uint32_t h = L.sect_tab + (uint32_t)i * PB_SEC_HDR_SIZE;
        L.sec_hdr[i] = h;
        memcpy(b + h + PB_SEC_NAME, S[i].name, strlen(S[i].name));
        pb_w32(b, h + PB_SEC_VSIZE, S[i].vsize);
        pb_w32(b, h + PB_SEC_RVA, L.sec_rva[i]);
        pb_w32(b, h + PB_SEC_RAWSIZE, S[i].raw);
        pb_w32(b, h + PB_SEC_RAWPTR, L.sec_off[i]);
        pb_w32(b, h + PB_SEC_CHARS, S[i].chars);
    }
    for (int i = 0; i < PB_NSEC; i++) if (S[i].body) memcpy(b + L.sec_off[i], S[i].body, S[i].body_n);
    assert(sp->npdata >= 0 && sp->npdata <= 0x200 / 12);
    for (uint32_t i = 0; i < (uint32_t)sp->npdata; i++) {               /* .pdata: RUNTIME_FUNCTION = begin, end, unwind info (RVAs) */
        const uint32_t e = L.sec_off[PB_S_PDATA] + i * 12;
        pb_w32(b, e, 0x1000 + i * 0x10);
        pb_w32(b, e + 4, 0x1000 + i * 0x10 + 0x0C);
        pb_w32(b, e + 8, 0x2F00);
    }
    free(rd.b);
    free(rel.b);
    if (out_lay) *out_lay = L;
    return f;
}

static inline void pb_free(pb_file_t *f) { free(f->b); f->b = NULL; f->n = 0; }

/* RVA -> file offset using the layout (sections only); UINT32_MAX if no section holds it */
static inline uint32_t pb_rva_to_off(const pb_layout_t *L, uint32_t rva) {
    for (int i = 0; i < PB_NSEC; i++)
        if (rva >= L->sec_rva[i] && rva - L->sec_rva[i] < L->sec_raw[i]) return L->sec_off[i] + (rva - L->sec_rva[i]);
    return UINT32_MAX;
}

/* writes the file to path; returns false on failure */
static inline bool pb_write(const char *path, const pb_file_t *f) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    const bool ok = fwrite(f->b, 1, f->n, fp) == f->n;
    return fclose(fp) == 0 && ok;
}

/* an exactly sized heap copy, so AddressSanitizer sees every read past the end */
static inline uint8_t *pb_copy(const uint8_t *b, size_t n) {
    uint8_t *c = (uint8_t *)malloc(n ? n : 1);
    assert(c);
    if (n) memcpy(c, b, n);
    return c;
}


/* ---- a minimal image for tests that need a table of their own size ----
 * Headers (0x400 bytes) and ONE section, ".rdata" at RVA 0x1000 with VirtualSize == SizeOfRawData == raw,
 * data directories all empty. The caller writes the tables into the section body and then names them with
 * pb_mini_dir(). */
typedef struct { uint8_t *b; size_t n; uint32_t opt, sec_off, sec_rva; } pb_mini_t;

static inline pb_mini_t pb_mini(uint32_t raw) {
    pb_mini_t m;
    m.sec_off = PB_HEADERS_SIZE;
    m.sec_rva = 0x1000;
    m.n = (size_t)m.sec_off + raw;
    m.b = (uint8_t *)calloc(1, m.n);
    assert(m.b);
    uint8_t *b = m.b;
    const uint32_t coff = PB_E_LFANEW_DEFAULT + 4;
    m.opt = coff + PB_COFF_SIZE;
    pb_w16(b, 0, 0x5A4D);
    pb_w32(b, PB_DOS_E_LFANEW, PB_E_LFANEW_DEFAULT);
    memcpy(b + PB_E_LFANEW_DEFAULT, "PE\0\0", 4);
    pb_w16(b, coff + PB_COFF_MACHINE, PB_MACHINE_AMD64);
    pb_w16(b, coff + PB_COFF_NSECTIONS, 1);
    pb_w16(b, coff + PB_COFF_OPTSIZE, PB_OPT_PE32P_SIZE);
    pb_w16(b, m.opt + PB_OPT_MAGIC, PB_MAGIC_PE32P);
    pb_w32(b, m.opt + PB_OPT_ENTRY_RVA, 0);
    pb_w64(b, m.opt + PB_OPT_IMAGE_BASE, UINT64_C(0x10000000));
    pb_w32(b, m.opt + PB_OPT_SECT_ALIGN, PB_SECT_ALIGN);
    pb_w32(b, m.opt + PB_OPT_FILE_ALIGN, PB_FILE_ALIGN);
    pb_w32(b, m.opt + PB_OPT_SIZE_OF_IMAGE, 0x1000 + pb_align(raw ? raw : 1, PB_SECT_ALIGN));
    pb_w32(b, m.opt + PB_OPT_SIZE_OF_HDRS, PB_HEADERS_SIZE);
    pb_w16(b, m.opt + PB_OPT_SUBSYSTEM, 1);
    pb_w32(b, m.opt + PB_OPT_NUM_DIRS, 16);
    const uint32_t h = m.opt + PB_OPT_PE32P_SIZE;
    memcpy(b + h, ".rdata", 6);
    pb_w32(b, h + PB_SEC_VSIZE, raw);
    pb_w32(b, h + PB_SEC_RVA, m.sec_rva);
    pb_w32(b, h + PB_SEC_RAWSIZE, raw);
    pb_w32(b, h + PB_SEC_RAWPTR, m.sec_off);
    pb_w32(b, h + PB_SEC_CHARS, PB_SCN_INIT_DATA | PB_SCN_READ);
    return m;
}
static inline void pb_mini_dir(pb_mini_t *m, int idx, uint32_t rva, uint32_t size) {
    pb_w32(m->b, m->opt + PB_OPT_DIRS + (uint32_t)idx * 8, rva);
    pb_w32(m->b, m->opt + PB_OPT_DIRS + (uint32_t)idx * 8 + 4, size);
}
static inline void pb_mini_free(pb_mini_t *m) { free(m->b); m->b = NULL; m->n = 0; }

#endif /* CBAE_TEST_PE_BUILDER_H */
