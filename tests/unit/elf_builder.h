/*
 * elf_builder.h - builds ELF64 files from a description, writing every field at the offset the gABI and the
 * x86-64 psABI give it. It shares no struct and no code with the loader under test, so a layout mistake
 * in the loader cannot be repeated here.
 *
 * A description (eb_spec_t) lists the sections, symbols and relocations the test wants. The builder adds
 * what a compiler would: the relocation sections (one per target section, in order of first mention),
 * .symtab, .strtab, .shstrtab, and, when a symbol needs one, SHT_SYMTAB_SHNDX. User section i is section
 * index i + 1; user symbol i is symbol index i + 1 (index 0 of each table is the reserved null entry).
 *
 * eb_build() also reports where everything went (eb_layout_t) so a test can damage one field at a time.
 */
#ifndef CBAE_TEST_ELF_BUILDER_H
#define CBAE_TEST_ELF_BUILDER_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- sizes ---- */
#define EB_EHDR_SIZE 64u
#define EB_SHDR_SIZE 64u
#define EB_SYM_SIZE  24u
#define EB_RELA_SIZE 24u

/* ---- e_ident ---- */
#define EB_EI_CLASS   4
#define EB_EI_DATA    5
#define EB_EI_VERSION 6
#define EB_CLASS32    1
#define EB_CLASS64    2
#define EB_DATA_LSB   1
#define EB_DATA_MSB   2

/* ---- Elf64_Ehdr ---- */
#define EB_E_TYPE      16
#define EB_E_MACHINE   18
#define EB_E_VERSION   20
#define EB_E_ENTRY     24
#define EB_E_PHOFF     32
#define EB_E_SHOFF     40
#define EB_E_FLAGS     48
#define EB_E_EHSIZE    52
#define EB_E_PHENTSIZE 54
#define EB_E_PHNUM     56
#define EB_E_SHENTSIZE 58
#define EB_E_SHNUM     60
#define EB_E_SHSTRNDX  62

/* ---- Elf64_Shdr ---- */
#define EB_SH_NAME      0
#define EB_SH_TYPE      4
#define EB_SH_FLAGS     8
#define EB_SH_ADDR      16
#define EB_SH_OFFSET    24
#define EB_SH_SIZE      32
#define EB_SH_LINK      40
#define EB_SH_INFO      44
#define EB_SH_ADDRALIGN 48
#define EB_SH_ENTSIZE   56

/* ---- Elf64_Sym ---- */
#define EB_ST_NAME  0
#define EB_ST_INFO  4
#define EB_ST_OTHER 5
#define EB_ST_SHNDX 6
#define EB_ST_VALUE 8
#define EB_ST_SIZE  16

/* ---- Elf64_Rela ---- */
#define EB_R_OFFSET 0
#define EB_R_INFO   8
#define EB_R_ADDEND 16

/* ---- values ---- */
#define EB_ET_NONE 0
#define EB_ET_REL  1
#define EB_ET_EXEC 2
#define EB_ET_DYN  3
#define EB_ET_CORE 4
#define EB_EM_X86_64  62
#define EB_EM_AARCH64 183

#define EB_SHT_NULL         0
#define EB_SHT_PROGBITS     1
#define EB_SHT_SYMTAB       2
#define EB_SHT_STRTAB       3
#define EB_SHT_RELA         4
#define EB_SHT_DYNAMIC      6
#define EB_SHT_NOTE         7
#define EB_SHT_NOBITS       8
#define EB_SHT_REL          9
#define EB_SHT_DYNSYM       11
#define EB_SHT_SYMTAB_SHNDX 18

#define EB_SHF_WRITE     0x1u
#define EB_SHF_ALLOC     0x2u
#define EB_SHF_EXECINSTR 0x4u
#define EB_SHF_MERGE     0x10u
#define EB_SHF_STRINGS   0x20u
#define EB_SHF_INFO_LINK 0x40u

#define EB_STB_LOCAL      0
#define EB_STB_GLOBAL     1
#define EB_STB_WEAK       2
#define EB_STB_GNU_UNIQUE 10
#define EB_STT_NOTYPE    0
#define EB_STT_OBJECT    1
#define EB_STT_FUNC      2
#define EB_STT_SECTION   3
#define EB_STT_FILE      4
#define EB_STT_COMMON    5
#define EB_STT_TLS       6
#define EB_STT_GNU_IFUNC 10
#define EB_ST_INFO_OF(bind, type) ((uint8_t)(((bind) << 4) | ((type) & 0xF)))

#define EB_SHN_UNDEF     0u
#define EB_SHN_LORESERVE 0xFF00u
#define EB_SHN_ABS       0xFFF1u
#define EB_SHN_COMMON    0xFFF2u
#define EB_SHN_XINDEX    0xFFFFu

#define EB_R_X86_64_NONE        0
#define EB_R_X86_64_64          1
#define EB_R_X86_64_PC32        2
#define EB_R_X86_64_PLT32       4
#define EB_R_X86_64_GOTPCREL    9
#define EB_R_X86_64_32          10
#define EB_R_X86_64_32S         11
#define EB_R_X86_64_PC64        24
#define EB_R_X86_64_GOTPCRELX   41
#define EB_R_X86_64_REX_GOTPCRELX 42
#define EB_R_INFO_OF(sym, type) (((uint64_t)(sym) << 32) | (uint32_t)(type))

/* ---- the description ---- */
#define EB_MAX_SEC    40
#define EB_MAX_SYM    48
#define EB_MAX_REL    96
#define EB_MAX_RELSEC 8
#define EB_LAYOUT_SECS 128         /* per-section positions are kept for the first this many sections */

typedef struct {
    const char    *name;
    uint32_t       type;           /* EB_SHT_* */
    uint64_t       flags, addr, align, entsize;
    const uint8_t *data;           /* the contents (not for NOBITS) */
    uint64_t       size;           /* their length; for NOBITS, the size the section has in memory */
    uint32_t       link, info;     /* written as given */
} eb_section_t;

typedef struct {
    const char *name;              /* NULL: st_name is 0 */
    uint8_t     info, other;
    uint32_t    shndx;             /* the section index; 0xFFF1 ABS and 0xFFF2 COMMON as in the ABI */
    bool        xindex;            /* store 0xFFFF in st_shndx and the real index in SHT_SYMTAB_SHNDX */
    uint64_t    value, size;
} eb_symbol_t;

typedef struct {
    uint32_t target;               /* the user section index the relocation applies to */
    uint64_t offset;
    uint32_t sym, type;
    int64_t  addend;
} eb_rela_t;

typedef struct {
    uint16_t     etype, machine;
    uint8_t      ei_class, ei_data;
    uint64_t     entry;
    eb_section_t sec[EB_MAX_SEC];   int nsec;
    eb_symbol_t  sym[EB_MAX_SYM];   int nsym;
    eb_rela_t    rel[EB_MAX_REL];   int nrel;
    bool         no_symtab;         /* no .symtab, .strtab or relocation sections */
    uint32_t     pad_sections;      /* this many empty sections after the user's (for large counts) ... */
    uint64_t     pad_flags;         /* ... with these sh_flags (0: not allocated) */
    bool         ext_numbering;     /* use the extended e_shnum / e_shstrndx form even when not needed */
} eb_spec_t;

typedef struct {
    uint32_t shoff, shnum;
    uint32_t symtab, strtab, shstrtab, shndx_tab;          /* section indices; shndx_tab 0: none */
    uint32_t sym_off, nsyms;                               /* file offset of symbol 0; entries including the null one */
    uint32_t strtab_off, strtab_size, shstrtab_off, shstrtab_size, shndx_off;
    uint32_t nrelsec;
    uint32_t rela_idx[EB_MAX_RELSEC], rela_target[EB_MAX_RELSEC], rela_off[EB_MAX_RELSEC], rela_n[EB_MAX_RELSEC];
    uint32_t rel_off[EB_MAX_REL];                          /* file offset of the entry written for spec.rel[i] */
    uint32_t sec_off[EB_LAYOUT_SECS], sec_size[EB_LAYOUT_SECS];
} eb_layout_t;

typedef struct { uint8_t *b; size_t n; } eb_file_t;

/* ---- little-endian access ---- */
static inline void eb_w16(uint8_t *b, size_t o, uint16_t v) { b[o] = (uint8_t)v; b[o + 1] = (uint8_t)(v >> 8); }
static inline void eb_w32(uint8_t *b, size_t o, uint32_t v) { for (int i = 0; i < 4; i++) b[o + i] = (uint8_t)(v >> (8 * i)); }
static inline void eb_w64(uint8_t *b, size_t o, uint64_t v) { for (int i = 0; i < 8; i++) b[o + i] = (uint8_t)(v >> (8 * i)); }
static inline uint16_t eb_r16(const uint8_t *b, size_t o) { return (uint16_t)(b[o] | (b[o + 1] << 8)); }
static inline uint32_t eb_r32(const uint8_t *b, size_t o) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | b[o + i]; return v; }
static inline uint64_t eb_r64(const uint8_t *b, size_t o) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | b[o + i]; return v; }

static inline uint32_t eb_sh(const eb_layout_t *L, uint32_t i) { return L->shoff + i * EB_SHDR_SIZE; }          /* file offset of section header i */
static inline uint32_t eb_sym(const eb_layout_t *L, uint32_t i) { return L->sym_off + i * EB_SYM_SIZE; }       /* ... of symbol i */

/* ---- the default description: a small driver-like module ----
 *
 * user sections                      user symbols (ELF index)
 *  1 .text        alloc|exec          1 FILE  mod.c
 *  2 .rodata      alloc               2 SECTION .text      3 SECTION .rodata   4 SECTION .data
 *  3 .data        alloc|write         5 LOCAL FUNC helper   .text+0x30 (0x10)
 *  4 .bss         nobits              6 LOCAL OBJECT local_var .data+0x18 (8)
 *  5 .modinfo     alloc               7 GLOBAL FUNC init_module    .text+0    (0x20)   <- offset 0
 *  6 __ksymtab_strings alloc          8 GLOBAL FUNC cleanup_module .text+0x20 (0x10)
 *  7 .comment                         9 GLOBAL OBJECT g_counter .data+0x10 (8)
 *  8 .debug_info                     10 WEAK FUNC weak_hook .text+0x40 (8)
 * generated: .rela.text .rela.data   11 GLOBAL undefined printk       12 undefined kmalloc
 *  .rela.debug_info .symtab .strtab  13 WEAK undefined optional_api   14 GLOBAL OBJECT undefined jiffies
 *  .shstrtab                         15 GLOBAL COMMON shared_buf (align 32, size 64)
 *                                    16 GLOBAL ABS ABS_CONST = 0x1234
 *                                    17 GLOBAL OBJECT big_bss .bss+0 (0x100)
 *                                    18 GLOBAL undefined never_referenced (no relocation names it)
 *                                    19 GLOBAL GNU_IFUNC resolver .text+0x48 (8)
 *                                    20 GLOBAL TLS tls_var .data+0 (8)
 *
 * relocations: .text: PLT32 printk, PLT32 printk, PLT32 kmalloc, PC32 .rodata+0xC, PLT32 helper,
 *   PLT32 optional_api, GOTPCRELX jiffies, 32S .data+8, type 42 jiffies, type 10 .rodata, type 0, type 24;
 *   .data: 64 init_module, 64 printk; .debug_info: three entries (one names never_referenced).
 */
#define EB_S_TEXT 1
#define EB_S_RODATA 2
#define EB_S_DATA 3
#define EB_S_BSS 4
#define EB_S_MODINFO 5
#define EB_S_KSYMSTR 6
#define EB_S_COMMENT 7
#define EB_S_DEBUG 8

static inline eb_spec_t eb_spec_default(void) {
    static uint8_t text[0x80], rodata[0x40], data[0x20], debug[0x20];
    static const uint8_t modinfo[] = "license=GPL\0author=A. Author\0author=B. Author\0description=A test module\0vermagic=6.8.0 SMP mod_unload\0";
    static const uint8_t ksymstr[] = "my_export\0init_module\0other_export\0";
    static const uint8_t comment[] = "GCC: (GNU) 13.3.0";
    static bool init;
    if (!init) {
        memset(text, 0x90, sizeof text);
        for (int at = 0; at < 0x60; at += 0x10) { text[at] = 0xE8; }                    /* call rel32, to be relocated */
        text[0x38] = 0xE8; text[0x40] = 0xE8; text[0x48] = 0xE8;
        for (int i = 0; i < (int)sizeof rodata; i++) rodata[i] = (uint8_t)('a' + i % 26);
        memset(data, 0, sizeof data);
        memset(debug, 0xDD, sizeof debug);
        init = true;
    }
    eb_spec_t s;
    memset(&s, 0, sizeof s);
    s.etype = EB_ET_REL;
    s.machine = EB_EM_X86_64;
    s.ei_class = EB_CLASS64;
    s.ei_data = EB_DATA_LSB;
    int k = 0;
    s.sec[k++] = (eb_section_t){ ".text", EB_SHT_PROGBITS, EB_SHF_ALLOC | EB_SHF_EXECINSTR, 0, 16, 0, text, sizeof text, 0, 0 };
    s.sec[k++] = (eb_section_t){ ".rodata", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 8, 0, rodata, sizeof rodata, 0, 0 };
    s.sec[k++] = (eb_section_t){ ".data", EB_SHT_PROGBITS, EB_SHF_ALLOC | EB_SHF_WRITE, 0, 8, 0, data, sizeof data, 0, 0 };
    s.sec[k++] = (eb_section_t){ ".bss", EB_SHT_NOBITS, EB_SHF_ALLOC | EB_SHF_WRITE, 0, 32, 0, NULL, 0x100, 0, 0 };
    s.sec[k++] = (eb_section_t){ ".modinfo", EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 1, 0, modinfo, sizeof modinfo - 1, 0, 0 };
    s.sec[k++] = (eb_section_t){ "__ksymtab_strings", EB_SHT_PROGBITS, EB_SHF_ALLOC | EB_SHF_MERGE | EB_SHF_STRINGS, 0, 1, 1, ksymstr, sizeof ksymstr - 1, 0, 0 };
    s.sec[k++] = (eb_section_t){ ".comment", EB_SHT_PROGBITS, EB_SHF_MERGE | EB_SHF_STRINGS, 0, 1, 1, comment, sizeof comment, 0, 0 };
    s.sec[k++] = (eb_section_t){ ".debug_info", EB_SHT_PROGBITS, 0, 0, 1, 0, debug, sizeof debug, 0, 0 };
    s.nsec = k;

    k = 0;
    s.sym[k++] = (eb_symbol_t){ "mod.c",          EB_ST_INFO_OF(EB_STB_LOCAL, EB_STT_FILE),   0, EB_SHN_ABS, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ NULL,             EB_ST_INFO_OF(EB_STB_LOCAL, EB_STT_SECTION), 0, EB_S_TEXT, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ NULL,             EB_ST_INFO_OF(EB_STB_LOCAL, EB_STT_SECTION), 0, EB_S_RODATA, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ NULL,             EB_ST_INFO_OF(EB_STB_LOCAL, EB_STT_SECTION), 0, EB_S_DATA, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ "helper",         EB_ST_INFO_OF(EB_STB_LOCAL, EB_STT_FUNC),   0, EB_S_TEXT, false, 0x30, 0x10 };
    s.sym[k++] = (eb_symbol_t){ "local_var",      EB_ST_INFO_OF(EB_STB_LOCAL, EB_STT_OBJECT), 0, EB_S_DATA, false, 0x18, 8 };
    s.sym[k++] = (eb_symbol_t){ "init_module",    EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_FUNC),  0, EB_S_TEXT, false, 0, 0x20 };
    s.sym[k++] = (eb_symbol_t){ "cleanup_module", EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_FUNC),  0, EB_S_TEXT, false, 0x20, 0x10 };
    s.sym[k++] = (eb_symbol_t){ "g_counter",      EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_OBJECT), 0, EB_S_DATA, false, 0x10, 8 };
    s.sym[k++] = (eb_symbol_t){ "weak_hook",      EB_ST_INFO_OF(EB_STB_WEAK, EB_STT_FUNC),    0, EB_S_TEXT, false, 0x40, 8 };
    s.sym[k++] = (eb_symbol_t){ "printk",         EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_NOTYPE), 0, EB_SHN_UNDEF, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ "kmalloc",        EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_NOTYPE), 0, EB_SHN_UNDEF, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ "optional_api",   EB_ST_INFO_OF(EB_STB_WEAK, EB_STT_NOTYPE),  0, EB_SHN_UNDEF, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ "jiffies",        EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_OBJECT), 0, EB_SHN_UNDEF, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ "shared_buf",     EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_OBJECT), 0, EB_SHN_COMMON, false, 32, 64 };
    s.sym[k++] = (eb_symbol_t){ "ABS_CONST",      EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_NOTYPE), 0, EB_SHN_ABS, false, 0x1234, 0 };
    s.sym[k++] = (eb_symbol_t){ "big_bss",        EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_OBJECT), 0, EB_S_BSS, false, 0, 0x100 };
    s.sym[k++] = (eb_symbol_t){ "never_referenced", EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_NOTYPE), 0, EB_SHN_UNDEF, false, 0, 0 };
    s.sym[k++] = (eb_symbol_t){ "resolver",       EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_GNU_IFUNC), 0, EB_S_TEXT, false, 0x48, 8 };
    s.sym[k++] = (eb_symbol_t){ "tls_var",        EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_TLS),   0, EB_S_DATA, false, 0, 8 };
    s.nsym = k;

    k = 0;
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x01, 11, EB_R_X86_64_PLT32, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x11, 11, EB_R_X86_64_PLT32, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x21, 12, EB_R_X86_64_PLT32, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x31, 3, EB_R_X86_64_PC32, 0xC };            /* .rodata + 0x10 - 4 */
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x39, 5, EB_R_X86_64_PLT32, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x41, 13, EB_R_X86_64_PLT32, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x49, 14, EB_R_X86_64_GOTPCRELX, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x51, 4, EB_R_X86_64_32S, 8 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x5A, 14, EB_R_X86_64_REX_GOTPCRELX, -4 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x62, 3, EB_R_X86_64_32, 0x10 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x6A, 3, EB_R_X86_64_NONE, 0 };
    s.rel[k++] = (eb_rela_t){ EB_S_TEXT, 0x72, 11, EB_R_X86_64_PC64, 0 };
    s.rel[k++] = (eb_rela_t){ EB_S_DATA, 0x00, 7, EB_R_X86_64_64, 0 };
    s.rel[k++] = (eb_rela_t){ EB_S_DATA, 0x08, 11, EB_R_X86_64_64, 0 };
    s.rel[k++] = (eb_rela_t){ EB_S_DEBUG, 0x00, 2, EB_R_X86_64_64, 0 };
    s.rel[k++] = (eb_rela_t){ EB_S_DEBUG, 0x08, 18, EB_R_X86_64_64, 0 };
    s.rel[k++] = (eb_rela_t){ EB_S_DEBUG, 0x10, 3, EB_R_X86_64_32, 4 };
    s.nrel = k;
    return s;
}

/* ---- building ---- */

typedef struct {
    uint32_t name, type, link, info;
    uint64_t flags, addr, off, size, align, entsize;
    const uint8_t *data;              /* what to copy to off (size bytes), or NULL */
    uint8_t *own;                     /* freed with the table */
} eb_fsec_t;

typedef struct { uint8_t *b; uint32_t n, cap; } eb_strs_t;

static inline void eb_strs_init(eb_strs_t *t) {            /* offset 0 is always the empty string */
    t->cap = 64; t->b = (uint8_t *)calloc(1, t->cap); assert(t->b); t->n = 1;
}

static inline uint32_t eb_strs_add(eb_strs_t *t, const char *s) {
    if (!s || !*s) return 0;
    const size_t l = strlen(s) + 1;
    if (t->n + l > t->cap) { t->cap = (t->n + (uint32_t)l) * 2 + 64; t->b = (uint8_t *)realloc(t->b, t->cap); assert(t->b); }
    const uint32_t at = t->n;
    memcpy(t->b + at, s, l);
    t->n += (uint32_t)l;
    return at;
}

static inline uint64_t eb_align_up(uint64_t v, uint64_t a) { return a > 1 ? (v + a - 1) / a * a : v; }

static inline eb_file_t eb_build(const eb_spec_t *sp, eb_layout_t *Lout) {
    eb_layout_t L;
    memset(&L, 0, sizeof L);
    const uint32_t U = (uint32_t)sp->nsec, P = sp->pad_sections;

    /* which targets have relocations, in order of first mention */
    uint32_t tgt[EB_MAX_RELSEC], ntgt = 0;
    if (!sp->no_symtab)
        for (int i = 0; i < sp->nrel; i++) {
            uint32_t k = 0;
            while (k < ntgt && tgt[k] != sp->rel[i].target) k++;
            if (k == ntgt) { assert(ntgt < EB_MAX_RELSEC); tgt[ntgt++] = sp->rel[i].target; }
        }
    bool need_shndx = false;
    for (int i = 0; i < sp->nsym; i++) if (sp->sym[i].xindex) need_shndx = true;

    /* the section list: null, user, pad, relocation, symtab, strtab, [shndx], shstrtab */
    uint32_t shnum = 1 + U + P + (sp->no_symtab ? 0 : ntgt + 2 + (need_shndx ? 1 : 0)) + 1;
    uint32_t next = 1 + U + P;
    for (uint32_t k = 0; k < ntgt; k++) L.rela_idx[k] = next++;
    if (!sp->no_symtab) { L.symtab = next++; L.strtab = next++; if (need_shndx) L.shndx_tab = next++; }
    L.shstrtab = next++;
    assert(next == shnum);
    L.shnum = shnum;
    L.nrelsec = ntgt;
    L.nsyms = (uint32_t)sp->nsym + 1;

    eb_fsec_t *fs = (eb_fsec_t *)calloc(shnum, sizeof *fs);
    assert(fs);
    eb_strs_t shstr, str;
    eb_strs_init(&shstr);
    eb_strs_init(&str);

    for (uint32_t i = 0; i < U; i++) {
        const eb_section_t *u = &sp->sec[i];
        eb_fsec_t *f = &fs[1 + i];
        f->name = eb_strs_add(&shstr, u->name);
        f->type = u->type; f->flags = u->flags; f->addr = u->addr; f->align = u->align; f->entsize = u->entsize;
        f->size = u->size; f->link = u->link; f->info = u->info; f->data = u->data;
    }
    const uint32_t padname = P ? eb_strs_add(&shstr, ".pad") : 0;
    for (uint32_t i = 0; i < P; i++) { eb_fsec_t *f = &fs[1 + U + i]; f->name = padname; f->type = EB_SHT_PROGBITS; f->align = 1; f->flags = sp->pad_flags; }

    /* symbols: .strtab, the table, the optional SHNDX table */
    uint32_t first_global = L.nsyms;
    for (int i = 0; i < sp->nsym; i++) if ((sp->sym[i].info >> 4) != EB_STB_LOCAL) { first_global = (uint32_t)i + 1; break; }
    if (!sp->no_symtab) {
        uint8_t *tab = (uint8_t *)calloc(L.nsyms, EB_SYM_SIZE);
        uint8_t *xtab = need_shndx ? (uint8_t *)calloc(L.nsyms, 4) : NULL;
        assert(tab);
        for (int i = 0; i < sp->nsym; i++) {
            const eb_symbol_t *y = &sp->sym[i];
            uint8_t *e = tab + (size_t)(i + 1) * EB_SYM_SIZE;
            eb_w32(e, EB_ST_NAME, eb_strs_add(&str, y->name));
            e[EB_ST_INFO] = y->info;
            e[EB_ST_OTHER] = y->other;
            eb_w16(e, EB_ST_SHNDX, y->xindex ? (uint16_t)EB_SHN_XINDEX : (uint16_t)y->shndx);
            eb_w64(e, EB_ST_VALUE, y->value);
            eb_w64(e, EB_ST_SIZE, y->size);
            if (xtab && y->xindex) eb_w32(xtab, (size_t)(i + 1) * 4, y->shndx);
        }
        eb_fsec_t *f = &fs[L.symtab];
        f->name = eb_strs_add(&shstr, ".symtab"); f->type = EB_SHT_SYMTAB; f->link = L.strtab; f->info = first_global;
        f->align = 8; f->entsize = EB_SYM_SIZE; f->size = (uint64_t)L.nsyms * EB_SYM_SIZE; f->data = tab; f->own = tab;
        f = &fs[L.strtab];
        f->name = eb_strs_add(&shstr, ".strtab"); f->type = EB_SHT_STRTAB; f->align = 1;
        if (need_shndx) {
            f = &fs[L.shndx_tab];
            f->name = eb_strs_add(&shstr, ".symtab_shndx"); f->type = EB_SHT_SYMTAB_SHNDX; f->link = L.symtab; f->align = 4; f->entsize = 4;
            f->size = (uint64_t)L.nsyms * 4; f->data = xtab; f->own = xtab;
        }
        /* relocation sections: entries grouped by target, in the order the description gives them */
        for (uint32_t k = 0; k < ntgt; k++) {
            uint32_t n = 0;
            for (int i = 0; i < sp->nrel; i++) if (sp->rel[i].target == tgt[k]) n++;
            L.rela_target[k] = tgt[k]; L.rela_n[k] = n;
            uint8_t *rt = (uint8_t *)calloc(n ? n : 1, EB_RELA_SIZE);
            uint32_t j = 0;
            for (int i = 0; i < sp->nrel; i++) {
                if (sp->rel[i].target != tgt[k]) continue;
                uint8_t *e = rt + (size_t)j * EB_RELA_SIZE;
                eb_w64(e, EB_R_OFFSET, sp->rel[i].offset);
                eb_w64(e, EB_R_INFO, EB_R_INFO_OF(sp->rel[i].sym, sp->rel[i].type));
                eb_w64(e, EB_R_ADDEND, (uint64_t)sp->rel[i].addend);
                j++;
            }
            char nm[80];
            const char *tn = tgt[k] >= 1 && tgt[k] <= U ? sp->sec[tgt[k] - 1].name : ".x";       /* ".x" for a target the description does not have */
            snprintf(nm, sizeof nm, ".rela%s", tn ? tn : "");
            f = &fs[L.rela_idx[k]];
            f->name = eb_strs_add(&shstr, nm); f->type = EB_SHT_RELA; f->flags = EB_SHF_INFO_LINK; f->link = L.symtab; f->info = tgt[k];
            f->align = 8; f->entsize = EB_RELA_SIZE; f->size = (uint64_t)n * EB_RELA_SIZE; f->data = rt; f->own = rt;
        }
    }
    {
        eb_fsec_t *f = &fs[L.shstrtab];
        f->name = eb_strs_add(&shstr, ".shstrtab"); f->type = EB_SHT_STRTAB; f->align = 1;
    }
    if (!sp->no_symtab) { fs[L.strtab].size = str.n; fs[L.strtab].data = str.b; }
    fs[L.shstrtab].size = shstr.n; fs[L.shstrtab].data = shstr.b;
    L.strtab_size = str.n; L.shstrtab_size = shstr.n;

    /* where the bytes go: header, then each section's contents in order, then the section header table */
    uint64_t cur = EB_EHDR_SIZE;
    for (uint32_t i = 1; i < shnum; i++) {
        eb_fsec_t *f = &fs[i];
        if (f->type == EB_SHT_NOBITS) { f->off = cur; continue; }
        if (f->size == 0) { f->off = 0; continue; }
        assert(f->data && "a section with contents needs data");
        cur = eb_align_up(cur, f->align > 16 ? 16 : f->align);
        f->off = cur;
        cur += f->size;
    }
    const uint64_t shoff = eb_align_up(cur, 8);
    const uint64_t total = shoff + (uint64_t)shnum * EB_SHDR_SIZE;
    uint8_t *b = (uint8_t *)calloc(1, (size_t)total);
    assert(b);

    for (uint32_t i = 1; i < shnum; i++) if (fs[i].data && fs[i].size && fs[i].type != EB_SHT_NOBITS) memcpy(b + fs[i].off, fs[i].data, (size_t)fs[i].size);

    /* e_shnum is 0 when the count is SHN_LORESERVE or more (then section 0's sh_size holds it), and e_shstrndx is
     * SHN_XINDEX when the index is (then section 0's sh_link holds it); ext_numbering uses both forms regardless */
    const bool big_count = sp->ext_numbering || shnum >= EB_SHN_LORESERVE;
    const bool big_index = sp->ext_numbering || L.shstrtab >= EB_SHN_LORESERVE;
    for (uint32_t i = 0; i < shnum; i++) {
        uint8_t *h = b + shoff + (size_t)i * EB_SHDR_SIZE;
        const eb_fsec_t *f = &fs[i];
        eb_w32(h, EB_SH_NAME, f->name); eb_w32(h, EB_SH_TYPE, f->type); eb_w64(h, EB_SH_FLAGS, f->flags); eb_w64(h, EB_SH_ADDR, f->addr);
        eb_w64(h, EB_SH_OFFSET, f->off); eb_w64(h, EB_SH_SIZE, f->size); eb_w32(h, EB_SH_LINK, f->link); eb_w32(h, EB_SH_INFO, f->info);
        eb_w64(h, EB_SH_ADDRALIGN, f->align); eb_w64(h, EB_SH_ENTSIZE, f->entsize);
    }
    if (big_count) eb_w64(b, shoff + EB_SH_SIZE, shnum);
    if (big_index) eb_w32(b, shoff + EB_SH_LINK, L.shstrtab);

    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[EB_EI_CLASS] = sp->ei_class; b[EB_EI_DATA] = sp->ei_data; b[EB_EI_VERSION] = 1;
    eb_w16(b, EB_E_TYPE, sp->etype); eb_w16(b, EB_E_MACHINE, sp->machine); eb_w32(b, EB_E_VERSION, 1);
    eb_w64(b, EB_E_ENTRY, sp->entry); eb_w64(b, EB_E_SHOFF, shoff);
    eb_w16(b, EB_E_EHSIZE, EB_EHDR_SIZE); eb_w16(b, EB_E_SHENTSIZE, EB_SHDR_SIZE);
    eb_w16(b, EB_E_SHNUM, big_count ? 0 : (uint16_t)shnum);
    eb_w16(b, EB_E_SHSTRNDX, big_index ? (uint16_t)EB_SHN_XINDEX : (uint16_t)L.shstrtab);

    /* the layout report */
    L.shoff = (uint32_t)shoff;
    for (uint32_t i = 0; i < shnum && i < EB_LAYOUT_SECS; i++) { L.sec_off[i] = (uint32_t)fs[i].off; L.sec_size[i] = (uint32_t)fs[i].size; }
    if (!sp->no_symtab) {
        L.sym_off = (uint32_t)fs[L.symtab].off; L.strtab_off = (uint32_t)fs[L.strtab].off;
        if (need_shndx) L.shndx_off = (uint32_t)fs[L.shndx_tab].off;
        for (uint32_t k = 0; k < ntgt; k++) L.rela_off[k] = (uint32_t)fs[L.rela_idx[k]].off;
        for (int i = 0; i < sp->nrel; i++) {
            uint32_t k = 0, j = 0;
            while (tgt[k] != sp->rel[i].target) k++;
            for (int m = 0; m < i; m++) if (sp->rel[m].target == sp->rel[i].target) j++;
            L.rel_off[i] = L.rela_off[k] + j * EB_RELA_SIZE;
        }
    }
    L.shstrtab_off = (uint32_t)fs[L.shstrtab].off;

    for (uint32_t i = 0; i < shnum; i++) free(fs[i].own);
    free(fs); free(shstr.b); free(str.b);
    if (Lout) *Lout = L;
    return (eb_file_t){ b, (size_t)total };
}

static inline void eb_free(eb_file_t *f) { free(f->b); f->b = NULL; f->n = 0; }
static inline uint8_t *eb_copy(const uint8_t *b, size_t n) { uint8_t *p = (uint8_t *)malloc(n ? n : 1); assert(p); if (n) memcpy(p, b, n); return p; }
static inline bool eb_write(const char *path, const eb_file_t *f) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    const bool ok = fwrite(f->b, 1, f->n, fp) == f->n;
    return fclose(fp) == 0 && ok;
}

#endif /* CBAE_TEST_ELF_BUILDER_H */
