/**
 * @file elf_loader.c
 * @brief ELF64 parser: a relocatable object (a Linux kernel module) or a linked file into a
 *        cbae_binary_image_t. The model it produces is described in elf_loader.h.
 *
 * Layout follows the gABI and the x86-64 psABI. The file is untrusted, so the rules are those of the PE
 * loader (see pe_loader.c and loader_util.h):
 *
 *  - Every field is read at its documented offset by byte assembly. There is no struct laid over the
 *    file. (The old loader's packed structs were read through casts, took an entry size from the file
 *    and used it for the count but not for the stride, and so read far past the table.)
 *  - Every table is bounded by the bytes the file really holds: a section's contents stop at the end of
 *    the file, a string stops at the end of its table, a table with n entries must have the bytes for n
 *    entries. Sizes and offsets that would wrap are never added.
 *  - Each table is walked twice by the same code, a plan pass that only counts and a fill pass that
 *    writes into arrays sized for exactly that count, so the two cannot disagree and the image's arena
 *    is sized from the file instead of being a fixed 8 MiB.
 *  - What had to be clamped, skipped or cut is recorded as a note on the image, never silently.
 */
#include "loader/elf_loader.h"
#include "loader_util.h"
#include "platform/file_io.h"
#include "platform/logging.h"
#include "platform/string_pool.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the format: sizes and values from the ELF gABI and the x86-64 psABI ---- */
#define ELF_EHDR_SIZE     64
#define ELF_SHDR_SIZE     64
#define ELF_SYM_SIZE      24
#define ELF_RELA_SIZE     24
#define ELFCLASS64        2
#define ELFDATA2LSB       1
#define EV_CURRENT        1
#define ET_REL            1
#define ET_EXEC           2
#define ET_DYN            3
#define EM_X86_64         62
#define EM_AARCH64        183
#define SHT_NULL          0
#define SHT_SYMTAB        2
#define SHT_STRTAB        3
#define SHT_RELA          4
#define SHT_NOBITS        8
#define SHT_REL           9
#define SHT_SYMTAB_SHNDX  18
#define SHF_WRITE         0x1u
#define SHF_ALLOC         0x2u
#define SHF_EXECINSTR     0x4u
#define STB_LOCAL         0
#define STB_GLOBAL        1
#define STB_WEAK          2
#define STB_GNU_UNIQUE    10
#define STT_OBJECT        1
#define STT_FUNC          2
#define STT_SECTION       3
#define STT_FILE          4
#define STT_COMMON        5
#define STT_TLS           6
#define STT_GNU_IFUNC     10
#define SHN_UNDEF         0u
#define SHN_LORESERVE     0xFF00u
#define SHN_ABS           0xFFF1u
#define SHN_COMMON        0xFFF2u
#define SHN_XINDEX        0xFFFFu
#define R_X86_64_NONE     0
#define R_X86_64_64       1
#define R_X86_64_PC32     2
#define R_X86_64_PLT32    4
#define R_X86_64_GOTPCREL 9
#define R_X86_64_32       10
#define R_X86_64_32S      11
#define R_X86_64_GOTPCRELX     41
#define R_X86_64_REX_GOTPCRELX 42

/* ---- what this loader decides ---- */
#define ELF_PAGE            0x1000u
#define ELF_MAX_ALIGN       ((uint64_t)1 << 20)   /* a larger sh_addralign is cut to this */
#define ELF_MAX_VSIZE       ((uint64_t)1 << 40)   /* the most address space one section is given */
#define ELF_REL_LIMIT       ((uint64_t)1 << 62)   /* the layout of a relocatable object must end below this */
#define ELF_MAX_ARENA_BYTES ((uint64_t)1 << 30)
#define ELF_MAX_NOTES_BEFORE 24

/* what the walkers count, to report once at the end instead of once per occurrence */
typedef enum {
    N_SEC_NAME_CUT, N_SEC_NAME_BAD, N_SEC_TRUNCATED, N_LAYOUT_ALIGN_BAD, N_LAYOUT_ALIGN_CUT, N_LAYOUT_SIZE_CUT, N_LAYOUT_WRAP,
    N_SYM_NAME_CUT, N_SYM_NAME_BAD, N_SYM_BAD_SHNDX, N_SYM_RESERVED_SHNDX, N_SYM_UNMAPPED, N_SYM_OUT_OF_SECTION, N_SYM_XINDEX_MISSING,
    N_KSYM_UNTERMINATED,
    N_REL_SECTION, N_RELA_ENTSIZE, N_RELA_TRUNCATED, N_RELA_BAD_TARGET, N_RELA_UNLOADED, N_RELOC_OUTSIDE, N_RELOC_BAD_SYMBOL,
    N_MODINFO_CUT,
    N_COUNT
} note_id_t;

typedef struct {
    uint32_t name, type, link, info;
    uint64_t flags, addr, off, size, align, entsize;
} shdr_t;

typedef struct {
    const uint8_t       *f;
    size_t               n;
    uint16_t             etype, machine;
    uint64_t             entry, shoff;
    uint32_t             shnum;                  /* the real count, after extended numbering */
    span_t               shstr;                  /* the section name table's bytes in the file */
    uint64_t            *va;                     /* [shnum] address of each section, 0 when it is not loaded */
    uint32_t             symtab;                 /* section index of the symbol table that is read, 0 if none */
    uint64_t             nsyms;                  /* its entries, the null entry included */
    const uint8_t       *sym;                    /* where they start */
    span_t               symstr;
    span_t               shndx;                  /* SHT_SYMTAB_SHNDX contents for that table */
    uint32_t             modinfo, ksym;          /* section index of .modinfo and __ksymtab_strings, 0 if absent */
    uint8_t             *seen;                   /* one bit per symbol: it already has an import */
    cbae_string_pool_t  *defined;                /* names of the defined global and weak symbols, if __ksymtab_strings exists */
    cbae_binary_image_t *img;
    bool                 quiet;                  /* plan pass: count, do not note */
    uint64_t             cnt[N_COUNT];
    char                 pre[ELF_MAX_NOTES_BEFORE][CBAE_IMAGE_NOTE_LEN];
    uint32_t             npre;
} elf_ctx_t;

#define COUNT(c, id)      do { if (!(c)->quiet) (c)->cnt[id]++; } while (0)
#define COUNT_N(c, id, k) do { if (!(c)->quiet) (c)->cnt[id] += (k); } while (0)

/* a note made before the image exists is kept, and given to it when it does */
static void elf_note(elf_ctx_t *c, const char *fmt, ...) CBAE_PRINTF_FORMAT(2, 3);
static void elf_note(elf_ctx_t *c, const char *fmt, ...) {
    char text[CBAE_IMAGE_NOTE_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    if (c->img) cbae_image_note(c->img, "%s", text);
    else if (c->npre < ELF_MAX_NOTES_BEFORE) memcpy(c->pre[c->npre++], text, sizeof text);
}

/* ---- section headers ---- */

/* Header i, 0 <= i < shnum. parse_headers has checked that the whole table is in the file. */
static shdr_t shdr(const elf_ctx_t *c, uint32_t i) {
    const uint8_t *h = c->f + c->shoff + (size_t)i * ELF_SHDR_SIZE;
    shdr_t s;
    s.name = rd32(h);       s.type = rd32(h + 4);   s.flags = rd64(h + 8);   s.addr = rd64(h + 16);
    s.off = rd64(h + 24);   s.size = rd64(h + 32);  s.link = rd32(h + 40);   s.info = rd32(h + 44);
    s.align = rd64(h + 48); s.entsize = rd64(h + 56);
    return s;
}

/* The bytes of a section that are in the file: none for SHT_NOBITS, and never past the end of the file. */
static span_t sec_bytes(const elf_ctx_t *c, const shdr_t *s) {
    if (s->type == SHT_NOBITS || s->off >= c->n) return (span_t){ NULL, 0 };
    const uint64_t avail = c->n - s->off;
    const uint64_t take = s->size < avail ? s->size : avail;
    return (span_t){ take ? c->f + s->off : NULL, (size_t)take };
}

/* The name of section idx in dst; "" for none, or for one the name table does not hold. */
static str_res_t sec_name_raw(const elf_ctx_t *c, uint32_t idx, char *dst, size_t cap) {
    dst[0] = '\0';
    if (idx == 0 || idx >= c->shnum) return STR_UNMAPPED;
    const uint32_t off = rd32(c->f + c->shoff + (size_t)idx * ELF_SHDR_SIZE);
    if (off == 0) return STR_OK;                                /* no name: legal */
    if (off >= c->shstr.n) return STR_UNMAPPED;
    return read_str((span_t){ c->shstr.p + off, c->shstr.n - off }, dst, cap);
}

/* The address range of a loaded section, as the image will say it: cut at ELF_MAX_VSIZE and so that
 * addr + size does not wrap. */
static uint64_t sec_vsize(const shdr_t *s, uint64_t va) {
    uint64_t v = s->size > ELF_MAX_VSIZE ? ELF_MAX_VSIZE : s->size;
    if (va > UINT64_MAX - v) v = UINT64_MAX - va;
    return v;
}

static bool is_pow2(uint64_t a) { return a && !(a & (a - 1)); }

/* ---- headers ---- */

static cbae_err_t parse_headers(elf_ctx_t *c) {
    const uint8_t *f = c->f;
    const size_t n = c->n;
    if (n < ELF_EHDR_SIZE) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not an ELF file: %zu bytes is too small for an ELF header", n);
    if (f[0] != 0x7F || f[1] != 'E' || f[2] != 'L' || f[3] != 'F') CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not an ELF file: no ELF magic");
    if (f[4] != ELFCLASS64) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not an ELF64 file (EI_CLASS is %u)", f[4]);
    if (f[5] != ELFDATA2LSB) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not a little-endian ELF file (EI_DATA is %u)", f[5]);
    if (f[6] != EV_CURRENT) elf_note(c, "e_ident gives ELF version %u, not 1", f[6]);

    c->etype = rd16(f + 16);
    c->machine = rd16(f + 18);
    const uint32_t version = rd32(f + 20);
    c->entry = rd64(f + 24);
    c->shoff = rd64(f + 40);
    const uint16_t ehsize = rd16(f + 52), shentsize = rd16(f + 58), shnum16 = rd16(f + 60), shstrndx16 = rd16(f + 62);
    if (version != EV_CURRENT) elf_note(c, "e_version is %u, not 1", version);
    if (ehsize != ELF_EHDR_SIZE) elf_note(c, "e_ehsize is %u, not %d", ehsize, ELF_EHDR_SIZE);
    if (c->etype != ET_REL && c->etype != ET_EXEC && c->etype != ET_DYN)
        elf_note(c, "e_type %u is not a relocatable, executable or shared object file", c->etype);
    if (c->machine != EM_X86_64 && c->machine != EM_AARCH64) elf_note(c, "machine type %u is neither x86-64 nor AArch64", c->machine);

    if (c->shoff == 0) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "the file has no section header table (e_shoff is 0)");
    if (shentsize != ELF_SHDR_SIZE) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "e_shentsize is %u: an ELF64 section header is %d bytes", shentsize, ELF_SHDR_SIZE);
    if (c->shoff > n || n - c->shoff < ELF_SHDR_SIZE)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "the section header table (e_shoff 0x%llx) is outside the %zu-byte file", (unsigned long long)c->shoff, n);

    /* e_shnum is 0 when there are SHN_LORESERVE or more sections: the count is then in section 0's sh_size */
    uint64_t shnum = shnum16 ? shnum16 : rd64(f + c->shoff + 32);
    if (shnum == 0) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "the section header table has no sections");
    if (shnum > (n - c->shoff) / ELF_SHDR_SIZE)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "the section header table (%llu entries at 0x%llx) runs past the end of the %zu-byte file",
                        (unsigned long long)shnum, (unsigned long long)c->shoff, n);
    c->shnum = (uint32_t)shnum;

    /* e_shstrndx is SHN_XINDEX when the index is SHN_LORESERVE or more: it is then in section 0's sh_link */
    const uint32_t shstrndx = shstrndx16 == SHN_XINDEX ? rd32(f + c->shoff + 40) : shstrndx16;
    if (shstrndx != 0) {
        if (shstrndx >= c->shnum) elf_note(c, "e_shstrndx %u is outside the %u sections: the sections have no names", shstrndx, c->shnum);
        else {
            const shdr_t ss = shdr(c, shstrndx);
            if (ss.type != SHT_STRTAB) elf_note(c, "the section name table (section %u) is not of type SHT_STRTAB", shstrndx);
            c->shstr = sec_bytes(c, &ss);
            if (c->shstr.n && c->shstr.p[c->shstr.n - 1] != 0) elf_note(c, "the section name table does not end with a NUL");
        }
    }
    return CBAE_OK;
}

/* ---- where the loaded sections go ---- */

/* c->va[i]: ET_REL has no addresses, so the SHF_ALLOC sections are placed one after another from
 * CBAE_ELF_REL_BASE, each on a page boundary (or its sh_addralign, if larger); a linked file keeps sh_addr. */
static cbae_err_t layout(elf_ctx_t *c) {
    c->va = (uint64_t *)calloc(c->shnum, sizeof(uint64_t));
    if (!c->va) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot allocate the address table for %u sections", c->shnum);
    uint64_t cursor = CBAE_ELF_REL_BASE;
    for (uint32_t i = 1; i < c->shnum; i++) {
        const shdr_t s = shdr(c, i);
        if (s.type == SHT_NULL || !(s.flags & SHF_ALLOC)) continue;
        if (s.size > ELF_MAX_VSIZE) COUNT(c, N_LAYOUT_SIZE_CUT);
        if (c->etype != ET_REL) {
            c->va[i] = s.addr;
            if (s.addr > UINT64_MAX - (s.size > ELF_MAX_VSIZE ? ELF_MAX_VSIZE : s.size)) COUNT(c, N_LAYOUT_WRAP);
            continue;
        }
        uint64_t a = s.align;
        if (a > 1 && !is_pow2(a)) { COUNT(c, N_LAYOUT_ALIGN_BAD); a = 1; }
        if (a > ELF_MAX_ALIGN) { COUNT(c, N_LAYOUT_ALIGN_CUT); a = ELF_MAX_ALIGN; }
        if (a < ELF_PAGE) a = ELF_PAGE;
        const uint64_t start = (cursor + a - 1) / a * a;                       /* cursor < 2^62 and a <= 2^20: no overflow */
        const uint64_t size = s.size > ELF_MAX_VSIZE ? ELF_MAX_VSIZE : s.size;
        if (start > ELF_REL_LIMIT || size > ELF_REL_LIMIT - start)
            CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "the loaded sections of this object do not fit in the address space (section %u)", i);
        c->va[i] = start;
        cursor = start + size;
    }
    return CBAE_OK;
}

/* ---- the symbol table, and the sections the loader looks for by name ---- */

/* The section index of symbol i (0 < i < nsyms): st_shndx, or for SHN_XINDEX the entry of the extended index
 * table. When the table is needed and does not have the entry, *missing is set (if given) and the result is
 * SHN_XINDEX, a reserved index that places nothing. One function decides this for every consumer, so a symbol
 * cannot be an import to the relocation walker and a definition to the symbol walker. */
static uint32_t sym_shndx(const elf_ctx_t *c, uint64_t i, bool *missing) {
    const uint16_t s16 = rd16(c->sym + i * ELF_SYM_SIZE + 6);
    if (s16 != SHN_XINDEX) return s16;
    if (i < c->shndx.n / 4) return rd32(c->shndx.p + i * 4);
    if (missing) *missing = true;
    return SHN_XINDEX;
}

/* An undefined symbol that is neither a file nor a section symbol: something the module needs from outside. */
static bool sym_is_import(const elf_ctx_t *c, uint64_t i) {
    const unsigned stype = c->sym[i * ELF_SYM_SIZE + 4] & 0xF;
    return sym_shndx(c, i, NULL) == SHN_UNDEF && stype != STT_FILE && stype != STT_SECTION;
}

static bool defined_export(const elf_ctx_t *c, uint64_t i) {
    const uint8_t *e = c->sym + i * ELF_SYM_SIZE;
    const unsigned stype = e[4] & 0xF, bind = e[4] >> 4;
    return sym_shndx(c, i, NULL) != SHN_UNDEF && stype != STT_SECTION && stype != STT_FILE && bind != STB_LOCAL;
}

/* a name in the symbol string table, cut to cap - 1 bytes; "" if it has none or points outside the table.
 * @p report: count a cut or bad name for the notes. Only the symbol walker does; an import entry and the table
 * of defined names copy a name the walker has already counted. */
static void sym_name(elf_ctx_t *c, uint32_t off, char *dst, size_t cap, bool report) {
    dst[0] = '\0';
    if (off == 0) return;
    if (off >= c->symstr.n) { if (report) COUNT(c, N_SYM_NAME_BAD); return; }
    if (read_str((span_t){ c->symstr.p + off, c->symstr.n - off }, dst, cap) == STR_CUT && report) COUNT(c, N_SYM_NAME_CUT);
}

static cbae_err_t find_tables(elf_ctx_t *c) {
    uint32_t extra_symtabs = 0;
    for (uint32_t i = 1; i < c->shnum; i++) {
        const shdr_t s = shdr(c, i);
        if (s.type == SHT_SYMTAB) { if (c->symtab) extra_symtabs++; else c->symtab = i; }
        char nm[CBAE_SEC_NAME_MAX];
        if (!c->modinfo || !c->ksym) {
            sec_name_raw(c, i, nm, sizeof nm);
            if (!c->modinfo && strcmp(nm, ".modinfo") == 0) c->modinfo = i;
            if (!c->ksym && strcmp(nm, "__ksymtab_strings") == 0) c->ksym = i;
        }
    }
    if (extra_symtabs) elf_note(c, "the file has %u more symbol tables: only the first (section %u) is read", extra_symtabs, c->symtab);
    if (!c->symtab) return CBAE_OK;

    const shdr_t st = shdr(c, c->symtab);
    if (st.entsize != 0 && st.entsize != ELF_SYM_SIZE) {
        elf_note(c, "the symbol table (section %u) has entry size %llu, not %d: no symbols are read", c->symtab, (unsigned long long)st.entsize, ELF_SYM_SIZE);
        c->symtab = 0;
        return CBAE_OK;
    }
    const span_t bytes = sec_bytes(c, &st);
    c->nsyms = bytes.n / ELF_SYM_SIZE;
    c->sym = bytes.p;
    if (st.size / ELF_SYM_SIZE > c->nsyms) elf_note(c, "the symbol table has %llu entries but only %llu are in the file", (unsigned long long)(st.size / ELF_SYM_SIZE), (unsigned long long)c->nsyms);
    else if (st.size % ELF_SYM_SIZE) elf_note(c, "the symbol table's size is not a multiple of %d: the last %llu bytes are ignored", ELF_SYM_SIZE, (unsigned long long)(st.size % ELF_SYM_SIZE));
    if (c->nsyms == 0) { c->symtab = 0; return CBAE_OK; }

    if (st.link == 0 || st.link >= c->shnum) elf_note(c, "the symbol table's string table (sh_link %u) does not exist: symbols have no names", st.link);
    else {
        const shdr_t ss = shdr(c, st.link);
        if (ss.type != SHT_STRTAB) elf_note(c, "the symbol string table (section %u) is not of type SHT_STRTAB", st.link);
        c->symstr = sec_bytes(c, &ss);
        if (c->symstr.n && c->symstr.p[c->symstr.n - 1] != 0) elf_note(c, "the symbol string table does not end with a NUL");
    }
    for (uint32_t i = 1; i < c->shnum; i++) {                  /* the extended section index table of this symbol table */
        const shdr_t s = shdr(c, i);
        if (s.type == SHT_SYMTAB_SHNDX && s.link == c->symtab) { c->shndx = sec_bytes(c, &s); break; }
    }

    c->seen = (uint8_t *)calloc((size_t)((c->nsyms + 7) / 8), 1);
    if (!c->seen) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot allocate the import table for %llu symbols", (unsigned long long)c->nsyms);
    if (c->ksym) {                                             /* __ksymtab_strings names are exports unless the table already has them */
        cbae_err_t err = cbae_string_pool_init(&c->defined, (size_t)(c->nsyms < 4096 ? c->nsyms : 4096));
        if (err != CBAE_OK) CBAE_RETURN_ERR(err, "cannot allocate the name table for %llu symbols", (unsigned long long)c->nsyms);
        for (uint64_t i = 1; i < c->nsyms; i++) {
            if (!defined_export(c, i)) continue;
            char nm[CBAE_SYM_NAME_MAX];
            sym_name(c, rd32(c->sym + i * ELF_SYM_SIZE), nm, sizeof nm, false);
            if (!cbae_string_pool_intern(c->defined, nm)) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot record the name of symbol %llu", (unsigned long long)i);
        }
    }
    return CBAE_OK;
}

/* ---- the tables: each is walked by one function that either counts or fills ---- */

static uint32_t sec_flags(const shdr_t *s) {
    uint32_t f = 0;
    if (s->flags & SHF_ALLOC) {
        f |= CBAE_SEC_READ;
        if (s->flags & SHF_EXECINSTR) f |= CBAE_SEC_EXEC;
        if (s->flags & SHF_WRITE) f |= CBAE_SEC_WRITE;
    }
    if (s->type == SHT_NOBITS) f |= CBAE_SEC_BSS;
    if (s->type == SHT_RELA || s->type == SHT_REL) f |= CBAE_SEC_RELOC;
    return f;
}

static void walk_sections(elf_ctx_t *c, sink_t *k) {
    for (uint32_t i = 1; i < c->shnum; i++) {
        const shdr_t s = shdr(c, i);
        if (s.type == SHT_NULL) continue;
        cbae_section_t *o = (cbae_section_t *)sink_slot(k, sizeof *o);
        if (!o) continue;
        memset(o, 0, sizeof *o);
        const str_res_t r = sec_name_raw(c, i, o->name, sizeof o->name);
        if (r == STR_CUT) COUNT(c, N_SEC_NAME_CUT);
        else if (r == STR_UNMAPPED) COUNT(c, N_SEC_NAME_BAD);
        const bool loaded = (s.flags & SHF_ALLOC) != 0;
        span_t b = sec_bytes(c, &s);
        if (s.type != SHT_NOBITS && b.n < s.size) COUNT(c, N_SEC_TRUNCATED);
        uint64_t backed = b.n;
        o->virt_addr = loaded ? c->va[i] : 0;
        o->virt_size = loaded ? sec_vsize(&s, c->va[i]) : 0;
        if (loaded && backed > o->virt_size) backed = o->virt_size;
        o->file_offset = s.off;
        o->file_size = backed;
        o->flags = sec_flags(&s);
        o->data = backed ? b.p : NULL;
    }
}

static cbae_sym_binding_t map_bind(unsigned b) {
    return b == STB_GLOBAL || b == STB_GNU_UNIQUE ? CBAE_BIND_GLOBAL : b == STB_WEAK ? CBAE_BIND_WEAK : CBAE_BIND_LOCAL;
}

static cbae_sym_kind_t map_kind(unsigned t) {
    switch (t) {
    case STT_FUNC: case STT_GNU_IFUNC:                return CBAE_KIND_FUNCTION;
    case STT_OBJECT: case STT_COMMON: case STT_TLS:   return CBAE_KIND_OBJECT;
    case 0: case STT_SECTION: case STT_FILE:          return CBAE_KIND_NOTYPE;
    default:                                          return CBAE_KIND_UNKNOWN;
    }
}

/* ELF symbols k + 1, k = 0..: img->symbols[k]. Undefined symbols are imports, defined global and weak
 * ones exports. See elf_loader.h for the address rules. */
static void walk_symbols(elf_ctx_t *c, sink_t *k) {
    for (uint64_t i = 1; i < c->nsyms; i++) {
        cbae_symbol_t *o = (cbae_symbol_t *)sink_slot(k, sizeof *o);
        if (!o) continue;
        const uint8_t *e = c->sym + i * ELF_SYM_SIZE;
        const uint32_t st_name = rd32(e);
        const unsigned stype = e[4] & 0xF, bind = e[4] >> 4;
        const uint64_t value = rd64(e + 8), size = rd64(e + 16);

        /* SHN_ABS, SHN_COMMON and the other reserved values mean something only in st_shndx itself. An index that
         * came from SHT_SYMTAB_SHNDX is a section number, whatever its value (a file with 70000 sections has
         * sections 0xFF00 and above), and one that is not in the table stays SHN_XINDEX and places nothing. */
        const bool via_table = rd16(e + 6) == SHN_XINDEX;
        bool xmissing = false;
        const uint32_t shndx = sym_shndx(c, i, &xmissing);
        if (xmissing) COUNT(c, N_SYM_XINDEX_MISSING);
        memset(o, 0, sizeof *o);
        o->table_index = k->n - 1;
        o->binding = map_bind(bind);
        o->kind = map_kind(stype);
        o->size = size;
        /* the field is 16 bits: a number that does not fit, or that would read as a reserved value, is SHN_XINDEX */
        o->section_idx = (via_table && shndx >= SHN_LORESERVE) || shndx > 0xFFFF ? (uint16_t)SHN_XINDEX : (uint16_t)shndx;
        if (stype == STT_FILE) o->type = CBAE_SYM_FILE;
        else if (stype == STT_SECTION) o->type = CBAE_SYM_SECTION;
        else if (shndx == SHN_UNDEF) o->type = CBAE_SYM_IMPORT;
        else o->type = o->binding == CBAE_BIND_LOCAL ? CBAE_SYM_LOCAL : CBAE_SYM_EXPORT;

        if (o->type == CBAE_SYM_SECTION) sec_name_raw(c, shndx, o->name, sizeof o->name);     /* st_name is 0 by convention */
        else sym_name(c, st_name, o->name, sizeof o->name, true);
        if (o->type == CBAE_SYM_IMPORT) memcpy(o->source, "kernel", sizeof "kernel");

        o->address = CBAE_ADDR_INVALID;
        if (o->type == CBAE_SYM_IMPORT || o->type == CBAE_SYM_FILE || stype == STT_COMMON || stype == STT_TLS || (!via_table && shndx == SHN_COMMON)) {
            /* nothing is placed: no address */
        } else if (!via_table && shndx == SHN_ABS) {
            o->address = value;
        } else if (xmissing) {
            /* counted above */
        } else if (!via_table && shndx >= SHN_LORESERVE) {
            COUNT(c, N_SYM_RESERVED_SHNDX);
        } else if (shndx >= c->shnum) {
            COUNT(c, N_SYM_BAD_SHNDX);
        } else {
            const shdr_t s = shdr(c, shndx);
            if (s.type == SHT_NULL || !(s.flags & SHF_ALLOC)) COUNT(c, N_SYM_UNMAPPED);
            else if (c->etype != ET_REL) o->address = value;                             /* a linked file's value is the address */
            else if (value > sec_vsize(&s, c->va[shndx])) COUNT(c, N_SYM_OUT_OF_SECTION);
            else o->address = c->va[shndx] + value;
        }
    }
}

/* A name in __ksymtab_strings that no defined symbol carries is an export whose symbol is missing (the
 * module was stripped): it is listed, without an address. */
static void walk_ksymtab(elf_ctx_t *c, sink_t *k) {
    if (!c->ksym) return;
    const shdr_t s = shdr(c, c->ksym);
    const span_t b = sec_bytes(c, &s);
    const uint8_t *p = b.p, *end = b.p ? b.p + b.n : NULL;
    while (p && p < end) {
        if (*p == 0) { p++; continue; }
        const uint8_t *z = (const uint8_t *)memchr(p, 0, (size_t)(end - p));
        const size_t len = z ? (size_t)(z - p) : (size_t)(end - p);
        if (!z) COUNT(c, N_KSYM_UNTERMINATED);
        const size_t cut = len < CBAE_SYM_NAME_MAX - 1 ? len : CBAE_SYM_NAME_MAX - 1;
        if (len > cut) COUNT(c, N_SYM_NAME_CUT);
        if (!c->defined || !cbae_string_pool_find_n(c->defined, (const char *)p, cut)) {
            cbae_symbol_t *o = (cbae_symbol_t *)sink_slot(k, sizeof *o);
            if (o) {
                memset(o, 0, sizeof *o);
                memcpy(o->name, p, cut);
                o->type = CBAE_SYM_EXPORT;
                o->binding = CBAE_BIND_GLOBAL;
                o->kind = CBAE_KIND_UNKNOWN;
                o->address = CBAE_ADDR_INVALID;
                o->table_index = k->n - 1;
            }
        }
        p += len + (z ? 1 : 0);
    }
}

static cbae_reloc_type_t map_reloc(uint16_t machine, uint32_t t) {
    if (t == R_X86_64_NONE) return CBAE_RELOC_NOP;
    if (machine != EM_X86_64) return CBAE_RELOC_UNKNOWN;
    switch (t) {
    case R_X86_64_64:    return CBAE_RELOC_64;
    case R_X86_64_PC32:  return CBAE_RELOC_PC32;
    case R_X86_64_PLT32: return CBAE_RELOC_PLT32;
    case R_X86_64_32:    return CBAE_RELOC_ABS32;
    case R_X86_64_32S:   return CBAE_RELOC_32S;
    case R_X86_64_GOTPCREL: case R_X86_64_GOTPCRELX: case R_X86_64_REX_GOTPCRELX: return CBAE_RELOC_GOTPCREL;
    default:             return CBAE_RELOC_UNKNOWN;
    }
}

/* Relocations, and, from the same walk, the imports they name. */
static void walk_relocs(elf_ctx_t *c, sink_t *rk, sink_t *ik) {
    if (c->seen) memset(c->seen, 0, (size_t)((c->nsyms + 7) / 8));
    const bool rel_obj = c->etype == ET_REL;
    for (uint32_t ri = 1; ri < c->shnum; ri++) {
        const shdr_t rs = shdr(c, ri);
        if (rs.type == SHT_REL) { COUNT(c, N_REL_SECTION); continue; }
        if (rs.type != SHT_RELA) continue;
        if (rs.entsize != 0 && rs.entsize != ELF_RELA_SIZE) { COUNT(c, N_RELA_ENTSIZE); continue; }
        const span_t ent = sec_bytes(c, &rs);
        const uint64_t nent = ent.n / ELF_RELA_SIZE;
        if (rs.size / ELF_RELA_SIZE > nent) COUNT(c, N_RELA_TRUNCATED);

        shdr_t ts;
        memset(&ts, 0, sizeof ts);
        const uint32_t tgt = rs.info;
        if (rel_obj) {                                          /* r_offset is an offset in the section sh_info names */
            if (tgt == 0 || tgt >= c->shnum) { COUNT_N(c, N_RELA_BAD_TARGET, nent); continue; }
            ts = shdr(c, tgt);
            if (ts.type == SHT_NULL || !(ts.flags & SHF_ALLOC)) { COUNT_N(c, N_RELA_UNLOADED, nent); continue; }
        }
        const uint64_t tsize = rel_obj ? sec_vsize(&ts, c->va[tgt]) : 0;
        const span_t tbytes = rel_obj ? sec_bytes(c, &ts) : (span_t){ NULL, 0 };
        const bool symok = c->symtab != 0 && rs.link == c->symtab;

        for (uint64_t j = 0; j < nent; j++) {
            const uint8_t *e = ent.p + j * ELF_RELA_SIZE;
            const uint64_t off = rd64(e), info = rd64(e + 8);
            const uint64_t si = info >> 32;
            const uint32_t type = (uint32_t)info;
            uint64_t target_va = off, file_off = CBAE_ADDR_INVALID;
            if (rel_obj) {
                if (off >= tsize) { COUNT(c, N_RELOC_OUTSIDE); continue; }
                target_va = c->va[tgt] + off;
                if (off < tbytes.n) file_off = (uint64_t)(tbytes.p - c->f) + off;
            }
            uint32_t sym_index = CBAE_RELOC_NO_SYMBOL;
            bool import = false;
            if (si != 0) {
                if (symok && si < c->nsyms) {
                    sym_index = (uint32_t)(si - 1);
                    import = sym_is_import(c, si);
                } else {
                    COUNT(c, N_RELOC_BAD_SYMBOL);
                }
            }
            cbae_relocation_t *r = (cbae_relocation_t *)sink_slot(rk, sizeof *r);
            if (r) {
                memset(r, 0, sizeof *r);
                r->target_va = target_va;
                r->file_offset = file_off;
                r->type = map_reloc(c->machine, type);
                r->addend = (int64_t)rd64(e + 16);
                r->sym_index = sym_index;
                r->references_import = import;
                r->table_index = rk->n - 1;
            }
            if (import && !(c->seen[si >> 3] & (1u << (si & 7)))) {
                c->seen[si >> 3] |= (uint8_t)(1u << (si & 7));
                cbae_import_entry_t *im = (cbae_import_entry_t *)sink_slot(ik, sizeof *im);
                if (im) {
                    const uint8_t *se = c->sym + si * ELF_SYM_SIZE;
                    memset(im, 0, sizeof *im);
                    sym_name(c, rd32(se), im->name, sizeof im->name, false);
                    memcpy(im->module, "kernel", sizeof "kernel");
                    im->iat_va = CBAE_ADDR_INVALID;
                    im->rela_offset = file_off;
                    im->rela_type = type;
                    im->state = CBAE_IMPORT_UNRESOLVED;
                    im->table_index = ik->n - 1;
                }
            }
        }
    }
}

/* ---- .modinfo ---- */

static void modinfo_field(elf_ctx_t *c, char *dst, size_t cap, bool *seen, const char *val, size_t len) {
    if (*seen) return;                                          /* the first one wins, as in the kernel's get_modinfo */
    *seen = true;
    const size_t cut = len < cap - 1 ? len : cap - 1;
    memcpy(dst, val, cut);
    dst[cut] = '\0';
    if (len > cut) COUNT(c, N_MODINFO_CUT);
}

static void read_modinfo(elf_ctx_t *c, cbae_binary_image_t *img) {
    if (c->ksym) img->meta.elf.has_ksymtab = true;
    if (!c->modinfo) return;
    const shdr_t s = shdr(c, c->modinfo);
    const span_t b = sec_bytes(c, &s);
    if (!b.p) return;
    bool seen[4] = { false, false, false, false };
    const uint8_t *p = b.p, *end = b.p + b.n;
    while (p < end) {                                           /* NUL-terminated "key=value" strings; zero padding between them is skipped */
        if (*p == 0) { p++; continue; }
        const uint8_t *z = (const uint8_t *)memchr(p, 0, (size_t)(end - p));
        const size_t len = z ? (size_t)(z - p) : (size_t)(end - p);
        const uint8_t *eq = (const uint8_t *)memchr(p, '=', len);
        if (eq) {
            const size_t kl = (size_t)(eq - p);
            const char *v = (const char *)eq + 1;
            const size_t vl = len - kl - 1;
            if (kl == 8 && memcmp(p, "vermagic", 8) == 0)         modinfo_field(c, img->meta.elf.kernel_version, sizeof img->meta.elf.kernel_version, &seen[0], v, vl);
            else if (kl == 7 && memcmp(p, "license", 7) == 0)     modinfo_field(c, img->meta.elf.module_license, sizeof img->meta.elf.module_license, &seen[1], v, vl);
            else if (kl == 6 && memcmp(p, "author", 6) == 0)      modinfo_field(c, img->meta.elf.module_author, sizeof img->meta.elf.module_author, &seen[2], v, vl);
            else if (kl == 11 && memcmp(p, "description", 11) == 0) modinfo_field(c, img->meta.elf.module_description, sizeof img->meta.elf.module_description, &seen[3], v, vl);
        }
        p += len + (z ? 1 : 0);
    }
}

/* ---- assembling the image ---- */

static void emit_notes(const elf_ctx_t *c, cbae_binary_image_t *img) {
#define EMIT(id, text) do { if (c->cnt[id]) cbae_image_note(img, text, (unsigned long long)c->cnt[id]); } while (0)
    EMIT(N_LAYOUT_SIZE_CUT,   "%llu loaded sections are larger than 1 TiB: their address range was cut to 1 TiB");
    EMIT(N_LAYOUT_WRAP,       "%llu loaded sections would run past the top of the address space: their address range was cut");
    EMIT(N_LAYOUT_ALIGN_BAD,  "%llu sections have an alignment that is not a power of two: they are placed on a page boundary");
    EMIT(N_LAYOUT_ALIGN_CUT,  "%llu sections have an alignment above 1 MiB: it was cut to 1 MiB");
    EMIT(N_SEC_NAME_CUT,      "%llu section names are longer than 31 bytes and were cut");
    EMIT(N_SEC_NAME_BAD,      "%llu section names are not in the section name table: those sections have no name");
    EMIT(N_SEC_TRUNCATED,     "%llu sections have bytes beyond the end of the file: only the bytes present are used");
    EMIT(N_SYM_NAME_CUT,      "%llu symbol names are longer than 127 bytes and were cut");
    EMIT(N_SYM_NAME_BAD,      "%llu symbol names are not in the string table: those symbols have no name");
    EMIT(N_SYM_BAD_SHNDX,     "%llu symbols are in a section that does not exist: they have no address");
    EMIT(N_SYM_RESERVED_SHNDX, "%llu symbols have a reserved section index other than ABS and COMMON: they have no address");
    EMIT(N_SYM_UNMAPPED,      "%llu symbols are in sections that are not loaded: they have no address");
    EMIT(N_SYM_OUT_OF_SECTION, "%llu symbols lie beyond the end of their section: they have no address");
    EMIT(N_SYM_XINDEX_MISSING, "%llu symbols need the extended section index table, which is missing or too short: they have no address");
    EMIT(N_KSYM_UNTERMINATED, "the last string of __ksymtab_strings has no terminating NUL (%llu)");
    EMIT(N_REL_SECTION,       "%llu SHT_REL sections (implicit addends) are not read: the x86-64 ABI uses SHT_RELA");
    EMIT(N_RELA_ENTSIZE,      "%llu relocation sections have an entry size other than 24: ignored");
    EMIT(N_RELA_TRUNCATED,    "%llu relocation sections run past the end of the file: only the entries present are read");
    EMIT(N_RELA_BAD_TARGET,   "%llu relocation entries apply to a section that does not exist: ignored");
    EMIT(N_RELA_UNLOADED,     "%llu relocation entries apply to sections that are not loaded (such as .debug_*): ignored");
    EMIT(N_RELOC_OUTSIDE,     "%llu relocations lie beyond the end of the section they patch: ignored");
    EMIT(N_RELOC_BAD_SYMBOL,  "%llu relocations name a symbol that is not in the symbol table that was read: they name no symbol");
    EMIT(N_MODINFO_CUT,       "%llu .modinfo values are longer than their fields and were cut");
#undef EMIT
}

static void ctx_free(elf_ctx_t *c) {
    if (!c) return;
    free(c->va);
    free(c->seen);
    cbae_string_pool_destroy(c->defined);
    free(c);
}

static cbae_err_t load_owned(uint8_t *data, size_t n, const char *name, cbae_binary_image_t **out) {
    elf_ctx_t *c = (elf_ctx_t *)calloc(1, sizeof *c);
    if (!c) { free(data); CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot allocate the ELF parser state"); }
    c->f = data;
    c->n = n;
    cbae_binary_image_t *img = NULL;
    cbae_err_t err = parse_headers(c);
    if (err == CBAE_OK) err = layout(c);
    if (err == CBAE_OK) err = find_tables(c);
    if (err != CBAE_OK) { ctx_free(c); free(data); return err; }

    /* plan: how many of each, from the same walkers that will fill them */
    c->quiet = true;
    sink_t sec = { NULL, 0, 0 }, sym = { NULL, 0, 0 }, rel = { NULL, 0, 0 }, imp = { NULL, 0, 0 };
    walk_sections(c, &sec);
    walk_symbols(c, &sym);
    walk_ksymtab(c, &sym);
    walk_relocs(c, &rel, &imp);
    const uint64_t need = array_bytes(sec.n, sizeof(cbae_section_t)) + array_bytes(sym.n, sizeof(cbae_symbol_t)) +
                          array_bytes(imp.n, sizeof(cbae_import_entry_t)) + array_bytes(rel.n, sizeof(cbae_relocation_t));
    if (need > ELF_MAX_ARENA_BYTES) {
        CBAE_SET_ERR(CBAE_ERR_OVERFLOW, "the tables of this file (%u sections, %u symbols, %u imports, %u relocations) would need %llu bytes; the limit is %llu",
                     sec.n, sym.n, imp.n, rel.n, (unsigned long long)need, (unsigned long long)ELF_MAX_ARENA_BYTES);
        ctx_free(c); free(data);
        return CBAE_ERR_OVERFLOW;
    }

    err = cbae_image_create((cbae_size_t)need, &img);
    if (err != CBAE_OK) { ctx_free(c); free(data); return err; }
    cbae_image_adopt_file(img, data, n);                       /* from here the image owns the bytes */
    snprintf(img->path, sizeof img->path, "%s", name ? name : "");
    c->img = img;
    c->quiet = false;
    for (uint32_t i = 0; i < c->npre; i++) cbae_image_note(img, "%s", c->pre[i]);

    img->format = CBAE_FMT_ELF64;
    img->os_origin = CBAE_OS_LINUX;
    img->arch = c->machine == EM_X86_64 ? CBAE_ARCH_X86_64 : c->machine == EM_AARCH64 ? CBAE_ARCH_ARM64 : CBAE_ARCH_UNKNOWN;
    img->load_base = 0;
    img->entry_point = (c->etype != ET_REL && c->entry != 0) ? (cbae_addr_t)c->entry : (cbae_addr_t)CBAE_ADDR_INVALID;

    err = CBAE_OK;
    if (sec.n) { img->sections = CBAE_ARENA_ALLOC_N(&img->arena, cbae_section_t, sec.n); if (!img->sections) err = CBAE_ERR_OOM; }
    if (err == CBAE_OK && sym.n) { img->symbols = CBAE_ARENA_ALLOC_N(&img->arena, cbae_symbol_t, sym.n); if (!img->symbols) err = CBAE_ERR_OOM; }
    if (err == CBAE_OK && imp.n) { img->imports = CBAE_ARENA_ALLOC_N(&img->arena, cbae_import_entry_t, imp.n); if (!img->imports) err = CBAE_ERR_OOM; }
    if (err == CBAE_OK && rel.n) { img->relocations = CBAE_ARENA_ALLOC_N(&img->arena, cbae_relocation_t, rel.n); if (!img->relocations) err = CBAE_ERR_OOM; }
    if (err != CBAE_OK) { cbae_image_destroy(&img); ctx_free(c); CBAE_RETURN_ERR(err, "cannot allocate the image tables"); }

    sink_t fsec = { img->sections, sec.n, 0 }, fsym = { img->symbols, sym.n, 0 }, frel = { img->relocations, rel.n, 0 }, fimp = { img->imports, imp.n, 0 };
    walk_sections(c, &fsec);
    walk_symbols(c, &fsym);
    walk_ksymtab(c, &fsym);
    walk_relocs(c, &frel, &fimp);
    if (fsec.n != sec.n || fsym.n != sym.n || frel.n != rel.n || fimp.n != imp.n) {
        cbae_image_destroy(&img); ctx_free(c);
        CBAE_RETURN_ERR(CBAE_ERR_GENERIC, "internal error: the ELF tables changed between the plan and the fill pass");
    }
    img->section_count = sec.n;
    img->symbol_count = sym.n;
    img->import_count = imp.n;
    img->reloc_count = rel.n;
    read_modinfo(c, img);
    emit_notes(c, img);

    err = cbae_image_build_indexes(img);
    ctx_free(c);
    if (err != CBAE_OK) { cbae_image_destroy(&img); return err; }
    cbae_image_log_summary(img);
    *out = img;
    return CBAE_OK;
}

cbae_err_t cbae_elf_load_buffer(const uint8_t *data, size_t size, const char *name, cbae_binary_image_t **out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out is NULL");
    *out = NULL;
    if (!data && size) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "data is NULL");
    uint8_t *copy = NULL;
    if (size) {
        copy = (uint8_t *)malloc(size);
        if (!copy) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot copy %zu bytes", size);
        memcpy(copy, data, size);
    }
    return load_owned(copy, size, name, out);
}

cbae_err_t cbae_elf_load(const char *path, cbae_binary_image_t **out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out is NULL");
    *out = NULL;
    if (!path) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "path is NULL");
    LOG_INFO("ELF load: %s", path);
    cbae_file_data_t file;
    cbae_err_t err = cbae_file_read(path, &file);
    if (err != CBAE_OK) return err;
    return load_owned(file.data, file.size, path, out);
}
