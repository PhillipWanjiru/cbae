/**
 * @file pe_loader.c
 * @brief PE32+ parser: a Windows driver or DLL into a cbae_binary_image_t.
 *
 * Layout follows the Microsoft PE/COFF specification. The file is untrusted, so:
 *
 *  - Nothing is read except through a span: a pointer plus the number of file-backed bytes behind it.
 *    sec_span() turns an RVA into a span that ends where the section's raw data (or the file) ends,
 *    and every table walk is bounded by its span. There is no "the table starts inside the file, so it
 *    is all there".
 *  - Every header field is read at its documented offset with explicit byte assembly. There is no
 *    struct laid over the file: a struct bakes one reading of the layout into the parser, and the old
 *    loader's struct was two bytes off (it took the two linker-version bytes for two 16-bit fields), so
 *    it read the image base, entry point, subsystem and every data directory wrongly.
 *  - Each table is walked twice by the same code: a plan pass that only counts, then a fill pass that
 *    writes into arrays allocated for exactly that count. The two passes cannot disagree, and the
 *    arena is sized from the plan instead of being a fixed 8 MiB that a large file overruns.
 *  - What had to be clamped, skipped or cut is recorded as a note on the image, never silently.
 */
#include "loader/pe_loader.h"
#include "loader_util.h"
#include "platform/file_io.h"
#include "platform/logging.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PE_MAX_SECTIONS        96            /* the Windows loader's limit */
#define PE_MAX_EXPORT_SLOTS    0x10000u      /* ordinals are 16 bits */
#define PE_MAX_IMPORTS         262144u       /* entries, over all DLLs */
#define PE_MAX_ARENA_BYTES     ((uint64_t)1 << 30)
#define PE_MAX_NOTES_BEFORE    16

#define PE_DOS_SIZE            64
#define PE_COFF_SIZE           20
#define PE_OPT_FIXED           112           /* PE32+ optional header up to the data directories */
#define PE_SECTION_SIZE        40
#define PE_DIRS_MAX            16
#define PE_MACHINE_AMD64       0x8664
#define PE_MACHINE_ARM64       0xAA64
#define PE_MAGIC_PE32          0x10B
#define PE_MAGIC_PE32P         0x20B
#define PE_SUBSYSTEM_NATIVE    1
#define PE_DIR_EXPORT          0
#define PE_DIR_IMPORT          1
#define PE_DIR_BASERELOC       5
#define PE_DIR_DEBUG           6
#define PE_REL_ABSOLUTE        0
#define PE_REL_HIGHLOW         3
#define PE_REL_DIR64           10
#define PE_SCN_EXEC            0x20000000u
#define PE_SCN_READ            0x40000000u
#define PE_SCN_WRITE           0x80000000u
#define PE_SCN_INIT_DATA       0x00000040u
#define PE_SCN_UNINIT_DATA     0x00000080u
#define PE_DEBUG_ENTRY         28
#define PE_DEBUG_CODEVIEW      2
#define PE_RSDS                0x53445352u   /* "RSDS" */
#define PE_ORDINAL_FLAG64      ((uint64_t)1 << 63)

/* reading numbers and strings, spans and sinks: loader_util.h */

typedef struct {
    char     name[9];
    uint32_t rva;
    uint32_t extent;       /* bytes it occupies in memory: VirtualSize, or SizeOfRawData if that is 0 */
    uint32_t backed;       /* of those, the bytes that come from the file */
    uint32_t off;          /* PointerToRawData */
    uint32_t chars;
} pe_sec_t;

typedef struct { uint32_t rva, size; } pe_dir_t;

typedef struct {
    const uint8_t *f;
    size_t         n;
    uint64_t       ib;
    uint32_t       entry_rva, size_of_image, size_of_headers, hdr_mapped, checksum;
    uint16_t       subsystem, dll_chars, machine;
    uint32_t       nsec;
    pe_sec_t       sec[PE_MAX_SECTIONS];
    uint32_t       ndirs;
    pe_dir_t       dir[PE_DIRS_MAX];
    cbae_binary_image_t *img;                   /* once it exists, notes go straight to it */
    bool           quiet;                       /* plan pass: count, do not note */
    char           pre[PE_MAX_NOTES_BEFORE][CBAE_IMAGE_NOTE_LEN];
    uint32_t       npre;                        /* notes made before the image existed */
    uint32_t       last_sec;                    /* where the last RVA lookup landed: relocations are sorted */
    bool           overlap;                     /* two sections share memory: then a lookup must start at section 0 */
} pe_ctx_t;

static void pe_note(pe_ctx_t *c, const char *fmt, ...) CBAE_PRINTF_FORMAT(2, 3);
static void pe_note(pe_ctx_t *c, const char *fmt, ...) {
    if (c->quiet) return;
    char text[CBAE_IMAGE_NOTE_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    if (c->img) cbae_image_note(c->img, "%s", text);
    else if (c->npre < PE_MAX_NOTES_BEFORE) memcpy(c->pre[c->npre++], text, sizeof text);
}

/* ---- RVA -> bytes ---- */

/* The file-backed bytes from @p rva to the end of the section's raw data. {NULL, 0} when the RVA is in
 * no section, or in the part of a section that is not in the file (a zero-filled tail). Sections win
 * over the headers. Where sections overlap, the first one in table order owns the address.
 *
 * The search starts at the section that answered last time, which makes a long run of sorted lookups
 * (relocations) cost one comparison each. That is only legitimate while no two sections overlap: with
 * an overlap the answer would depend on where the search began, and the plan pass and the fill pass,
 * which look the same things up in a different history, could then disagree. */
static span_t sec_span(pe_ctx_t *c, uint32_t rva) {
    const span_t none = { NULL, 0 };
    const uint32_t start = c->overlap ? 0 : c->last_sec;
    for (uint32_t k = 0; k < c->nsec; k++) {
        const uint32_t i = (start + k) % c->nsec;
        const pe_sec_t *s = &c->sec[i];
        if (rva < s->rva || rva - s->rva >= s->extent) continue;
        c->last_sec = i;
        const uint32_t delta = rva - s->rva;
        if (delta >= s->backed) return none;
        return (span_t){ c->f + s->off + delta, s->backed - delta };
    }
    if (rva < c->hdr_mapped) return (span_t){ c->f + rva, c->hdr_mapped - rva };
    return none;
}

static const pe_sec_t *sec_of_rva(const pe_ctx_t *c, uint32_t rva) {
    for (uint32_t i = 0; i < c->nsec; i++)
        if (rva >= c->sec[i].rva && rva - c->sec[i].rva < c->sec[i].extent) return &c->sec[i];
    return NULL;
}

/* ---- headers ---- */

static uint32_t sec_flags(uint32_t ch) {
    uint32_t f = 0;
    if (ch & PE_SCN_EXEC)         f |= CBAE_SEC_EXEC;
    if (ch & PE_SCN_READ)         f |= CBAE_SEC_READ;
    if (ch & PE_SCN_WRITE)        f |= CBAE_SEC_WRITE;
    if (ch & PE_SCN_INIT_DATA)    f |= CBAE_SEC_INIT;
    if (ch & PE_SCN_UNINIT_DATA)  f |= CBAE_SEC_BSS;
    return f;
}

static cbae_err_t parse_headers(pe_ctx_t *c) {
    const uint8_t *f = c->f;
    const size_t n = c->n;
    if (n < PE_DOS_SIZE) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not a PE file: %zu bytes is too small for a DOS header", n);
    if (f[0] != 'M' || f[1] != 'Z') CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not a PE file: no MZ signature");
    const uint32_t lfanew = rd32(f + 0x3C);
    /* "PE\0\0", the COFF header, and at least the two bytes of the optional header's magic */
    if ((uint64_t)lfanew + 4 + PE_COFF_SIZE + 2 > n)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "e_lfanew 0x%x puts the PE header past the end of the %zu-byte file", lfanew, n);
    if (memcmp(f + lfanew, "PE\0\0", 4) != 0) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "not a PE file: no PE signature at e_lfanew 0x%x", lfanew);

    const uint8_t *coff = f + lfanew + 4;
    c->machine = rd16(coff + 0);
    const uint32_t nsec = rd16(coff + 2);
    const uint32_t optsz = rd16(coff + 16);
    const size_t opt_off = (size_t)lfanew + 4 + PE_COFF_SIZE;
    if (opt_off + optsz > n)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "the optional header (%u bytes at 0x%zx) runs past the end of the %zu-byte file", optsz, opt_off, n);
    if (optsz < 2) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "SizeOfOptionalHeader is %u: no optional header", optsz);
    const uint8_t *opt = f + opt_off;
    const uint16_t magic = rd16(opt);
    if (magic == PE_MAGIC_PE32) CBAE_RETURN_ERR(CBAE_ERR_UNSUPPORTED, "PE32 (32-bit) images are not supported");
    if (magic != PE_MAGIC_PE32P) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "unknown optional header magic 0x%x", magic);
    if (optsz < PE_OPT_FIXED) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "a PE32+ optional header is at least %d bytes, this one is %u", PE_OPT_FIXED, optsz);

    c->entry_rva       = rd32(opt + 16);
    c->ib              = rd64(opt + 24);
    c->size_of_image   = rd32(opt + 56);
    c->size_of_headers = rd32(opt + 60);
    c->checksum        = rd32(opt + 64);
    c->subsystem       = rd16(opt + 68);
    c->dll_chars       = rd16(opt + 70);
    /* every address is image base + a 32-bit RVA (+ a 32-bit size): none of them may wrap */
    if (c->ib > UINT64_MAX - 2 * (uint64_t)UINT32_MAX)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "ImageBase 0x%llx is too close to the top of the address space: addresses would wrap", (unsigned long long)c->ib);
    c->hdr_mapped = c->size_of_headers < n ? c->size_of_headers : (uint32_t)(n < UINT32_MAX ? n : UINT32_MAX);

    const uint32_t declared = rd32(opt + 108);
    const uint32_t room = (optsz - PE_OPT_FIXED) / 8;
    uint32_t nd = declared;
    if (nd > PE_DIRS_MAX) { pe_note(c, "NumberOfRvaAndSizes is %u: only the first %d data directories are read", declared, PE_DIRS_MAX); nd = PE_DIRS_MAX; }
    if (nd > room) { pe_note(c, "NumberOfRvaAndSizes is %u but the optional header has room for %u", declared, room); nd = room; }
    c->ndirs = nd;
    for (uint32_t i = 0; i < nd; i++) {
        const uint32_t rva = rd32(opt + PE_OPT_FIXED + 8 * i), size = rd32(opt + PE_OPT_FIXED + 8 * i + 4);
        if (rva != 0 && size != 0) { c->dir[i].rva = rva; c->dir[i].size = size; }   /* present only with both */
    }

    if (nsec > PE_MAX_SECTIONS) CBAE_RETURN_ERR(CBAE_ERR_PARSE, "%u sections: the Windows loader accepts at most %d", nsec, PE_MAX_SECTIONS);
    const size_t tab = opt_off + optsz;
    if (tab + (size_t)nsec * PE_SECTION_SIZE > n)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "the section table (%u entries at 0x%zx) runs past the end of the %zu-byte file", nsec, tab, n);
    c->nsec = nsec;
    for (uint32_t i = 0; i < nsec; i++) {
        const uint8_t *h = f + tab + (size_t)i * PE_SECTION_SIZE;
        pe_sec_t *s = &c->sec[i];
        size_t len = 0;
        while (len < 8 && h[len]) len++;
        memcpy(s->name, h, len);
        s->name[len] = '\0';
        const uint32_t vsize = rd32(h + 8), raw = rd32(h + 16);
        s->rva    = rd32(h + 12);
        s->off    = rd32(h + 20);
        s->chars  = rd32(h + 36);
        s->extent = vsize ? vsize : raw;
        const uint64_t avail = s->off < n ? n - s->off : 0;
        uint64_t backed = raw;
        if (backed > s->extent) backed = s->extent;               /* raw data beyond the virtual size is file padding */
        if (backed > avail) backed = avail;
        s->backed = (uint32_t)backed;
        if (raw != 0 && (uint64_t)s->off + raw > n && backed < (raw < s->extent ? raw : s->extent))
            pe_note(c, "section %s: raw data (0x%x bytes at file offset 0x%x) runs past the end of the file; %u bytes are present",
                    s->name, raw, s->off, s->backed);
    }
    for (uint32_t i = 0; i < nsec; i++)
        for (uint32_t j = i + 1; j < nsec; j++) {
            const pe_sec_t *a = &c->sec[i], *b = &c->sec[j];
            if (a->extent && b->extent && (uint64_t)a->rva < (uint64_t)b->rva + b->extent && (uint64_t)b->rva < (uint64_t)a->rva + a->extent) {
                pe_note(c, "sections %s and %s overlap in memory", a->name, b->name);
                c->overlap = true;
                i = nsec; break;                                   /* one note is enough */
            }
        }
    if (c->machine != PE_MACHINE_AMD64 && c->machine != PE_MACHINE_ARM64)
        pe_note(c, "machine type 0x%04x is neither x86-64 nor ARM64", c->machine);
    if (c->entry_rva) {
        const pe_sec_t *es = sec_of_rva(c, c->entry_rva);
        if (!es || !(es->chars & PE_SCN_EXEC)) pe_note(c, "the entry point (RVA 0x%x) is not in an executable section", c->entry_rva);
    }
    return CBAE_OK;
}

/* ---- the five tables: each is walked by one function that either counts or fills ---- */

static void walk_imports(pe_ctx_t *c, sink_t *k) {
    const pe_dir_t d = c->dir[PE_DIR_IMPORT];
    if (!d.rva) return;
    const span_t ds = sec_span(c, d.rva);
    if (ds.n < 20) { pe_note(c, "the import directory (RVA 0x%x) is not in the file", d.rva); return; }
    bool ended = false;
    for (size_t at = 0; at + 20 <= ds.n && !ended; at += 20) {
        const uint8_t *e = ds.p + at;
        const uint32_t ilt = rd32(e), name = rd32(e + 12), iat = rd32(e + 16);
        if (name == 0 || iat == 0) { ended = true; break; }        /* the terminating descriptor, as the Windows loader reads it */
        char module[CBAE_IMPORT_MODULE_MAX];
        const str_res_t mr = read_str(sec_span(c, name), module, sizeof module);
        if (mr == STR_UNMAPPED) pe_note(c, "import descriptor %zu: the DLL name (RVA 0x%x) is not in the file", at / 20, name);
        else if (mr == STR_CUT) pe_note(c, "import descriptor %zu: the DLL name is longer than %d bytes and was cut", at / 20, CBAE_IMPORT_MODULE_MAX - 1);
        const span_t ts = sec_span(c, ilt ? ilt : iat);
        if (ts.n < 8) { pe_note(c, "import descriptor %zu (%s): the lookup table (RVA 0x%x) is not in the file", at / 20, module, ilt ? ilt : iat); continue; }
        bool terminated = false;
        for (size_t i = 0; (i + 1) * 8 <= ts.n; i++) {
            const uint64_t ent = rd64(ts.p + i * 8);
            if (ent == 0) { terminated = true; break; }
            if (k->n >= PE_MAX_IMPORTS) { pe_note(c, "more than %u imports: the rest are ignored", PE_MAX_IMPORTS); return; }
            cbae_import_entry_t *imp = (cbae_import_entry_t *)sink_slot(k, sizeof *imp);
            if (!imp) continue;
            memset(imp, 0, sizeof *imp);
            memcpy(imp->module, module, sizeof imp->module);
            imp->iat_va = (cbae_addr_t)(c->ib + iat + 8 * (uint64_t)i);
            imp->rela_offset = (cbae_off_t)CBAE_ADDR_INVALID;
            imp->table_index = k->n - 1;
            if (ent & PE_ORDINAL_FLAG64) {
                imp->ordinal = (uint16_t)(ent & 0xFFFF);
                imp->state = CBAE_IMPORT_BY_ORDINAL;
                snprintf(imp->name, CBAE_IMPORT_NAME_MAX, "ord#%u", imp->ordinal);
            } else {
                const span_t hn = sec_span(c, (uint32_t)(ent & 0x7FFFFFFF));
                if (hn.n >= 2) {
                    imp->hint = rd16(hn.p);
                    const str_res_t nr = read_str((span_t){ hn.p + 2, hn.n - 2 }, imp->name, CBAE_IMPORT_NAME_MAX);
                    imp->state = CBAE_IMPORT_BY_NAME;
                    if (nr == STR_CUT) pe_note(c, "an import name from %s is longer than %d bytes and was cut", module, CBAE_IMPORT_NAME_MAX - 1);
                } else {
                    pe_note(c, "an import name entry (RVA 0x%x, from %s) is not in the file", (uint32_t)(ent & 0x7FFFFFFF), module);
                }
            }
        }
        if (!terminated) pe_note(c, "the import lookup table of %s has no terminating zero entry inside the file", module);
    }
    if (!ended) pe_note(c, "the import directory has no terminating descriptor inside the file");
}

static cbae_sym_kind_t kind_at(const pe_ctx_t *c, uint32_t rva) {
    const pe_sec_t *s = sec_of_rva(c, rva);
    if (!s) return CBAE_KIND_NOTYPE;
    return (s->chars & PE_SCN_EXEC) ? CBAE_KIND_FUNCTION : CBAE_KIND_OBJECT;
}

static void export_symbol(pe_ctx_t *c, sink_t *k, pe_dir_t d, const char *name, uint32_t target, bool *noted_fwd) {
    cbae_symbol_t *sym = (cbae_symbol_t *)sink_slot(k, sizeof *sym);
    if (!sym) return;
    memset(sym, 0, sizeof *sym);
    snprintf(sym->name, sizeof sym->name, "%s", name);
    sym->type = CBAE_SYM_EXPORT;
    sym->binding = CBAE_BIND_GLOBAL;
    sym->table_index = k->n - 1;
    if (target >= d.rva && target - d.rva < d.size) {              /* inside the export directory: a forwarder string */
        char fwd[64];
        if (read_str(sec_span(c, target), fwd, sizeof fwd) == STR_UNMAPPED && !*noted_fwd) {
            pe_note(c, "export %.40s: the forwarder string (RVA 0x%x) is not in the file", name, target);
            *noted_fwd = true;
        }
        snprintf(sym->source, sizeof sym->source, "fwd:%.56s", fwd);
        sym->address = CBAE_ADDR_INVALID;
        sym->kind = CBAE_KIND_FUNCTION;
    } else {
        sym->address = (cbae_addr_t)(c->ib + target);
        sym->kind = kind_at(c, target);
    }
}

static void walk_exports(pe_ctx_t *c, sink_t *k) {
    const pe_dir_t d = c->dir[PE_DIR_EXPORT];
    if (!d.rva) return;
    const span_t ds = sec_span(c, d.rva);
    if (ds.n < 40) { pe_note(c, "the export directory (RVA 0x%x) is not in the file", d.rva); return; }
    const uint32_t base = rd32(ds.p + 16), nfuncs = rd32(ds.p + 20), nnames = rd32(ds.p + 24);
    const uint32_t eat_rva = rd32(ds.p + 28), names_rva = rd32(ds.p + 32), ords_rva = rd32(ds.p + 36);

    uint32_t neat = nfuncs;
    if (neat > PE_MAX_EXPORT_SLOTS) { pe_note(c, "the export table declares %u functions: only the first %u are read", nfuncs, PE_MAX_EXPORT_SLOTS); neat = PE_MAX_EXPORT_SLOTS; }
    const span_t eat = sec_span(c, eat_rva);
    if (neat > eat.n / 4) { if (neat) pe_note(c, "the export address table (%u entries) runs past the end of the file: %zu are present", neat, eat.n / 4); neat = (uint32_t)(eat.n / 4); }

    uint32_t nn = nnames;
    const span_t names = sec_span(c, names_rva), ords = sec_span(c, ords_rva);
    if (nn > names.n / 4 || nn > ords.n / 2) {
        const size_t have = names.n / 4 < ords.n / 2 ? names.n / 4 : ords.n / 2;
        if (nn) pe_note(c, "the export name tables (%u entries) run past the end of the file: %zu are present", nn, have);
        nn = (uint32_t)(have < nn ? have : nn);
    }

    uint8_t named[PE_MAX_EXPORT_SLOTS / 8];
    memset(named, 0, sizeof named);
    bool noted_ord = false, noted_name = false, noted_fwd = false;
    for (uint32_t i = 0; i < nn; i++) {
        const uint32_t slot = rd16(ords.p + 2 * (size_t)i);
        if (slot >= neat) { if (!noted_ord) { pe_note(c, "export name %u has ordinal index %u, outside the %u-entry address table: skipped", i, slot, neat); noted_ord = true; } continue; }
        const uint32_t target = rd32(eat.p + 4 * (size_t)slot);
        if (target == 0) continue;                                  /* an unused slot */
        char name[CBAE_SYM_NAME_MAX];
        const str_res_t r = read_str(sec_span(c, rd32(names.p + 4 * (size_t)i)), name, sizeof name);
        if (r == STR_UNMAPPED) { if (!noted_name) { pe_note(c, "export name %u is not in the file: that export is listed by ordinal", i); noted_name = true; } continue; }
        if (r == STR_CUT) pe_note(c, "export %.40s... has a name longer than %d bytes and was cut", name, CBAE_SYM_NAME_MAX - 1);
        named[slot >> 3] |= (uint8_t)(1u << (slot & 7));
        export_symbol(c, k, d, name, target, &noted_fwd);
    }
    for (uint32_t slot = 0; slot < neat; slot++) {
        const uint32_t target = rd32(eat.p + 4 * (size_t)slot);
        if (target == 0 || (named[slot >> 3] & (1u << (slot & 7)))) continue;
        char name[CBAE_SYM_NAME_MAX];
        snprintf(name, sizeof name, "ord#%llu", (unsigned long long)base + slot);
        export_symbol(c, k, d, name, target, &noted_fwd);
    }
}

static cbae_reloc_type_t reloc_type(uint32_t t) {
    return t == PE_REL_ABSOLUTE ? CBAE_RELOC_NOP : t == PE_REL_HIGHLOW ? CBAE_RELOC_ABS32 : t == PE_REL_DIR64 ? CBAE_RELOC_ABS64 : CBAE_RELOC_UNKNOWN;
}

static void walk_relocs(pe_ctx_t *c, sink_t *k) {
    const pe_dir_t d = c->dir[PE_DIR_BASERELOC];
    if (!d.rva) return;
    const span_t ds = sec_span(c, d.rva);
    size_t avail = ds.n < d.size ? ds.n : d.size;
    if (avail < d.size) pe_note(c, "the base relocation directory (%u bytes at RVA 0x%x) runs past the end of the file: %zu are present", d.size, d.rva, avail);
    size_t pos = 0;
    while (avail - pos >= 8) {
        const uint32_t page = rd32(ds.p + pos), bsz = rd32(ds.p + pos + 4);
        if (bsz < 8) { pe_note(c, "a base relocation block at offset 0x%zx has size %u (less than its 8-byte header): the rest are ignored", pos, bsz); break; }
        size_t room = avail - pos;
        size_t nent;
        bool last = false;
        if (bsz > room) { pe_note(c, "a base relocation block at offset 0x%zx declares %u bytes but %zu remain: it is cut", pos, bsz, room); nent = (room - 8) / 2; last = true; }
        else nent = (bsz - 8) / 2;
        for (size_t i = 0; i < nent; i++) {
            cbae_relocation_t *r = (cbae_relocation_t *)sink_slot(k, sizeof *r);
            if (!r) continue;
            const uint16_t ent = rd16(ds.p + pos + 8 + 2 * i);
            const uint64_t rva = (uint64_t)page + (ent & 0x0FFF);        /* page 0xFFFFFFFF + offset 0x00F is past 4 GiB: it must not wrap to 0xE */
            memset(r, 0, sizeof *r);
            r->page_rva = page;
            r->sym_index = CBAE_RELOC_NO_SYMBOL;
            r->target_va = (cbae_addr_t)(c->ib + rva);
            r->type = reloc_type((uint32_t)(ent >> 12));
            r->table_index = k->n - 1;
            const span_t at = rva <= UINT32_MAX ? sec_span(c, (uint32_t)rva) : (span_t){ NULL, 0 };
            r->file_offset = at.p ? (cbae_off_t)(at.p - c->f) : (cbae_off_t)CBAE_ADDR_INVALID;
        }
        if (last) break;
        pos += bsz;
    }
}

/* the first CodeView entry that has a non-empty PDB path: an empty one does not end the search */
static void read_debug(pe_ctx_t *c, cbae_binary_image_t *img) {
    const pe_dir_t d = c->dir[PE_DIR_DEBUG];
    if (!d.rva) return;
    const span_t ds = sec_span(c, d.rva);
    const size_t ents = (ds.n < d.size ? ds.n : d.size) / PE_DEBUG_ENTRY;
    if (ds.n < d.size) pe_note(c, "the debug directory (%u bytes at RVA 0x%x) runs past the end of the file", d.size, d.rva);
    for (size_t i = 0; i < ents; i++) {
        const uint8_t *e = ds.p + i * PE_DEBUG_ENTRY;
        if (rd32(e + 12) != PE_DEBUG_CODEVIEW) continue;
        const uint32_t size = rd32(e + 16), ptr = rd32(e + 24);
        if (ptr >= c->n) { pe_note(c, "a CodeView debug record is at file offset 0x%x, past the end of the file", ptr); continue; }
        size_t have = c->n - ptr;
        if (have > size) have = size;
        if (have < 24 || rd32(c->f + ptr) != PE_RSDS) continue;     /* "RSDS", a 16-byte GUID, a 4-byte age, then the path */
        char path[sizeof img->meta.pe.pdb_path];
        const str_res_t r = read_str((span_t){ c->f + ptr + 24, have - 24 }, path, sizeof path);
        if (r == STR_UNMAPPED || path[0] == '\0') continue;
        if (r == STR_CUT) pe_note(c, "the PDB path is longer than %zu bytes and was cut", sizeof path - 1);
        memcpy(img->meta.pe.pdb_path, path, sizeof path);
        return;
    }
}

/* ---- assembling the image ---- */

static cbae_err_t fill_sections(pe_ctx_t *c, cbae_binary_image_t *img) {
    img->sections = CBAE_ARENA_ALLOC_N(&img->arena, cbae_section_t, c->nsec);
    if (!img->sections) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot allocate %u sections", c->nsec);
    img->section_count = c->nsec;
    for (uint32_t i = 0; i < c->nsec; i++) {
        const pe_sec_t *s = &c->sec[i];
        cbae_section_t *o = &img->sections[i];
        memcpy(o->name, s->name, sizeof s->name);
        o->virt_addr = (cbae_addr_t)(c->ib + s->rva);
        o->virt_size = s->extent;
        o->file_offset = s->off;
        o->file_size = s->backed;
        o->flags = sec_flags(s->chars);
        o->data = s->backed ? c->f + s->off : NULL;
    }
    return CBAE_OK;
}

static cbae_err_t load_owned(uint8_t *data, size_t n, const char *name, cbae_binary_image_t **out) {
    pe_ctx_t *c = (pe_ctx_t *)calloc(1, sizeof *c);
    if (!c) { free(data); CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot allocate the PE parser state"); }
    c->f = data;
    c->n = n;
    cbae_err_t err = parse_headers(c);
    if (err != CBAE_OK) { free(c); free(data); return err; }

    /* plan: how many of each, from the same walkers that will fill them */
    c->quiet = true;
    sink_t imp = { NULL, 0, 0 }, sym = { NULL, 0, 0 }, rel = { NULL, 0, 0 };
    walk_imports(c, &imp);
    walk_exports(c, &sym);
    walk_relocs(c, &rel);
    const uint64_t need = array_bytes(c->nsec, sizeof(cbae_section_t)) + array_bytes(sym.n, sizeof(cbae_symbol_t)) +
                          array_bytes(imp.n, sizeof(cbae_import_entry_t)) + array_bytes(rel.n, sizeof(cbae_relocation_t));
    if (need > PE_MAX_ARENA_BYTES) {
        free(c); free(data);
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "the tables of this file (%u imports, %u exports, %u relocations) would need %llu bytes; the limit is %llu",
                        imp.n, sym.n, rel.n, (unsigned long long)need, (unsigned long long)PE_MAX_ARENA_BYTES);
    }

    cbae_binary_image_t *img = NULL;
    err = cbae_image_create((cbae_size_t)need, &img);
    if (err != CBAE_OK) { free(c); free(data); return err; }
    cbae_image_adopt_file(img, data, n);                           /* from here the image owns the bytes */
    snprintf(img->path, sizeof img->path, "%s", name ? name : "");
    c->img = img;
    c->quiet = false;
    for (uint32_t i = 0; i < c->npre; i++) cbae_image_note(img, "%s", c->pre[i]);

    img->format = CBAE_FMT_PE32PLUS;
    img->os_origin = CBAE_OS_WINDOWS;
    img->arch = c->machine == PE_MACHINE_AMD64 ? CBAE_ARCH_X86_64 : c->machine == PE_MACHINE_ARM64 ? CBAE_ARCH_ARM64 : CBAE_ARCH_UNKNOWN;
    img->load_base = (cbae_addr_t)c->ib;
    img->entry_point = c->entry_rva ? (cbae_addr_t)(c->ib + c->entry_rva) : (cbae_addr_t)CBAE_ADDR_INVALID;
    img->meta.pe.image_base = c->ib;
    img->meta.pe.image_size = c->size_of_image;
    img->meta.pe.subsystem = c->subsystem;
    img->meta.pe.dll_characteristics = c->dll_chars;
    img->meta.pe.checksum = c->checksum;
    img->meta.pe.is_driver = c->subsystem == PE_SUBSYSTEM_NATIVE;

    err = fill_sections(c, img);
    if (err == CBAE_OK && imp.n) {
        img->imports = CBAE_ARENA_ALLOC_N(&img->arena, cbae_import_entry_t, imp.n);
        if (!img->imports) err = CBAE_ERR_OOM;
    }
    if (err == CBAE_OK && sym.n) {
        img->symbols = CBAE_ARENA_ALLOC_N(&img->arena, cbae_symbol_t, sym.n);
        if (!img->symbols) err = CBAE_ERR_OOM;
    }
    if (err == CBAE_OK && rel.n) {
        img->relocations = CBAE_ARENA_ALLOC_N(&img->arena, cbae_relocation_t, rel.n);
        if (!img->relocations) err = CBAE_ERR_OOM;
    }
    if (err != CBAE_OK) { cbae_image_destroy(&img); free(c); CBAE_RETURN_ERR(err, "cannot allocate the image tables"); }

    sink_t fi = { img->imports, imp.n, 0 }, fs = { img->symbols, sym.n, 0 }, fr = { img->relocations, rel.n, 0 };
    walk_imports(c, &fi);
    walk_exports(c, &fs);
    walk_relocs(c, &fr);
    if (fi.n != imp.n || fs.n != sym.n || fr.n != rel.n) {
        cbae_image_destroy(&img); free(c);
        CBAE_RETURN_ERR(CBAE_ERR_GENERIC, "internal error: the PE tables changed between the plan and the fill pass");
    }
    img->import_count = imp.n;
    img->symbol_count = sym.n;
    img->reloc_count = rel.n;
    read_debug(c, img);

    err = cbae_image_build_indexes(img);
    free(c);
    if (err != CBAE_OK) { cbae_image_destroy(&img); return err; }
    cbae_image_log_summary(img);
    *out = img;
    return CBAE_OK;
}

cbae_err_t cbae_pe_load_buffer(const uint8_t *data, size_t size, const char *name, cbae_binary_image_t **out) {
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

cbae_err_t cbae_pe_load(const char *path, cbae_binary_image_t **out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out is NULL");
    *out = NULL;
    if (!path) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "path is NULL");
    LOG_INFO("PE load: %s", path);
    cbae_file_data_t file;
    cbae_err_t err = cbae_file_read(path, &file);
    if (err != CBAE_OK) return err;
    return load_owned(file.data, file.size, path, out);
}
