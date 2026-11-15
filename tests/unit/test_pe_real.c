/**
 * @file test_pe_real.c
 * @brief The PE loader on files that a real compiler and linker made.
 *
 * Every other PE test builds its files with pe_builder.h, which only makes what its author thought of. These are made by clang and
 * lld-link, with no Windows SDK (tests/fixtures/pe): a driver (a discardable INIT section, imports from ntoskrnl.exe and HAL.dll with
 * real hints and one by ordinal, unwind data, 603 function pointers that need base relocations over two pages, a CodeView path), the
 * same driver linked flat (section alignment = file alignment = 512, no base relocations, no debug information), a DLL (exports by
 * name, by ordinal only, a forwarder and a data export; imports by name) and the same DLL for ARM64. The loader is held to what is in
 * the files, as the .expect files in tests/fixtures/pe record it: every header field, data directory, section, import, export slot,
 * relocation entry and debug entry, read from the bytes by make_expect.py and checked there against pefile and llvm-readobj. The
 * loader is not involved in making them.
 *
 * What the file says is not what the image holds. The rules that turn one into the other (where a section lies and how much of it is
 * in the file, what an import and an export are called, which kind a symbol has, what a relocation entry points at) are written out
 * below as arithmetic on the expectation, and the image is compared with the result. Then the files are cut at every length and
 * damaged at random: whatever the loader makes of them must satisfy pe_check.h, and an out-of-memory sweep runs over a load of each.
 */
#include "loader/pe_loader.h"
#include "alloc_inject.h"
#include "oom_sweep.h"
#include "pe_check.h"
#include "pe_random.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CBAE_PE_FIXTURES
#error "CBAE_PE_FIXTURES must be the path of tests/fixtures/pe"
#endif

#define PASS(name) printf("  [PASS] %s\n", name)
#define PE_DIRS 16

/* ---- the expectation file ---- */

typedef struct { uint32_t vsize, rva, rawsize, rawptr, chars; char name[16]; } xsec_t;
typedef struct { uint32_t desc, iat, slot, v; char kind, dll[96], name[200]; } ximp_t;
typedef struct { uint32_t slot, rva; char fwd[128]; } xeat_t;
typedef struct { uint32_t slot; char name[200]; } xenm_t;
typedef struct { uint32_t page, bsz, idx, type, off; } xrel_t;
typedef struct { uint32_t type, size, rva, ptr; } xdbg_t;

typedef struct {
    uint32_t machine, nsec, fchars, entry;
    uint64_t ib;
    uint32_t size_of_image, size_of_headers, checksum, subsystem, dllchars, ndirs, fsize;
    uint32_t dir_rva[PE_DIRS], dir_size[PE_DIRS];
    xsec_t  *sec;
    ximp_t  *imp;  uint32_t nimp;
    bool     has_exp;
    uint32_t exp_base, exp_nfuncs, exp_nnames;
    char     exp_dll[96];
    xeat_t  *eat;
    xenm_t  *enm;
    xrel_t  *rel;  uint32_t nrel;
    xdbg_t   dbg[16]; uint32_t ndbg;
    char     pdb[300];
} xp_t;

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    assert(f && "fixture missing: run tests/fixtures/pe/regen.sh");
    fseek(f, 0, SEEK_END);
    const long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = (uint8_t *)malloc((size_t)len + 1);
    assert(b && fread(b, 1, (size_t)len, f) == (size_t)len);
    fclose(f);
    *n = (size_t)len;
    return b;
}

static void parse_expect(const char *path, xp_t *x) {
    memset(x, 0, sizeof *x);
    size_t n;
    char *text = (char *)slurp(path, &n);
    text[n] = '\0';
    uint32_t cap_imp = 0, cap_rel = 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#') continue;
        if (strncmp(line, "pe ", 3) == 0) {
            unsigned long long ib;
            assert(sscanf(line, "pe %u %u %u %u %llu %u %u %u %u %u %u %u", &x->machine, &x->nsec, &x->fchars, &x->entry, &ib, &x->size_of_image,
                          &x->size_of_headers, &x->checksum, &x->subsystem, &x->dllchars, &x->ndirs, &x->fsize) == 12);
            x->ib = ib;
            assert(x->nsec > 0 && x->ndirs <= PE_DIRS);
            x->sec = (xsec_t *)calloc(x->nsec, sizeof *x->sec);
            assert(x->sec);
        } else if (strncmp(line, "dir ", 4) == 0) {
            unsigned i, rva, size;
            assert(sscanf(line, "dir %u %u %u", &i, &rva, &size) == 3 && i < PE_DIRS);
            x->dir_rva[i] = rva; x->dir_size[i] = size;
        } else if (strncmp(line, "sec ", 4) == 0) {
            unsigned i;
            xsec_t s;
            assert(sscanf(line, "sec %u %u %u %u %u %u %15s", &i, &s.vsize, &s.rva, &s.rawsize, &s.rawptr, &s.chars, s.name) == 7 && i < x->nsec);
            x->sec[i] = s;
        } else if (strncmp(line, "imp ", 4) == 0) {
            ximp_t m;
            assert(sscanf(line, "imp %u %u %u %c %u %95s %199s", &m.desc, &m.iat, &m.slot, &m.kind, &m.v, m.dll, m.name) == 7);
            assert(m.kind == 'N' || m.kind == 'O');
            if (strcmp(m.name, "-") == 0) m.name[0] = '\0';
            if (x->nimp == cap_imp) { cap_imp = cap_imp ? cap_imp * 2 : 16; x->imp = (ximp_t *)realloc(x->imp, cap_imp * sizeof *x->imp); assert(x->imp); }
            x->imp[x->nimp++] = m;
        } else if (strncmp(line, "exp ", 4) == 0) {
            assert(sscanf(line, "exp %u %u %u %95s", &x->exp_base, &x->exp_nfuncs, &x->exp_nnames, x->exp_dll) == 4);
            x->has_exp = true;
            x->eat = (xeat_t *)calloc(x->exp_nfuncs ? x->exp_nfuncs : 1, sizeof *x->eat);
            x->enm = (xenm_t *)calloc(x->exp_nnames ? x->exp_nnames : 1, sizeof *x->enm);
            assert(x->eat && x->enm);
        } else if (strncmp(line, "eat ", 4) == 0) {
            unsigned slot;
            xeat_t e;
            assert(x->has_exp && sscanf(line, "eat %u %u %127s", &slot, &e.rva, e.fwd) == 3 && slot < x->exp_nfuncs);
            e.slot = slot;
            if (strcmp(e.fwd, "-") == 0) e.fwd[0] = '\0';
            x->eat[slot] = e;
        } else if (strncmp(line, "enm ", 4) == 0) {
            unsigned i;
            xenm_t e;
            assert(x->has_exp && sscanf(line, "enm %u %u %199s", &i, &e.slot, e.name) == 3 && i < x->exp_nnames);
            x->enm[i] = e;
        } else if (strncmp(line, "rel ", 4) == 0) {
            xrel_t r;
            assert(sscanf(line, "rel %u %u %u %u %u", &r.page, &r.bsz, &r.idx, &r.type, &r.off) == 5);
            if (x->nrel == cap_rel) { cap_rel = cap_rel ? cap_rel * 2 : 128; x->rel = (xrel_t *)realloc(x->rel, cap_rel * sizeof *x->rel); assert(x->rel); }
            x->rel[x->nrel++] = r;
        } else if (strncmp(line, "dbg ", 4) == 0) {
            xdbg_t d;
            assert(sscanf(line, "dbg %u %u %u %u", &d.type, &d.size, &d.rva, &d.ptr) == 4 && x->ndbg < 16);
            x->dbg[x->ndbg++] = d;
        } else if (strncmp(line, "pdb ", 4) == 0) {
            snprintf(x->pdb, sizeof x->pdb, "%s", line + 4);
        } else {
            assert(!"unknown record in an .expect file");
        }
    }
    free(text);
}

static void free_expect(xp_t *x) { free(x->sec); free(x->imp); free(x->eat); free(x->enm); free(x->rel); }

/* dst = src cut to cap - 1 bytes: what the loader does to a name that does not fit (written out, so the compiler has nothing to warn about) */
static void cut(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

/* ---- the rules ---- */

static uint32_t x_extent(const xsec_t *s) { return s->vsize ? s->vsize : s->rawsize; }          /* bytes in memory */
static uint32_t x_backed(const xsec_t *s) { return s->rawsize < x_extent(s) ? s->rawsize : x_extent(s); }   /* of those, from the file */

/* The section that owns an RVA: the first in table order whose memory holds it. */
static const xsec_t *x_sec(const xp_t *x, uint64_t rva) {
    for (uint32_t i = 0; i < x->nsec; i++)
        if (rva >= x->sec[i].rva && rva - x->sec[i].rva < x_extent(&x->sec[i])) return &x->sec[i];
    return NULL;
}

/* The file offset of an RVA, or CBAE_ADDR_INVALID: in a section's file-backed part, else in the headers. */
static uint64_t x_off(const xp_t *x, uint64_t rva) {
    const xsec_t *s = x_sec(x, rva);
    if (s) return rva - s->rva < x_backed(s) ? s->rawptr + (rva - s->rva) : CBAE_ADDR_INVALID;
    return rva < x->size_of_headers && rva < x->fsize ? rva : CBAE_ADDR_INVALID;
}

static uint32_t x_flags(uint32_t ch) {
    uint32_t f = 0;
    if (ch & 0x20000000u) f |= CBAE_SEC_EXEC;
    if (ch & 0x40000000u) f |= CBAE_SEC_READ;
    if (ch & 0x80000000u) f |= CBAE_SEC_WRITE;
    if (ch & 0x40u) f |= CBAE_SEC_INIT;
    if (ch & 0x80u) f |= CBAE_SEC_BSS;
    return f;
}

typedef struct { char name[200]; uint32_t slot, rva; bool fwd; char fwd_text[128]; } xexp_t;

/* The exports an image must hold, in order: the named ones as the name table lists them (an entry whose slot is empty is no export),
 * then the slots no name reaches, called ord#<ordinal>. At most nfuncs + nnames of them. */
static uint32_t x_exports(const xp_t *x, xexp_t *out) {
    uint32_t n = 0;
    bool *named = (bool *)calloc(x->exp_nfuncs ? x->exp_nfuncs : 1, sizeof *named);
    assert(named);
    for (uint32_t i = 0; i < x->exp_nnames; i++) {
        const uint32_t slot = x->enm[i].slot;
        assert(slot < x->exp_nfuncs);
        if (x->eat[slot].rva == 0) continue;
        named[slot] = true;
        snprintf(out[n].name, sizeof out[n].name, "%s", x->enm[i].name);
        out[n].slot = slot; out[n].rva = x->eat[slot].rva; out[n].fwd = x->eat[slot].fwd[0] != '\0';
        snprintf(out[n].fwd_text, sizeof out[n].fwd_text, "%s", x->eat[slot].fwd);
        n++;
    }
    for (uint32_t slot = 0; slot < x->exp_nfuncs; slot++) {
        if (x->eat[slot].rva == 0 || named[slot]) continue;
        snprintf(out[n].name, sizeof out[n].name, "ord#%llu", (unsigned long long)x->exp_base + slot);
        out[n].slot = slot; out[n].rva = x->eat[slot].rva; out[n].fwd = x->eat[slot].fwd[0] != '\0';
        snprintf(out[n].fwd_text, sizeof out[n].fwd_text, "%s", x->eat[slot].fwd);
        n++;
    }
    free(named);
    return n;
}

/* ---- one file ---- */

typedef struct { uint32_t sections, imports, exports, relocs, notes, nsec, nimp, nrel; } tally_t;

static tally_t check_file(const char *base) {
    char path[600], epath[620];
    snprintf(path, sizeof path, "%s/%s", CBAE_PE_FIXTURES, base);
    snprintf(epath, sizeof epath, "%s.expect", path);
    xp_t x;
    parse_expect(epath, &x);
    size_t n;
    uint8_t *file = slurp(path, &n);
    assert(n == x.fsize);
    cbae_binary_image_t *img = NULL;
    assert(cbae_pe_load(path, &img) == CBAE_OK && img);
    pe_check_image(img, file, n);

    /* header facts */
    assert(strcmp(img->path, path) == 0);
    assert(img->arch == (x.machine == 0x8664 ? CBAE_ARCH_X86_64 : x.machine == 0xAA64 ? CBAE_ARCH_ARM64 : CBAE_ARCH_UNKNOWN));
    assert(img->load_base == x.ib && img->meta.pe.image_base == x.ib);
    assert(img->entry_point == (x.entry ? x.ib + x.entry : CBAE_ADDR_INVALID));
    assert(img->meta.pe.image_size == x.size_of_image && img->meta.pe.checksum == x.checksum);
    assert(img->meta.pe.subsystem == x.subsystem && img->meta.pe.dll_characteristics == x.dllchars);
    assert(img->meta.pe.is_driver == (x.subsystem == 1));
    assert(strcmp(img->meta.pe.pdb_path, x.pdb) == 0);

    /* sections: one for each header, in table order */
    assert(img->section_count == x.nsec);
    for (uint32_t i = 0; i < x.nsec; i++) {
        const xsec_t *e = &x.sec[i];
        const cbae_section_t *s = &img->sections[i];
        assert(strcmp(s->name, e->name) == 0);
        assert(s->virt_addr == x.ib + e->rva && s->virt_size == x_extent(e));
        assert(s->file_offset == e->rawptr && s->file_size == x_backed(e) && s->flags == x_flags(e->chars));
        if (x_backed(e)) assert(s->data == img->file_data + e->rawptr && memcmp(s->data, file + e->rawptr, x_backed(e)) == 0);
        else assert(s->data == NULL);
        /* a real file's sections do not overlap: an address finds its own section, the bytes before and after it find another or none */
        assert(cbae_image_section_at_va(img, s->virt_addr) == s && cbae_image_section_at_va(img, s->virt_addr + s->virt_size - 1) == s);
        assert(cbae_image_section_by_name(img, s->name) == s);
        assert(cbae_image_section_at_va(img, s->virt_addr + s->virt_size) != s);
        if (x_backed(e)) {                                       /* the file-backed part is readable by address; the zero-filled tail is not */
            assert(cbae_image_va_to_ptr(img, s->virt_addr) == img->file_data + e->rawptr);
            assert(cbae_image_va_to_ptr(img, s->virt_addr + x_backed(e) - 1) == img->file_data + e->rawptr + x_backed(e) - 1);
            assert(cbae_image_offset_to_va(img, e->rawptr + x_backed(e) - 1) == s->virt_addr + x_backed(e) - 1);
        }
        if (x_backed(e) < x_extent(e)) assert(cbae_image_va_to_ptr(img, s->virt_addr + x_backed(e)) == NULL);
    }
    assert(cbae_image_section_at_va(img, x.ib + x.sec[0].rva - 1) == NULL || x.sec[0].rva == 0);

    /* imports: every entry of every lookup table, in file order */
    assert(img->import_count == x.nimp);
    for (uint32_t i = 0; i < x.nimp; i++) {
        const ximp_t *e = &x.imp[i];
        const cbae_import_entry_t *m = &img->imports[i];
        char want[CBAE_IMPORT_NAME_MAX];
        if (e->kind == 'O') snprintf(want, sizeof want, "ord#%u", e->v); else cut(want, sizeof want, e->name);
        assert(strcmp(m->name, want) == 0);
        cut(want, sizeof want, e->dll);
        assert(strcmp(m->module, want) == 0);
        assert(m->table_index == i && m->iat_va == x.ib + e->iat + 8ull * e->slot);
        assert(m->state == (e->kind == 'O' ? CBAE_IMPORT_BY_ORDINAL : CBAE_IMPORT_BY_NAME));
        assert(m->ordinal == (e->kind == 'O' ? e->v : 0) && m->hint == (e->kind == 'N' ? e->v : 0));
        assert(m->rela_offset == (cbae_off_t)CBAE_ADDR_INVALID && m->rela_type == 0);
        assert(cbae_image_import_at_iat(img, m->iat_va) == m);           /* the slot is in a loaded section and the file holds it */
        assert(cbae_image_section_at_va(img, m->iat_va) != NULL && cbae_image_va_to_ptr(img, m->iat_va) != NULL);
        const cbae_import_entry_t *first = NULL;                         /* the by-name lookup finds the first entry of that name */
        for (uint32_t j = 0; j < x.nimp && !first; j++) if (strcmp(img->imports[j].name, m->name) == 0) first = &img->imports[j];
        assert(cbae_image_import_by_name(img, m->name) == first);
    }

    /* exports: symbols 0.. */
    xexp_t *exps = (xexp_t *)calloc(x.exp_nfuncs + x.exp_nnames + 1, sizeof *exps);
    assert(exps);
    const uint32_t nexp = x.has_exp ? x_exports(&x, exps) : 0;
    assert(img->symbol_count == nexp);
    for (uint32_t i = 0; i < nexp; i++) {
        const xexp_t *e = &exps[i];
        const cbae_symbol_t *y = &img->symbols[i];
        char want[CBAE_SYM_NAME_MAX];
        cut(want, sizeof want, e->name);
        assert(strcmp(y->name, want) == 0 && y->table_index == i);
        assert(y->type == CBAE_SYM_EXPORT && y->binding == CBAE_BIND_GLOBAL && y->size == 0 && y->section_idx == 0);
        if (e->fwd) {
            char f63[64], src[CBAE_SYM_SOURCE_MAX];
            cut(f63, sizeof f63, e->fwd_text);
            snprintf(src, sizeof src, "fwd:%.56s", f63);
            assert(strcmp(y->source, src) == 0 && y->address == CBAE_ADDR_INVALID && y->kind == CBAE_KIND_FUNCTION);
        } else {
            const xsec_t *s = x_sec(&x, e->rva);
            assert(y->source[0] == '\0' && y->address == x.ib + e->rva);
            assert(y->kind == (!s ? CBAE_KIND_NOTYPE : (s->chars & 0x20000000u) ? CBAE_KIND_FUNCTION : CBAE_KIND_OBJECT));
            assert(cbae_image_symbol_at_va(img, y->address) == y);       /* no two exports of these files share an address */
            const uint64_t off = x_off(&x, e->rva);                      /* what the export names is in the file: an address finds its bytes */
            assert(off != CBAE_ADDR_INVALID && cbae_image_va_to_ptr(img, y->address) == img->file_data + off);
        }
        assert(cbae_image_symbol_by_name(img, y->name) == y);            /* and the names of one file are all different */
    }
    free(exps);

    /* base relocations: every entry of every block, padding entries too */
    assert(img->reloc_count == x.nrel);
    uint32_t dir64 = 0;
    for (uint32_t i = 0; i < x.nrel; i++) {
        const xrel_t *e = &x.rel[i];
        const cbae_relocation_t *r = &img->relocations[i];
        const uint64_t rva = (uint64_t)e->page + e->off;
        assert(r->table_index == i && r->page_rva == e->page && r->target_va == x.ib + rva);
        assert(r->type == (e->type == 0 ? CBAE_RELOC_NOP : e->type == 3 ? CBAE_RELOC_ABS32 : e->type == 10 ? CBAE_RELOC_ABS64 : CBAE_RELOC_UNKNOWN));
        assert(r->sym_index == CBAE_RELOC_NO_SYMBOL && r->addend == 0 && !r->references_import && !r->applied);
        assert(r->file_offset == x_off(&x, rva));
        if (e->type == 10) {
            /* a 64-bit fixup holds an address inside the image: this is the loaded image's own pointer, which the loader would rebase */
            assert(r->file_offset != (cbae_off_t)CBAE_ADDR_INVALID && r->file_offset + 8 <= n);
            assert(cbae_image_offset_to_va(img, r->file_offset) == r->target_va);
            uint64_t v = 0;
            for (int b = 0; b < 8; b++) v |= (uint64_t)file[r->file_offset + b] << (8 * b);
            assert(v >= x.ib && v - x.ib < x.size_of_image);
            dir64++;
        }
    }

    /* the notes: these files are complete and consistent, so there are none */
    assert(img->note_count == 0);

    tally_t t = { img->section_count, img->import_count, nexp, img->reloc_count, img->note_count, x.nsec, x.nimp, x.nrel };
    (void)dir64;
    cbae_image_destroy(&img);
    free(file);
    free_expect(&x);
    return t;
}

/* What each fixture is for: a fixture regenerated without the feature it exists to test would pass every other check and test nothing. */
static void check_features(void) {
    char path[600];
    xp_t x;
    snprintf(path, sizeof path, "%s/drv.sys.expect", CBAE_PE_FIXTURES);
    parse_expect(path, &x);
    bool ordinal = false, by_name = false, discardable = false, wide = false, padded = false, rsds = false;
    uint32_t pages = 0, last_page = UINT32_MAX, hint = 0;
    for (uint32_t i = 0; i < x.nimp; i++) { ordinal |= x.imp[i].kind == 'O'; by_name |= x.imp[i].kind == 'N'; hint += x.imp[i].kind == 'N' && x.imp[i].v != 0; }
    for (uint32_t i = 0; i < x.nsec; i++) discardable |= (x.sec[i].chars & 0x02000000u) && (x.sec[i].chars & 0x20000000u);
    for (uint32_t i = 0; i < x.nrel; i++) { if (x.rel[i].page != last_page) { pages++; last_page = x.rel[i].page; } padded |= x.rel[i].type == 0; wide |= x.rel[i].type == 10; }
    rsds = x.pdb[0] != '\0';
    assert(ordinal && by_name && hint == 6 && discardable && wide && padded && rsds && pages == 2 && x.nrel > 600);
    assert(x.dir_rva[1] && x.dir_rva[3] && x.dir_rva[5] && x.dir_rva[6]);                      /* imports, exceptions, relocations, debug */
    bool bss = false;
    for (uint32_t i = 0; i < x.nsec; i++) bss |= x_extent(&x.sec[i]) > x.sec[i].rawsize;       /* zero-filled memory that the file does not hold */
    assert(bss);
    free_expect(&x);

    snprintf(path, sizeof path, "%s/drv.min.sys.expect", CBAE_PE_FIXTURES);
    parse_expect(path, &x);
    assert(x.nrel == 0 && x.dir_rva[5] == 0 && x.pdb[0] == '\0' && x.nimp == 7);
    assert(x.sec[0].rva == x.sec[0].rawptr && x.sec[1].rva == x.sec[1].rawptr);                // flat: RVA = file offset, for the first sections
    free_expect(&x);

    snprintf(path, sizeof path, "%s/lib.dll.expect", CBAE_PE_FIXTURES);
    parse_expect(path, &x);
    bool fwd = false, unnamed = false;
    for (uint32_t s = 0; s < x.exp_nfuncs; s++) {
        fwd |= x.eat[s].fwd[0] != '\0';
        bool named = false;
        for (uint32_t i = 0; i < x.exp_nnames; i++) named |= x.enm[i].slot == s;
        unnamed |= x.eat[s].rva != 0 && !named;
    }
    assert(x.has_exp && fwd && unnamed && x.exp_base == 7 && x.exp_nfuncs == 5 && x.exp_nnames == 4 && x.machine == 0x8664);
    free_expect(&x);

    snprintf(path, sizeof path, "%s/lib.arm64.dll.expect", CBAE_PE_FIXTURES);
    parse_expect(path, &x);
    assert(x.machine == 0xAA64 && x.has_exp && x.nimp == 2);
    free_expect(&x);
}

/* ---- the same files, cut and damaged: whatever the loader makes of them must satisfy pe_check.h ---- */

static bool quick(void) { const char *q = getenv("CBAE_TEST_QUICK"); return q && q[0] && q[0] != '0'; }

/* loads an exactly sized copy; true if it loaded. An image must pass the check, a refusal must be a refusal and leave nothing. */
static bool load_copy(const uint8_t *bytes, size_t n) {
    uint8_t *copy = (uint8_t *)malloc(n ? n : 1);
    assert(copy);
    if (n) memcpy(copy, bytes, n);
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_pe_load_buffer(copy, n, "real.sys", &img);
    bool ok = false;
    if (rc == CBAE_OK) {
        assert(img);
        pe_check_image(img, copy, n);
        cbae_image_destroy(&img);
        ok = true;
    } else {
        assert((rc == CBAE_ERR_PARSE || rc == CBAE_ERR_OVERFLOW || rc == CBAE_ERR_UNSUPPORTED) && img == NULL);
    }
    free(copy);
    return ok;
}

static uint64_t awkward(rng_t *r, size_t n, const xp_t *x) {
    uint64_t pool[48] = { 0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFF00, 0xFFFFFFFFu, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull,
                          0x8000000000000000ull, UINT64_MAX, UINT64_MAX - 1, (uint64_t)n, (uint64_t)n - 1, (uint64_t)n + 1, 24, 64, 4096,
                          0x7FFFFFFF, 0x80000000u, 0xFFFFF000u, x->size_of_image, x->size_of_headers };
    uint32_t k = 28;
    for (uint32_t i = 0; i < x->nsec && k + 2 <= 48; i++) { pool[k++] = x->sec[i].rva; pool[k++] = x->sec[i].rva + x_extent(&x->sec[i]); }
    return pool[rn(r, k)];
}

static void put(uint8_t *b, size_t n, size_t p, uint64_t v, unsigned bytes) {
    for (unsigned i = 0; i < bytes && p + i < n; i++) b[p + i] = i < 8 ? (uint8_t)(v >> (8 * i)) : 0;      /* more than 8 bytes: zero fill */
}

/* the end of the headers: DOS header, COFF header, optional header with its directories, section table */
static size_t header_end(const uint8_t *f, size_t n) {
    const size_t lfanew = (size_t)f[0x3C] | (size_t)f[0x3D] << 8 | (size_t)f[0x3E] << 16 | (size_t)f[0x3F] << 24;
    const size_t optsz = (size_t)f[lfanew + 20] | (size_t)f[lfanew + 21] << 8, nsec = (size_t)f[lfanew + 6] | (size_t)f[lfanew + 7] << 8;
    const size_t end = lfanew + 24 + optsz + 40 * nsec;
    return end < n ? end : n;
}

static void sweep_file(const char *base, uint32_t iterations, uint64_t seed, uint32_t *loaded, uint32_t *refused, uint32_t *prefix_loaded, uint32_t *prefixes) {
    char path[600], epath[620];
    snprintf(path, sizeof path, "%s/%s", CBAE_PE_FIXTURES, base);
    snprintf(epath, sizeof epath, "%s.expect", path);
    size_t n;
    uint8_t *orig = slurp(path, &n);
    uint8_t *w = (uint8_t *)malloc(n);
    assert(w);
    xp_t x;
    parse_expect(epath, &x);
    const size_t hend = header_end(orig, n);

    /* prefixes: every length (a quick run takes every length up to the end of the headers, those within a few bytes of an edge of a
     * section's file data or of a data directory's table, and a sample of the rest) */
    bool *want = (bool *)calloc(n + 1, 1);
    assert(want);
    if (!quick()) memset(want, 1, n + 1);
    else {
        for (size_t len = 0; len <= n; len++) want[len] = len <= hend + 8 || len % 61 == 0;
        for (uint32_t i = 0; i < x.nsec; i++)
            for (int d = -3; d <= 3; d++) {
                const int64_t a = (int64_t)x.sec[i].rawptr + d, b = (int64_t)x.sec[i].rawptr + x.sec[i].rawsize + d;
                if (a >= 0 && (size_t)a <= n) want[a] = true;
                if (b >= 0 && (size_t)b <= n) want[b] = true;
            }
        for (uint32_t i = 0; i < PE_DIRS; i++) {
            if (!x.dir_rva[i]) continue;
            const uint64_t o = x_off(&x, x.dir_rva[i]);
            if (o == CBAE_ADDR_INVALID) continue;
            for (int d = -3; d <= 3; d++) {
                const int64_t a = (int64_t)o + d, b = (int64_t)o + x.dir_size[i] + d;
                if (a >= 0 && (size_t)a <= n) want[a] = true;
                if (b >= 0 && (size_t)b <= n) want[b] = true;
            }
        }
    }
    for (size_t len = 0; len <= n; len++) if (want[len]) { (*prefixes)++; *prefix_loaded += load_copy(orig, len); }
    free(want);

    /* damage, aimed at the structures: headers and directories, the tables inside the sections, anywhere */
    rng_t r = { seed * 0x9E3779B97F4A7C15ull + 1 };
    for (uint32_t it = 0; it < iterations; it++) {
        memcpy(w, orig, n);
        const uint32_t hits = 1 + rn(&r, 3);
        for (uint32_t h = 0; h < hits; h++) {
            const uint32_t where = rn(&r, 10);
            size_t p;
            if (where < 4) p = rn(&r, (uint32_t)hend);
            else if (where < 8) {
                const xsec_t *s = &x.sec[rn(&r, x.nsec)];
                p = (size_t)s->rawptr + (s->rawsize ? rn(&r, s->rawsize) : 0);
            } else p = rn(&r, (uint32_t)n);
            const uint32_t how = rn(&r, 7);
            if (how == 0) put(w, n, p, rnd(&r), 1);
            else if (how == 1) put(w, n, p, awkward(&r, n, &x), 4);
            else if (how == 2) put(w, n, p & ~(size_t)7, awkward(&r, n, &x), 8);
            else if (how == 3) put(w, n, p & ~(size_t)3, awkward(&r, n, &x), 4);
            else if (how == 4) { const size_t q = rn(&r, (uint32_t)n), len = 8 + rn(&r, 56); for (size_t i = 0; i < len && p + i < n && q + i < n; i++) w[p + i] = w[q + i]; }
            else if (how == 5) put(w, n, p, 0, 1 + rn(&r, 16));
            else { const size_t q = p & ~(size_t)3; uint32_t v = 0; for (int b = 0; b < 4 && q + b < n; b++) v |= (uint32_t)w[q + b] << (8 * b); v += (uint32_t)(int)(rn(&r, 9)) - 4; put(w, n, q, v, 4); }
        }
        size_t len = n;
        if (rn(&r, 8) == 0) len = rn(&r, (uint32_t)n + 1);
        if (load_copy(w, len)) (*loaded)++; else (*refused)++;
    }
    free_expect(&x);
    free(w);
    free(orig);
}

/* ---- out of memory ---- */

typedef struct { const uint8_t *b; size_t n; uint32_t nsec, nimp, nsym, nrel; } oom_ctx_t;

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
    assert(img->section_count == c->nsec && img->import_count == c->nimp && img->symbol_count == c->nsym && img->reloc_count == c->nrel);   /* complete, not partial */
    cbae_image_destroy(&img);
    return CBAE_OK;
}

static oom_report_t oom_file(const char *base, const tally_t *t) {
    char path[600];
    snprintf(path, sizeof path, "%s/%s", CBAE_PE_FIXTURES, base);
    size_t n;
    uint8_t *bytes = slurp(path, &n);
    oom_ctx_t ctx = { bytes, n, t->sections, t->imports, t->exports, t->relocs };
    const oom_report_t r = oom_sweep(oom_body, &ctx, true);
    assert(r.allocations > 5 && r.runs == 2 * r.allocations && r.reported > 0 && r.swallowed == 0);
    free(bytes);
    return r;
}

int main(void) {
    printf("=== test_pe_real ===\n");
    static const char *const files[] = { "drv.sys", "drv.min.sys", "lib.dll", "lib.arm64.dll" };
    char msg[600];
    tally_t tallies[4];
    check_features();
    PASS("the fixtures hold what they are for: an ordinal import, hints, a discardable section, base relocations over two pages with padding, a CodeView path; flat layout without relocations; a forwarder, an unnamed export; ARM64");
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        tallies[i] = check_file(files[i]);
        const tally_t *t = &tallies[i];
        snprintf(msg, sizeof msg, "%s: %u sections, %u imports, %u exports, %u relocation entries, %u notes: all as the expectation says", files[i], t->sections, t->imports, t->exports, t->relocs, t->notes);
        PASS(msg);
    }
    uint32_t loaded = 0, refused = 0, pl = 0, pn = 0;
    const uint32_t iterations = quick() ? 1500 : 8000;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) sweep_file(files[i], iterations, 200 + i, &loaded, &refused, &pl, &pn);
    snprintf(msg, sizeof msg, "%u prefixes of the %zu real files (%u loaded) and %u randomly damaged copies (%u loaded, %u refused): nothing crashed or read out of bounds, every image passes the check",
             pn, sizeof files / sizeof files[0], pl, loaded + refused, loaded, refused);
    PASS(msg);
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        const oom_report_t r = oom_file(files[i], &tallies[i]);
        snprintf(msg, sizeof msg, "%s: out of memory at each of the %llu allocations of a load (alone, and with every later one failing): %llu errors, no leak, none swallowed", files[i],
                 (unsigned long long)r.allocations, (unsigned long long)r.reported);
        PASS(msg);
    }
    printf("All real-file PE tests passed.\n");
    return 0;
}
