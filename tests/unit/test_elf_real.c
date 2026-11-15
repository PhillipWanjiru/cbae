/**
 * @file test_elf_real.c
 * @brief The ELF loader on files that a real compiler and linker made.
 *
 * Every other ELF test builds its files with elf_builder.h, which only makes what its author thought of. These are made by gcc,
 * g++ and ld (tests/fixtures/elf): a kernel-module-shaped object compiled with the kernel code model, a C++ object (COMDAT
 * groups, SHF_GROUP, a vtable, thread-local storage, exceptions, a global constructor), a shared object and a static executable.
 * The loader is held to what is in the files, as the .expect files in tests/fixtures/elf record it: every section header, symbol and
 * relocation entry, read from the bytes by make_expect.py and checked there against pyelftools and readelf. The loader is not
 * involved in making them.
 *
 * What the file says is not what the image holds. The rules that turn one into the other (where a relocatable section goes, which
 * relocations are kept, what an import is, which notes are due) are written out below from the documentation in loader/elf_loader.h,
 * as arithmetic on the expectation, and the image is compared with the result: sections, symbols (and the exports that have none),
 * relocations, imports, .modinfo, notes. Then the same files are cut at every length and damaged at random: whatever the loader
 * makes of them must satisfy elf_check.h.
 */
#include "loader/elf_loader.h"
#include "elf_builder.h"
#include "elf_check.h"
#include "elf_model.h"
#include "pe_random.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CBAE_ELF_FIXTURES
#error "CBAE_ELF_FIXTURES must be the path of tests/fixtures/elf"
#endif

#define PASS(name) printf("  [PASS] %s\n", name)

static bool has_note(const cbae_binary_image_t *img, const char *part) {
    const uint32_t kept = img->note_count < CBAE_IMAGE_NOTES_MAX ? img->note_count : CBAE_IMAGE_NOTES_MAX;
    for (uint32_t i = 0; i < kept; i++) if (strstr(img->notes[i], part)) return true;
    return false;
}

/* ---- the expectation file ---- */

typedef struct { uint32_t type, link, info; uint64_t flags, addr, off, size, align, entsize; char name[200]; } xsec_t;
typedef struct { uint32_t idx, bind, type, shndx; uint64_t value, size; char name[400]; } xsym_t;
typedef struct { uint32_t sec, entry, sym, type; uint64_t off; int64_t addend; } xrel_t;

typedef struct {
    uint32_t etype, machine, shnum, symtab;
    uint64_t entry;
    xsec_t *sec;
    xsym_t *sym;  uint32_t nsym;                          /* ELF symbols 1..nsym */
    xrel_t *rel;  uint32_t nrel;
    char (*ksym)[256]; uint32_t nksym;
    char meta[4][256]; bool has_meta[4];                  /* license author description vermagic */
} xp_t;

static const char *const META_KEYS[4] = { "license", "author", "description", "vermagic" };

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    assert(f && "fixture missing: run tests/fixtures/elf/regen.sh");
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
    uint32_t cap_sym = 0, cap_rel = 0, cap_ks = 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#') continue;
        unsigned long long a, b, c, d, e, f, g, h;
        unsigned u, v, w;
        long long addend;
        int off = 0;
        if (sscanf(line, "elf %u %u %llu %u %u", &u, &v, &a, &w, &x->symtab) == 5) {
            x->etype = u; x->machine = v; x->entry = a; x->shnum = w;
            x->sec = (xsec_t *)calloc(w, sizeof *x->sec);
            assert(x->sec);
        } else if (strncmp(line, "sec ", 4) == 0) {
            unsigned idx, type, link, info;
            char name[200];
            assert(sscanf(line, "sec %u %u %llu %llu %llu %llu %llu %llu %u %u %199s", &idx, &type, &a, &b, &c, &d, &e, &f, &link, &info, name) == 11);
            assert(idx < x->shnum);
            xsec_t *s = &x->sec[idx];
            s->type = type; s->flags = a; s->addr = b; s->off = c; s->size = d; s->align = e; s->entsize = f; s->link = link; s->info = info;
            snprintf(s->name, sizeof s->name, "%s", strcmp(name, "-") == 0 ? "" : name);
        } else if (strncmp(line, "sym ", 4) == 0) {
            unsigned idx, bind, type, shndx;
            char name[400];
            assert(sscanf(line, "sym %u %u %u %u %llu %llu %399s", &idx, &bind, &type, &shndx, &a, &b, name) == 7);
            if (x->nsym == cap_sym) { cap_sym = cap_sym ? cap_sym * 2 : 64; x->sym = (xsym_t *)realloc(x->sym, cap_sym * sizeof *x->sym); assert(x->sym); }
            xsym_t *y = &x->sym[x->nsym++];
            assert(idx == x->nsym);                         /* consecutive, from 1 */
            y->idx = idx; y->bind = bind; y->type = type; y->shndx = shndx; y->value = a; y->size = b;
            snprintf(y->name, sizeof y->name, "%s", strcmp(name, "-") == 0 ? "" : name);
        } else if (strncmp(line, "rel ", 4) == 0) {
            unsigned sec, entry, sym, type;
            assert(sscanf(line, "rel %u %u %llu %u %u %lld", &sec, &entry, &a, &sym, &type, &addend) == 6);
            if (x->nrel == cap_rel) { cap_rel = cap_rel ? cap_rel * 2 : 128; x->rel = (xrel_t *)realloc(x->rel, cap_rel * sizeof *x->rel); assert(x->rel); }
            xrel_t *r = &x->rel[x->nrel++];
            r->sec = sec; r->entry = entry; r->off = a; r->sym = sym; r->type = type; r->addend = addend;
        } else if (strncmp(line, "ksym ", 5) == 0) {
            if (x->nksym == cap_ks) { cap_ks = cap_ks ? cap_ks * 2 : 8; x->ksym = (char (*)[256])realloc(x->ksym, cap_ks * sizeof *x->ksym); assert(x->ksym); }
            snprintf(x->ksym[x->nksym++], 256, "%s", line + 5);
        } else if (strncmp(line, "meta ", 5) == 0) {
            char key[16];
            assert(sscanf(line, "meta %15s %n", key, &off) == 1);
            for (int k = 0; k < 4; k++)
                if (strcmp(key, META_KEYS[k]) == 0) { snprintf(x->meta[k], sizeof x->meta[k], "%s", line + off); x->has_meta[k] = true; }
        } else {
            assert(!"unknown record in an .expect file");
        }
        (void)c; (void)d; (void)e; (void)f; (void)g; (void)h; (void)u; (void)v; (void)w; (void)addend;
    }
    free(text);
    assert(x->shnum > 1 && x->sec[0].type == 0);
}

static void free_expect(xp_t *x) { free(x->sec); free(x->sym); free(x->rel); free(x->ksym); }

/* ---- the rules, from elf_loader.h ---- */

static bool x_loaded(const xp_t *x, uint32_t i) { return i > 0 && i < x->shnum && (x->sec[i].flags & 2u) != 0; }          /* SHF_ALLOC */

/* a relocatable object's loaded sections: the first at 0x400000, each on a page boundary or its alignment if that is larger, after the one before */
static void x_layout(const xp_t *x, uint64_t *va) {
    uint64_t cursor = 0x400000;
    for (uint32_t i = 1; i < x->shnum; i++) {
        va[i] = 0;
        if (!x_loaded(x, i)) continue;
        uint64_t a = x->sec[i].align;
        assert(a == 0 || (a & (a - 1)) == 0);                 /* the plain kind: these are real files */
        if (a < 4096) a = 4096;
        va[i] = (cursor + a - 1) / a * a;
        cursor = va[i] + x->sec[i].size;
    }
}

static bool x_is_import(const xsym_t *y) { return y->shndx == 0 && y->type != 3 && y->type != 4; }    /* undefined, not a section or file symbol */

/* ---- one file ---- */

typedef struct { uint32_t sections, symbols, exports, relocs_kept, relocs_total, imports, notes; } tally_t;

static tally_t check_file(const char *base) {
    char path[600], epath[620];
    snprintf(path, sizeof path, "%s/%s", CBAE_ELF_FIXTURES, base);
    snprintf(epath, sizeof epath, "%s.expect", path);
    xp_t x;
    parse_expect(epath, &x);
    size_t n;
    uint8_t *file = slurp(path, &n);
    cbae_binary_image_t *img = NULL;
    assert(cbae_elf_load(path, &img) == CBAE_OK && img);
    elf_check_image(img, file, n);

    const bool rel = x.etype == 1;
    uint64_t *va = (uint64_t *)calloc(x.shnum, sizeof *va);
    assert(va);
    if (rel) x_layout(&x, va);
    for (uint32_t i = 1; i < x.shnum; i++) if (!rel) va[i] = x.sec[i].addr;

    /* header facts */
    assert(img->arch == CBAE_ARCH_X86_64 && x.machine == 62);
    assert(img->entry_point == (!rel && x.entry ? x.entry : CBAE_ADDR_INVALID));

    /* sections: one for every header but the first, in table order */
    assert(img->section_count == x.shnum - 1);
    uint32_t cut_names = 0;
    for (uint32_t i = 1; i < x.shnum; i++) {
        const xsec_t *e = &x.sec[i];
        const cbae_section_t *s = &img->sections[i - 1];
        assert(e->type != 0);
        char want[CBAE_SEC_NAME_MAX];
        em_cut(want, e->name, sizeof want);
        assert(strcmp(s->name, want) == 0);
        if (strlen(e->name) > CBAE_SEC_NAME_MAX - 1) cut_names++;
        const bool loaded = x_loaded(&x, i);
        uint32_t flags = 0;
        if (loaded) { flags |= CBAE_SEC_READ; if (e->flags & 4u) flags |= CBAE_SEC_EXEC; if (e->flags & 1u) flags |= CBAE_SEC_WRITE; }
        if (e->type == 8) flags |= CBAE_SEC_BSS;
        if (e->type == 4 || e->type == 9) flags |= CBAE_SEC_RELOC;
        assert(s->flags == flags);
        assert(s->virt_addr == (loaded ? va[i] : 0) && s->virt_size == (loaded ? e->size : 0));
        assert(s->file_offset == e->off);
        const uint64_t held = e->type == 8 ? 0 : e->size;
        assert(s->file_size == held);
        if (held) assert(s->data == img->file_data + e->off && memcmp(s->data, file + e->off, held) == 0);
        else assert(s->data == NULL);
        if (loaded && rel && e->size) {                       /* a relocatable object's sections do not overlap: an address finds its own section */
            assert(cbae_image_section_at_va(img, va[i]) == s && cbae_image_section_at_va(img, va[i] + e->size - 1) == s);
            assert(cbae_image_section_by_name(img, s->name) != NULL);
        }
    }

    /* symbols: ELF symbol k is img->symbols[k - 1] */
    uint32_t unmapped = 0;
    for (uint32_t k = 1; k <= x.nsym; k++) {
        const xsym_t *e = &x.sym[k - 1];
        const cbae_symbol_t *y = &img->symbols[k - 1];
        assert(y->table_index == k - 1);
        char want[CBAE_SYM_NAME_MAX];
        em_cut(want, e->type == 3 ? (e->shndx >= 1 && e->shndx < x.shnum ? x.sec[e->shndx].name : "") : e->name, sizeof want);
        assert(strcmp(y->name, want) == 0);
        assert(y->binding == (e->bind == 1 || e->bind == 10 ? CBAE_BIND_GLOBAL : e->bind == 2 ? CBAE_BIND_WEAK : CBAE_BIND_LOCAL));
        const cbae_sym_kind_t kind = e->type == 2 || e->type == 10 ? CBAE_KIND_FUNCTION : e->type == 1 || e->type == 5 || e->type == 6 ? CBAE_KIND_OBJECT
                                   : e->type == 0 || e->type == 3 || e->type == 4 ? CBAE_KIND_NOTYPE : CBAE_KIND_UNKNOWN;
        assert(y->kind == kind && y->size == e->size && y->section_idx == (uint16_t)e->shndx);
        const cbae_sym_type_t type = e->type == 4 ? CBAE_SYM_FILE : e->type == 3 ? CBAE_SYM_SECTION : e->shndx == 0 ? CBAE_SYM_IMPORT
                                   : e->bind == 0 ? CBAE_SYM_LOCAL : CBAE_SYM_EXPORT;
        assert(y->type == type);
        assert(strcmp(y->source, type == CBAE_SYM_IMPORT ? "kernel" : "") == 0);
        uint64_t addr = CBAE_ADDR_INVALID;
        if (e->shndx == 0 || e->type == 4 || e->type == 5 || e->type == 6 || e->shndx == 0xFFF2) {
            /* undefined, a file, common or thread-local: nowhere */
        } else if (e->shndx == 0xFFF1) {
            addr = e->value;                                 /* absolute */
        } else {
            assert(e->shndx < 0xFF00 && e->shndx < x.shnum);
            if (!x_loaded(&x, e->shndx)) unmapped++;
            else if (!rel) addr = e->value;
            else if (e->value <= x.sec[e->shndx].size) addr = va[e->shndx] + e->value;
        }
        assert(y->address == addr);
    }

    /* exports without a symbol: the names in __ksymtab_strings that no defined global or weak symbol carries, in order */
    uint32_t pseudo = 0;
    for (uint32_t j = 0; j < x.nksym; j++) {
        bool defined = false;
        for (uint32_t k = 0; k < x.nsym; k++) {
            const xsym_t *e = &x.sym[k];
            if (e->shndx != 0 && e->type != 3 && e->type != 4 && e->bind != 0 && strcmp(e->name, x.ksym[j]) == 0) defined = true;
        }
        if (defined) continue;
        assert(x.nsym + pseudo < img->symbol_count);
        const cbae_symbol_t *y = &img->symbols[x.nsym + pseudo];
        assert(strcmp(y->name, x.ksym[j]) == 0 && y->type == CBAE_SYM_EXPORT && y->binding == CBAE_BIND_GLOBAL && y->kind == CBAE_KIND_UNKNOWN);
        assert(y->address == CBAE_ADDR_INVALID && y->table_index == x.nsym + pseudo && y->size == 0 && y->section_idx == 0);
        pseudo++;
    }
    assert(img->symbol_count == x.nsym + pseudo);

    /* a defined symbol that is the only one of its name is what the by-name lookup finds */
    for (uint32_t k = 0; k < x.nsym; k++) {
        const xsym_t *e = &x.sym[k];
        if (!e->name[0] || e->type == 3 || e->type == 4) continue;
        uint32_t same = 0;
        for (uint32_t j = 0; j < x.nsym; j++) same += strcmp(x.sym[j].name, e->name) == 0 && x.sym[j].type != 3 && x.sym[j].type != 4;
        if (same == 1) assert(cbae_image_symbol_by_name(img, e->name) == &img->symbols[k]);
        else assert(cbae_image_symbol_by_name(img, e->name) != NULL);
    }

    /* relocations: SHT_RELA sections in table order; ET_REL keeps the entries that patch a loaded section, a linked file all of them */
    uint32_t kept = 0, unloaded = 0, foreign = 0, nimp = 0;
    bool *imported = (bool *)calloc(x.nsym + 1u, sizeof *imported);
    assert(imported);
    for (uint32_t i = 0; i < x.nrel; i++) {
        const xrel_t *r = &x.rel[i];
        const xsec_t *rs = &x.sec[r->sec];
        assert(rs->type == 4);
        const uint32_t tgt = rs->info;
        uint64_t target_va = r->off, file_off = CBAE_ADDR_INVALID;
        if (rel) {
            assert(tgt >= 1 && tgt < x.shnum);
            if (!x_loaded(&x, tgt)) { unloaded++; continue; }
            assert(r->off < x.sec[tgt].size);
            target_va = va[tgt] + r->off;
            if (x.sec[tgt].type != 8) file_off = x.sec[tgt].off + r->off;
        }
        const bool symtab_ok = x.symtab != 0 && rs->link == x.symtab;
        const bool sym_ok = symtab_ok && r->sym != 0 && r->sym <= x.nsym;
        if (r->sym != 0 && !sym_ok) foreign++;
        assert(kept < img->reloc_count);
        const cbae_relocation_t *o = &img->relocations[kept];
        assert(o->table_index == kept && !o->applied && o->target_va == target_va && o->file_offset == file_off);
        assert(o->type == em_reloc_type(EB_EM_X86_64, r->type) && o->addend == r->addend);
        assert(o->sym_index == (sym_ok ? r->sym - 1 : CBAE_RELOC_NO_SYMBOL));
        const bool import = sym_ok && x_is_import(&x.sym[r->sym - 1]);
        assert(o->references_import == import);
        if (import && !imported[r->sym]) {
            imported[r->sym] = true;
            assert(nimp < img->import_count);
            const cbae_import_entry_t *im = &img->imports[nimp];
            char name[CBAE_IMPORT_NAME_MAX];
            em_cut(name, x.sym[r->sym - 1].name, sizeof name);
            assert(strcmp(im->name, name) == 0 && strcmp(im->module, "kernel") == 0 && im->table_index == nimp);
            assert(im->iat_va == CBAE_ADDR_INVALID && im->rela_offset == file_off && im->rela_type == r->type && im->state == CBAE_IMPORT_UNRESOLVED);
            nimp++;
        }
        kept++;
    }
    free(imported);
    assert(kept == img->reloc_count && nimp == img->import_count);

    /* .modinfo and __ksymtab_strings */
    char want[256];
    em_cut(want, x.meta[3], sizeof img->meta.elf.kernel_version);       assert(strcmp(img->meta.elf.kernel_version, want) == 0);
    em_cut(want, x.meta[0], sizeof img->meta.elf.module_license);       assert(strcmp(img->meta.elf.module_license, want) == 0);
    em_cut(want, x.meta[1], sizeof img->meta.elf.module_author);        assert(strcmp(img->meta.elf.module_author, want) == 0);
    em_cut(want, x.meta[2], sizeof img->meta.elf.module_description);   assert(strcmp(img->meta.elf.module_description, want) == 0);
    bool has_ks = false;
    for (uint32_t i = 1; i < x.shnum; i++) has_ks |= strcmp(x.sec[i].name, "__ksymtab_strings") == 0;
    assert(img->meta.elf.has_ksymtab == has_ks);

    /* notes: exactly the ones the file's contents call for */
    uint32_t want_notes = 0;
    char text[200];
    if (cut_names) { snprintf(text, sizeof text, "%u section names are longer than 31 bytes and were cut", cut_names); assert(has_note(img, text)); want_notes++; }
    if (unmapped) { snprintf(text, sizeof text, "%u symbols are in sections that are not loaded: they have no address", unmapped); assert(has_note(img, text)); want_notes++; }
    if (unloaded) { snprintf(text, sizeof text, "%u relocation entries apply to sections that are not loaded", unloaded); assert(has_note(img, text)); want_notes++; }
    if (foreign) { snprintf(text, sizeof text, "%u relocations name a symbol that is not in the symbol table that was read", foreign); assert(has_note(img, text)); want_notes++; }
    assert(img->note_count == want_notes);

    tally_t t = { img->section_count, x.nsym, pseudo, kept, x.nrel, nimp, img->note_count };
    cbae_image_destroy(&img);
    free(va);
    free(file);
    free_expect(&x);
    return t;
}

/* ---- the same files, cut and damaged: whatever the loader makes of them must satisfy elf_check.h ---- */

static bool quick(void) { const char *q = getenv("CBAE_TEST_QUICK"); return q && q[0] && q[0] != '0'; }

/* loads an exactly sized copy; true if it loaded. An image must pass the check, a refusal must be PARSE (or OVERFLOW) and leave nothing. */
static bool load_copy(const uint8_t *bytes, size_t n) {
    uint8_t *copy = (uint8_t *)malloc(n ? n : 1);
    assert(copy);
    if (n) memcpy(copy, bytes, n);
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_elf_load_buffer(copy, n, "real.o", &img);
    bool ok = false;
    if (rc == CBAE_OK) {
        assert(img);
        elf_check_image(img, copy, n);
        cbae_image_destroy(&img);
        ok = true;
    } else {
        assert((rc == CBAE_ERR_PARSE || rc == CBAE_ERR_OVERFLOW) && img == NULL);
    }
    free(copy);
    return ok;
}

static uint64_t awkward(rng_t *r, size_t n) {
    const uint64_t pool[] = { 0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFF00, 0xFFFFFFFFu, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull,
                              0x8000000000000000ull, UINT64_MAX, UINT64_MAX - 1, (uint64_t)n, (uint64_t)n - 1, (uint64_t)n + 1, 24, 64, 4096 };
    return pool[rn(r, (uint32_t)(sizeof pool / sizeof pool[0]))];
}

static void put(uint8_t *b, size_t n, size_t p, uint64_t v, unsigned bytes) {
    for (unsigned i = 0; i < bytes && p + i < n; i++) b[p + i] = i < 8 ? (uint8_t)(v >> (8 * i)) : 0;      /* more than 8 bytes: zero fill */
}

static void sweep_file(const char *base, uint32_t iterations, uint64_t seed, uint32_t *loaded, uint32_t *refused, uint32_t *prefix_loaded, uint32_t *prefixes) {
    char path[600];
    snprintf(path, sizeof path, "%s/%s", CBAE_ELF_FIXTURES, base);
    size_t n;
    uint8_t *orig = slurp(path, &n);
    uint8_t *w = (uint8_t *)malloc(n);
    assert(w);

    /* every prefix */
    for (size_t len = 0; len <= n; len++) { (*prefixes)++; *prefix_loaded += load_copy(orig, len); }

    /* damage, aimed at the tables: the section header table (half of it), the symbol table and relocation sections, anywhere */
    uint64_t shoff = 0; uint32_t shnum = 0;
    for (int i = 0; i < 8; i++) shoff |= (uint64_t)orig[40 + i] << (8 * i);
    shnum = (uint32_t)(orig[60] | (orig[61] << 8));
    xp_t x;
    char epath[620];
    snprintf(epath, sizeof epath, "%s.expect", path);
    parse_expect(epath, &x);
    rng_t r = { seed * 0x9E3779B97F4A7C15ull + 1 };
    for (uint32_t it = 0; it < iterations; it++) {
        memcpy(w, orig, n);
        const uint32_t hits = 1 + rn(&r, 3);
        for (uint32_t h = 0; h < hits; h++) {
            const uint32_t where = rn(&r, 10);
            size_t p;
            if (where < 5) p = (size_t)shoff + rn(&r, shnum * 64u);
            else if (where < 8) {
                const xsec_t *s = &x.sec[x.symtab && rn(&r, 2) ? x.symtab : 1 + rn(&r, x.shnum - 1)];
                p = (size_t)s->off + (s->size ? rn(&r, (uint32_t)(s->size > 0xFFFFFF ? 0xFFFFFF : s->size)) : 0);
            } else p = rn(&r, (uint32_t)n);
            const uint32_t how = rn(&r, 6);
            if (how == 0) put(w, n, p, rnd(&r), 1);
            else if (how == 1) put(w, n, p, awkward(&r, n), 4);
            else if (how == 2 || how == 3) put(w, n, p & ~(size_t)7, awkward(&r, n), 8);
            else if (how == 4) { const size_t q = rn(&r, (uint32_t)n), len = 8 + rn(&r, 56); for (size_t i = 0; i < len && p + i < n && q + i < n; i++) w[p + i] = w[q + i]; }
            else put(w, n, p, 0, 1 + rn(&r, 16));
        }
        size_t len = n;
        if (rn(&r, 8) == 0) len = rn(&r, (uint32_t)n + 1);
        if (load_copy(w, len)) (*loaded)++; else (*refused)++;
    }
    free_expect(&x);
    free(w);
    free(orig);
}

int main(void) {
    printf("=== test_elf_real ===\n");
    static const char *const files[] = { "kmod.o", "cxx.o", "lib.so", "exe", "lib.stripped.so", "exe.stripped" };
    char msg[400];
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        const tally_t t = check_file(files[i]);
        snprintf(msg, sizeof msg, "%s: %u sections, %u symbols (+%u exports without one), %u of %u relocation entries kept, %u imports, %u notes: all as the expectation says",
                 files[i], t.sections, t.symbols, t.exports, t.relocs_kept, t.relocs_total, t.imports, t.notes);
        PASS(msg);
    }
    uint32_t loaded = 0, refused = 0, pl = 0, pn = 0;
    const uint32_t iterations = quick() ? 1500 : 15000;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) sweep_file(files[i], iterations, 100 + i, &loaded, &refused, &pl, &pn);
    snprintf(msg, sizeof msg, "%u prefixes of the %zu real files (%u loaded) and %u randomly damaged copies (%u loaded, %u refused): nothing crashed or read out of bounds, every image passes the check",
             pn, sizeof files / sizeof files[0], pl, loaded + refused, loaded, refused);
    PASS(msg);
    printf("All real-file ELF tests passed.\n");
    return 0;
}
