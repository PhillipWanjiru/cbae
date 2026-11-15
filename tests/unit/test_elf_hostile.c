/**
 * @file test_elf_hostile.c
 * @brief The ELF loader against damaged and hostile files (audit A-036, A-037).
 *
 * The contract, whatever the bytes: the loader either refuses the file with an error code (CBAE_ERR_PARSE
 * or CBAE_ERR_OVERFLOW) and leaves no image, or returns an image that satisfies elf_check_image(); it
 * never reads outside its input, never wraps an address or a size, never allocates in proportion to a
 * number the file merely claims. The sanitizers make the first half visible: the image owns an exactly
 * sized heap copy of the file, so AddressSanitizer and Valgrind see a read one byte too far.
 *
 *   prefixes        every prefix of valid files (a download cut anywhere)
 *   one lie         a good file with ONE field set to each of ~40 awkward values, for every field of the
 *                   header, every section header, every symbol, every relocation and the extended index
 *                   table, over three different good files
 *   string bytes    every byte of the string tables, .modinfo and __ksymtab_strings set to NUL, 0xFF and '='
 *   random damage   seeded random byte, word and block damage, and truncation, on random valid files
 *   amplification   many sections sharing one relocation table, tens of thousands of imports and exports,
 *                   tables the budget refuses: bounded work and memory
 *   threads         concurrent loads share nothing
 */
#include "loader/elf_loader.h"
#include "elf_builder.h"
#include "elf_check.h"
#include "elf_random.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define QUICK (getenv("CBAE_TEST_QUICK") != NULL)

typedef struct { uint64_t ok, parse, overflow; } tally_t;

/* Loads b[0..n); the contract above. */
static void hostile_load(const uint8_t *b, size_t n, tally_t *t) {
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_elf_load_buffer(b, n, "hostile.ko", &img);
    if (rc == CBAE_OK) {
        assert(img);
        elf_check_image(img, b, n);
        cbae_image_destroy(&img);
        t->ok++;
        return;
    }
    assert(img == NULL);
    if (rc == CBAE_ERR_PARSE) t->parse++;
    else if (rc == CBAE_ERR_OVERFLOW) t->overflow++;
    else { fprintf(stderr, "unexpected error %d: %s\n", (int)rc, cbae_last_error()); assert(!"unexpected error code"); }
}

static uint8_t *heap_copy(const uint8_t *b, size_t n) { return eb_copy(b, n); }

/* ---- every prefix ---- */

static void test_prefixes(void) {
    tally_t t = { 0, 0, 0 };
    rng_t r = { UINT64_C(0x1234567887654321) };
    static elf_case_t c;
    const int files = QUICK ? 3 : 12;
    uint64_t loads = 0;
    for (int k = 0; k < files; k++) {
        eb_spec_t sp;
        if (k == 0) sp = eb_spec_default();
        else { er_random_case(&r, &c); sp = c.spec; }
        eb_layout_t L;
        eb_file_t f = eb_build(&sp, &L);
        const size_t step = QUICK ? 7 : 1;
        for (size_t n = 0; n <= f.n; n += step) { hostile_load(f.b, n, &t); loads++; }
        hostile_load(f.b, f.n, &t);
        loads++;
        /* the section header table is the last thing in the file, and the loader wants all of it: no shorter prefix loads */
        const size_t table_end = L.shoff + (size_t)L.shnum * 64;
        assert(table_end == f.n);
        for (size_t n = 0; n < table_end; n += 5) {
            cbae_binary_image_t *img = (cbae_binary_image_t *)1;
            assert(cbae_elf_load_buffer(f.b, n, "p", &img) == CBAE_ERR_PARSE && img == NULL);
        }
        eb_free(&f);
    }
    assert(t.ok > 0 && t.parse > 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu prefixes of %d files: %llu loaded, %llu refused, none crashed or read out of bounds",
             (unsigned long long)loads, files, (unsigned long long)t.ok, (unsigned long long)(t.parse + t.overflow));
    PASS(msg);
}

/* ---- one lie ---- */

typedef struct { uint32_t off; uint8_t width; } field_t;
static void add_field(field_t *fs, size_t *n, uint64_t off, uint8_t w) { fs[(*n)++] = (field_t){ (uint32_t)off, w }; }

/* every field of the file, from the layout the builder reports */
static size_t collect_fields(const eb_layout_t *L, const eb_spec_t *sp, field_t *fs) {
    size_t n = 0;
    for (uint32_t o = 4; o < 9; o++) add_field(fs, &n, o, 1);                                 /* class, data, version, OS ABI, ABI version */
    static const struct { uint32_t o; uint8_t w; } eh[] = {
        { 16, 2 }, { 18, 2 }, { 20, 4 }, { 24, 8 }, { 32, 8 }, { 40, 8 }, { 48, 4 }, { 52, 2 }, { 54, 2 }, { 56, 2 }, { 58, 2 }, { 60, 2 }, { 62, 2 } };
    for (size_t i = 0; i < sizeof eh / sizeof eh[0]; i++) add_field(fs, &n, eh[i].o, eh[i].w);
    static const struct { uint32_t o; uint8_t w; } sh[] = {
        { 0, 4 }, { 4, 4 }, { 8, 8 }, { 16, 8 }, { 24, 8 }, { 32, 8 }, { 40, 4 }, { 44, 4 }, { 48, 8 }, { 56, 8 } };
    for (uint32_t i = 0; i < L->shnum; i++)
        for (size_t k = 0; k < sizeof sh / sizeof sh[0]; k++) add_field(fs, &n, (uint64_t)eb_sh(L, i) + sh[k].o, sh[k].w);
    static const struct { uint32_t o; uint8_t w; } sy[] = { { 0, 4 }, { 4, 1 }, { 5, 1 }, { 6, 2 }, { 8, 8 }, { 16, 8 } };
    for (uint32_t i = 0; i < L->nsyms; i++)
        for (size_t k = 0; k < sizeof sy / sizeof sy[0]; k++) add_field(fs, &n, (uint64_t)eb_sym(L, i) + sy[k].o, sy[k].w);
    if (L->shndx_tab) for (uint32_t i = 0; i < L->nsyms; i++) add_field(fs, &n, (uint64_t)L->shndx_off + 4u * i, 4);
    for (int i = 0; i < sp->nrel; i++) {
        add_field(fs, &n, L->rel_off[i], 8);
        add_field(fs, &n, (uint64_t)L->rel_off[i] + 8, 8);
        add_field(fs, &n, (uint64_t)L->rel_off[i] + 16, 8);
    }
    return n;
}

static void test_one_lie(void) {
    tally_t t = { 0, 0, 0 };
    uint64_t loads = 0, fields_total = 0;
    rng_t r = { UINT64_C(0xCAFEF00DCAFEF00D) };
    static elf_case_t c;
    static field_t fs[2048];
    for (int variant = 0; variant < 3; variant++) {
        eb_spec_t sp;
        if (variant == 0) sp = eb_spec_default();
        else {
            do er_random_case(&r, &c); while (c.spec.nsym < 6 || c.spec.nrel < 4);            /* something to damage in each table */
            sp = c.spec;
        }
        eb_layout_t L;
        eb_file_t f = eb_build(&sp, &L);
        const size_t nf = collect_fields(&L, &sp, fs);
        assert(nf < 2048);
        fields_total += nf;
        const uint64_t n = f.n;
        const uint64_t vals[] = {
            0, 1, 2, 3, 4, 7, 8, 0xF, 0x10, 0x18, 0x40, 0x7F, 0x80, 0xFF, 0x100, 0x1FF, 0x400, 0xFFF, 0x1000, 0x7FFF, 0x8000,
            0xFEFF, 0xFF00, 0xFFFE, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFF0u, 0xFFFFFFFFu, n, n - 1, n + 1, n - 24, n - 64,
            UINT64_C(0x100000000), UINT64_C(0xFFFFFFFF00000000), UINT64_C(0x8000000000000000), UINT64_MAX, UINT64_C(0x8000000000000040),
            UINT64_C(0x400000000000000) };
        uint8_t *b = heap_copy(f.b, f.n);
        for (size_t i = 0; i < nf; i++) {
            const uint8_t w = fs[i].width;
            if ((uint64_t)fs[i].off + w > f.n) continue;
            uint8_t saved[8];
            memcpy(saved, b + fs[i].off, w);
            for (size_t v = 0; v < sizeof vals / sizeof vals[0]; v++) {
                if (QUICK && (v & 1)) continue;
                if (w == 1) b[fs[i].off] = (uint8_t)vals[v];
                else if (w == 2) eb_w16(b, fs[i].off, (uint16_t)vals[v]);
                else if (w == 4) eb_w32(b, fs[i].off, (uint32_t)vals[v]);
                else eb_w64(b, fs[i].off, vals[v]);
                hostile_load(b, f.n, &t);
                loads++;
            }
            memcpy(b + fs[i].off, saved, w);
        }
        free(b);
        eb_free(&f);
    }
    assert(t.ok > 0 && t.parse > 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu loads, each with one of %llu fields set to an awkward value: %llu loaded, %llu refused",
             (unsigned long long)loads, (unsigned long long)fields_total, (unsigned long long)t.ok, (unsigned long long)(t.parse + t.overflow));
    PASS(msg);
}

/* ---- string bytes ---- */

static void test_string_bytes(void) {
    tally_t t = { 0, 0, 0 };
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    uint8_t *b = heap_copy(f.b, f.n);
    const struct { uint32_t off, size; } regions[] = {
        { L.strtab_off, L.strtab_size }, { L.shstrtab_off, L.shstrtab_size },
        { L.sec_off[EB_S_MODINFO], (uint32_t)sp.sec[EB_S_MODINFO - 1].size }, { L.sec_off[EB_S_KSYMSTR], (uint32_t)sp.sec[EB_S_KSYMSTR - 1].size } };
    static const uint8_t vals[] = { 0x00, 0xFF, '=' };
    uint64_t loads = 0;
    for (size_t g = 0; g < sizeof regions / sizeof regions[0]; g++)
        for (uint32_t i = 0; i < regions[g].size; i++) {
            const uint32_t at = regions[g].off + i;
            const uint8_t saved = b[at];
            for (size_t v = 0; v < sizeof vals; v++) { b[at] = vals[v]; hostile_load(b, f.n, &t); loads++; }
            b[at] = saved;
        }
    free(b);
    eb_free(&f);
    assert(t.ok > 0 && loads > 500);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu loads, each with one byte of a string table, .modinfo or __ksymtab_strings set to NUL, 0xFF or '='", (unsigned long long)loads);
    PASS(msg);
}

/* ---- random damage ---- */

static void test_random_damage(void) {
    const uint64_t iterations = QUICK ? 3000 : 40000;
    tally_t t = { 0, 0, 0 };
    rng_t r = { UINT64_C(0xD15EA5ED0BADF00D) };
    static const uint32_t interesting[] = { 0, 1, 0xFF, 0x100, 0xFFF, 0x1000, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFF8u, 0x10000, 0x40000000 };
    static elf_case_t c;
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t base = eb_build(&sp, &L);
    for (uint64_t it = 0; it < iterations; it++) {
        eb_file_t f;
        eb_layout_t Lf = L;
        if (it % 4 == 0) { er_random_case(&r, &c); f = eb_build(&c.spec, &Lf); }
        else { f.n = base.n; f.b = heap_copy(base.b, base.n); }
        const uint32_t k = 1 + rn(&r, 8);
        size_t len = f.n;
        for (uint32_t m = 0; m < k; m++) {
            switch (rn(&r, 7)) {
            case 0: f.b[rn(&r, (uint32_t)f.n)] = (uint8_t)rnd(&r); break;
            case 1: { const uint32_t at = rn(&r, (uint32_t)f.n - 3); eb_w32(f.b, at, interesting[rn(&r, 12)]); break; }
            case 2: { const uint32_t at = rn(&r, (uint32_t)f.n - 1); eb_w16(f.b, at, (uint16_t)interesting[rn(&r, 12)]); break; }
            case 3: { const uint32_t n = 8 + rn(&r, 56), a = rn(&r, (uint32_t)f.n - n), b2 = rn(&r, (uint32_t)f.n - n); memmove(f.b + a, f.b + b2, n); break; }
            case 4: { const uint32_t at = rn(&r, 0x40); eb_w32(f.b, at < f.n - 3 ? at : 0, interesting[rn(&r, 12)]); break; }                      /* the header is where the loader looks first */
            case 5: { const uint32_t i = rn(&r, Lf.shnum); eb_w64(f.b, eb_sh(&Lf, i) + 8 * rn(&r, 8), ((uint64_t)interesting[rn(&r, 12)] << 32) | interesting[rn(&r, 12)]); break; }   /* a section header field */
            default: if (rn(&r, 4) == 0) len = 1 + rn(&r, (uint32_t)f.n); break;
            }
        }
        hostile_load(f.b, len < f.n ? len : f.n, &t);
        eb_free(&f);
    }
    eb_free(&base);
    assert(t.ok > 0 && t.parse > 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu randomly damaged files: %llu loaded, %llu refused; nothing crashed, wrapped or read out of bounds",
             (unsigned long long)iterations, (unsigned long long)t.ok, (unsigned long long)(t.parse + t.overflow));
    PASS(msg);
}

/* ---- amplification: work and memory follow the file, not the numbers in it ---- */

static double now_s(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9; }

/* A file put together by hand: header, blobs, then the section headers (the builder has no way to say "a thousand sections share this table"). */
typedef struct { uint32_t name, type; uint64_t flags, addr, off, size; uint32_t link, info; uint64_t align, entsize; } hsh_t;
typedef struct { uint8_t *b; size_t n, cap; hsh_t *sh; uint32_t nsh, capsh; } hb_t;

static void hb_init(hb_t *h) {
    memset(h, 0, sizeof *h);
    h->cap = 4096; h->b = (uint8_t *)calloc(1, h->cap); h->n = 64;
    h->capsh = 16; h->sh = (hsh_t *)calloc(h->capsh, sizeof(hsh_t)); h->nsh = 1;             /* section 0: null */
    assert(h->b && h->sh);
}
static uint64_t hb_blob(hb_t *h, const void *p, size_t len) {
    const size_t at = (h->n + 7) & ~(size_t)7;
    if (at + len > h->cap) { while (at + len > h->cap) h->cap *= 2; h->b = (uint8_t *)realloc(h->b, h->cap); assert(h->b); }
    memset(h->b + h->n, 0, at - h->n);
    if (p) memcpy(h->b + at, p, len); else memset(h->b + at, 0, len);
    h->n = at + len;
    return at;
}
static uint32_t hb_sec(hb_t *h, hsh_t s) {
    if (h->nsh == h->capsh) { h->capsh *= 2; h->sh = (hsh_t *)realloc(h->sh, h->capsh * sizeof(hsh_t)); assert(h->sh); }
    h->sh[h->nsh] = s;
    return h->nsh++;
}
/* writes the section header table and the ELF header; returns an exactly sized copy */
static eb_file_t hb_finish(hb_t *h, uint32_t shstrndx) {
    const uint64_t shoff = (h->n + 7) & ~(size_t)7;
    const size_t total = shoff + (size_t)h->nsh * 64;
    uint8_t *out = (uint8_t *)calloc(1, total);
    assert(out);
    memcpy(out, h->b, h->n);
    out[0] = 0x7F; out[1] = 'E'; out[2] = 'L'; out[3] = 'F'; out[4] = 2; out[5] = 1; out[6] = 1;
    eb_w16(out, 16, 1); eb_w16(out, 18, 62); eb_w32(out, 20, 1);
    eb_w64(out, 40, shoff); eb_w16(out, 52, 64); eb_w16(out, 58, 64);
    eb_w16(out, 60, (uint16_t)h->nsh); eb_w16(out, 62, (uint16_t)shstrndx);
    for (uint32_t i = 0; i < h->nsh; i++) {
        uint8_t *p = out + shoff + (size_t)i * 64;
        eb_w32(p, 0, h->sh[i].name); eb_w32(p, 4, h->sh[i].type); eb_w64(p, 8, h->sh[i].flags); eb_w64(p, 16, h->sh[i].addr);
        eb_w64(p, 24, h->sh[i].off); eb_w64(p, 32, h->sh[i].size); eb_w32(p, 40, h->sh[i].link); eb_w32(p, 44, h->sh[i].info);
        eb_w64(p, 48, h->sh[i].align); eb_w64(p, 56, h->sh[i].entsize);
    }
    free(h->b); free(h->sh);
    eb_file_t f = { out, total };
    return f;
}

/* section names for the hand-made files, and where they are in the name table */
static const char HB_SHSTR[] = "\0.bss\0.symtab\0.strtab\0.shstrtab\0.rela\0.text\0__ksymtab_strings";
enum { HB_N_BSS = 1, HB_N_SYMTAB = 6, HB_N_STRTAB = 14, HB_N_SHSTRTAB = 22, HB_N_RELA = 32, HB_N_TEXT = 38, HB_N_KSYM = 44 };

/* sections 1..4: a 1 GiB .bss that relocations may point anywhere in, the symbol table, its strings, the name table */
static void hb_base(hb_t *h, const uint8_t *syms, size_t nsyms_bytes, const char *strs, size_t nstr) {
    hsh_t bss = { HB_N_BSS, EB_SHT_NOBITS, EB_SHF_ALLOC | EB_SHF_WRITE, 0, 0, (uint64_t)1 << 30, 0, 0, 16, 0 };
    hb_sec(h, bss);
    hsh_t st = { HB_N_SYMTAB, EB_SHT_SYMTAB, 0, 0, hb_blob(h, syms, nsyms_bytes), nsyms_bytes, 3, 1, 8, 24 };
    hb_sec(h, st);
    hsh_t str = { HB_N_STRTAB, EB_SHT_STRTAB, 0, 0, hb_blob(h, strs, nstr), nstr, 0, 0, 1, 0 };
    hb_sec(h, str);
    hsh_t shs = { HB_N_SHSTRTAB, EB_SHT_STRTAB, 0, 0, hb_blob(h, HB_SHSTR, sizeof HB_SHSTR), sizeof HB_SHSTR, 0, 0, 1, 0 };
    hb_sec(h, shs);
}

/* A relocatable object that is nothing but its section header table: n_alloc allocated .bss sections of 1 TiB each, the last of them
 * last_size. More than 65279 sections, so e_shnum is 0 and the count is in section 0 (sh_size). The table is 64 bytes per section. */
static eb_file_t huge_layout_file(uint32_t n_alloc, uint64_t last_size) {
    const uint64_t shnum = (uint64_t)n_alloc + 1;
    const size_t total = 64 + (size_t)shnum * 64;
    uint8_t *b = (uint8_t *)calloc(1, total);
    assert(b);
    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F'; b[4] = 2; b[5] = 1; b[6] = 1;
    eb_w16(b, EB_E_TYPE, EB_ET_REL); eb_w16(b, EB_E_MACHINE, EB_EM_X86_64); eb_w32(b, EB_E_VERSION, 1);
    eb_w64(b, EB_E_SHOFF, 64); eb_w16(b, EB_E_EHSIZE, 64); eb_w16(b, EB_E_SHENTSIZE, 64);
    eb_w16(b, EB_E_SHNUM, 0); eb_w16(b, EB_E_SHSTRNDX, 0);
    eb_w64(b, 64 + EB_SH_SIZE, shnum);
    for (uint64_t i = 1; i < shnum; i++) {
        uint8_t *h = b + 64 + (size_t)i * 64;
        eb_w32(h, EB_SH_TYPE, EB_SHT_NOBITS); eb_w64(h, EB_SH_FLAGS, EB_SHF_ALLOC | EB_SHF_WRITE);
        eb_w64(h, EB_SH_SIZE, i == shnum - 1 ? last_size : (uint64_t)1 << 40); eb_w64(h, EB_SH_ADDRALIGN, 1);
    }
    eb_file_t f = { b, total };
    return f;
}

static void test_amplification(void) {
    /* 100 relocation sections all pointing at ONE table of 1000 entries: 100,000 relocations from a 30 KB file; the budget allows it */
    {
        static uint8_t nullsym[24];
        const uint32_t nent = 1000, R = 100;
        uint8_t *tab = (uint8_t *)calloc(nent, 24);
        for (uint32_t i = 0; i < nent; i++) { eb_w64(tab, i * 24, (uint64_t)i * 8); eb_w64(tab, i * 24 + 8, EB_R_INFO_OF(0, EB_R_X86_64_64)); }
        hb_t h;
        hb_init(&h);
        hb_base(&h, nullsym, sizeof nullsym, "", 1);
        const uint64_t off = hb_blob(&h, tab, (size_t)nent * 24);
        for (uint32_t i = 0; i < R; i++) { hsh_t s = { HB_N_RELA, EB_SHT_RELA, 0, 0, off, (uint64_t)nent * 24, 2, 1, 8, 24 }; hb_sec(&h, s); }
        eb_file_t f = hb_finish(&h, 4);
        const double t0 = now_s();
        cbae_binary_image_t *img = NULL;
        assert(cbae_elf_load_buffer(f.b, f.n, "amp.ko", &img) == CBAE_OK);
        elf_check_image(img, f.b, f.n);
        assert(img->reloc_count == (uint64_t)R * nent && img->section_count == 4 + R && img->note_count == 0);
        assert(img->relocations[R * nent - 1].target_va == 0x400000 + (uint64_t)(nent - 1) * 8);
        cbae_image_destroy(&img);
        assert(now_s() - t0 < 30.0);
        eb_free(&f);
        free(tab);
    }
    /* 3000 sections x 10,000 entries = 30 million relocations from a 430 KB file would need 1.4 GB: refused before anything big is allocated */
    if (!QUICK) {
        static uint8_t nullsym[24];
        const uint32_t nent = 10000, R = 3000;
        uint8_t *tab = (uint8_t *)calloc(nent, 24);
        for (uint32_t i = 0; i < nent; i++) { eb_w64(tab, i * 24, (uint64_t)i * 8); eb_w64(tab, i * 24 + 8, EB_R_INFO_OF(0, EB_R_X86_64_64)); }
        hb_t h;
        hb_init(&h);
        hb_base(&h, nullsym, sizeof nullsym, "", 1);
        const uint64_t off = hb_blob(&h, tab, (size_t)nent * 24);
        for (uint32_t i = 0; i < R; i++) { hsh_t s = { HB_N_RELA, EB_SHT_RELA, 0, 0, off, (uint64_t)nent * 24, 2, 1, 8, 24 }; hb_sec(&h, s); }
        eb_file_t f = hb_finish(&h, 4);
        cbae_binary_image_t *img = (cbae_binary_image_t *)1;
        const double t0 = now_s();
        assert(cbae_elf_load_buffer(f.b, f.n, "big.ko", &img) == CBAE_ERR_OVERFLOW && img == NULL);
        assert(strstr(cbae_last_error(), "relocations") != NULL && strstr(cbae_last_error(), "limit") != NULL);
        assert(now_s() - t0 < 30.0);
        eb_free(&f);
        free(tab);
    }
    /* 50,000 undefined symbols, each named by one of 100,000 relocations (twice): 50,000 imports, found without a quadratic search */
    {
        const uint32_t S = 50000;
        uint8_t *syms = (uint8_t *)calloc(S + 1, 24);
        char *strs = (char *)malloc(1 + (size_t)S * 9);
        size_t sn = 1;
        strs[0] = '\0';
        for (uint32_t i = 1; i <= S; i++) {
            eb_w32(syms, (size_t)i * 24, (uint32_t)sn);
            syms[(size_t)i * 24 + 4] = (uint8_t)EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_NOTYPE);
            sn += (size_t)snprintf(strs + sn, 9, "s%u", i) + 1;
        }
        uint8_t *tab = (uint8_t *)calloc(S, 24);
        for (uint32_t i = 0; i < S; i++) { eb_w64(tab, (size_t)i * 24, (uint64_t)i * 4); eb_w64(tab, (size_t)i * 24 + 8, EB_R_INFO_OF(i + 1, EB_R_X86_64_PLT32)); }
        hb_t h;
        hb_init(&h);
        hb_base(&h, syms, (size_t)(S + 1) * 24, strs, sn);
        const uint64_t off = hb_blob(&h, tab, (size_t)S * 24);
        for (int i = 0; i < 2; i++) { hsh_t s = { HB_N_RELA, EB_SHT_RELA, 0, 0, off, (uint64_t)S * 24, 2, 1, 8, 24 }; hb_sec(&h, s); }
        eb_file_t f = hb_finish(&h, 4);
        const double t0 = now_s();
        cbae_binary_image_t *img = NULL;
        assert(cbae_elf_load_buffer(f.b, f.n, "imports.ko", &img) == CBAE_OK);
        elf_check_image(img, f.b, f.n);
        assert(img->symbol_count == S && img->reloc_count == 2 * S && img->import_count == S && img->note_count == 0);
        assert(strcmp(img->imports[0].name, "s1") == 0 && strcmp(img->imports[S - 1].name, "s50000") == 0);
        assert(cbae_image_import_by_name(img, "s25000") == &img->imports[24999]);
        cbae_image_destroy(&img);
        assert(now_s() - t0 < 30.0);
        eb_free(&f);
        free(syms); free(strs); free(tab);
    }
    /* 20,000 defined symbols and a __ksymtab_strings of 40,000 names, half of them the same: 20,000 more exports, found in linear time */
    {
        const uint32_t D = 20000, K = 40000;
        uint8_t *syms = (uint8_t *)calloc(D + 1, 24);
        char *strs = (char *)malloc(1 + (size_t)D * 8);
        char *ks = (char *)malloc((size_t)K * 8);
        size_t sn = 1, kn = 0;
        strs[0] = '\0';
        for (uint32_t i = 0; i < D; i++) {
            eb_w32(syms, (size_t)(i + 1) * 24, (uint32_t)sn);
            syms[(size_t)(i + 1) * 24 + 4] = (uint8_t)EB_ST_INFO_OF(EB_STB_GLOBAL, EB_STT_FUNC);
            eb_w16(syms, (size_t)(i + 1) * 24 + 6, 5);                                         /* section 5: .text, added below */
            sn += (size_t)snprintf(strs + sn, 8, "n%u", i) + 1;
        }
        for (uint32_t i = 0; i < K; i++) kn += (size_t)snprintf(ks + kn, 8, "n%u", i) + 1;
        hb_t h;
        hb_init(&h);
        hb_base(&h, syms, (size_t)(D + 1) * 24, strs, sn);
        hsh_t text = { HB_N_TEXT, EB_SHT_PROGBITS, EB_SHF_ALLOC | EB_SHF_EXECINSTR, 0, 0, 0x100, 0, 0, 16, 0 };
        text.off = hb_blob(&h, NULL, 0x100);
        assert(hb_sec(&h, text) == 5);
        hsh_t kss = { HB_N_KSYM, EB_SHT_PROGBITS, EB_SHF_ALLOC, 0, 0, kn, 0, 0, 1, 0 };
        kss.off = hb_blob(&h, ks, kn);
        assert(hb_sec(&h, kss) == 6);
        eb_file_t f = hb_finish(&h, 4);
        const double t0 = now_s();
        cbae_binary_image_t *img = NULL;
        assert(cbae_elf_load_buffer(f.b, f.n, "ksyms.ko", &img) == CBAE_OK);
        elf_check_image(img, f.b, f.n);
        assert(img->symbol_count == K && img->meta.elf.has_ksymtab && img->note_count == 0);
        assert(strcmp(img->symbols[D - 1].name, "n19999") == 0 && img->symbols[D - 1].address != CBAE_ADDR_INVALID);
        assert(strcmp(img->symbols[D].name, "n20000") == 0 && img->symbols[D].address == CBAE_ADDR_INVALID && strcmp(img->symbols[K - 1].name, "n39999") == 0);
        assert(cbae_image_symbol_by_name(img, "n30000") == &img->symbols[D + 10000]);
        cbae_image_destroy(&img);
        assert(now_s() - t0 < 30.0);
        eb_free(&f);
        free(syms); free(strs); free(ks);
    }
    /* a symbol table of 4.8 million entries (115 MB) would need 1.1 GB of image: refused, before the image is allocated */
    if (!QUICK) {
        const size_t N = 4800000;
        uint8_t *syms = (uint8_t *)calloc(N, 24);
        assert(syms);
        hb_t h;
        hb_init(&h);
        hb_base(&h, syms, N * 24, "", 1);
        free(syms);
        eb_file_t f = hb_finish(&h, 4);
        cbae_binary_image_t *img = (cbae_binary_image_t *)1;
        const double t0 = now_s();
        assert(cbae_elf_load_buffer(f.b, f.n, "syms.ko", &img) == CBAE_ERR_OVERFLOW && img == NULL);
        assert(strstr(cbae_last_error(), "symbols") != NULL && strstr(cbae_last_error(), "limit") != NULL);
        assert(now_s() - t0 < 60.0);
        eb_free(&f);
    }
    /* The layout of a relocatable object must end below 2^62. Each section is at most 1 TiB, so it takes 4,194,304 of them to get there:
     * a 268 MB file. With the last one exactly filling what is left the object loads; a byte more and it is refused (OVERFLOW), before
     * any table is built. (From 0x400000, 4,194,303 sections of 2^40 end at 2^62 - 2^40 + 0x400000.) */
    if (!QUICK) {
        const uint64_t room = ((uint64_t)1 << 40) - 0x400000;
        for (int over = 0; over < 2; over++) {
            eb_file_t f = huge_layout_file(4194304, room + (uint64_t)over);
            cbae_binary_image_t *img = (cbae_binary_image_t *)1;
            const double t0 = now_s();
            const cbae_err_t rc = cbae_elf_load_buffer(f.b, f.n, "huge.ko", &img);
            if (over == 0) {
                assert(rc == CBAE_OK && img && img->section_count == 4194304);
                const cbae_section_t *last = &img->sections[4194303];
                assert(last->virt_addr == ((uint64_t)1 << 62) - ((uint64_t)1 << 40) + 0x400000 && last->virt_size == room);
                assert(last->virt_addr + last->virt_size == (uint64_t)1 << 62);
                assert(img->sections[0].virt_addr == 0x400000 && img->sections[1].virt_addr == 0x400000 + ((uint64_t)1 << 40));
                cbae_image_destroy(&img);
            } else {
                assert(rc == CBAE_ERR_OVERFLOW && img == NULL && strstr(cbae_last_error(), "do not fit in the address space") != NULL);
            }
            assert(now_s() - t0 < 120.0);
            eb_free(&f);
        }
    }
    PASS("amplification: sections sharing one relocation table, 50,000 imports, 40,000 exported names, tables the budget refuses, a layout that ends exactly at 2^62 and one that does not");
}

/* ---- threads ---- */

static void *worker(void *arg) {
    const eb_file_t *f = (const eb_file_t *)arg;
    for (int i = 0; i < (QUICK ? 20 : 200); i++) {
        cbae_binary_image_t *img = NULL;
        assert(cbae_elf_load_buffer(f->b, f->n, "t.ko", &img) == CBAE_OK);
        elf_check_image(img, f->b, f->n);
        assert(img->section_count == 14 && img->symbol_count == 22 && img->import_count == 4 && img->reloc_count == 14);
        cbae_image_destroy(&img);
        cbae_binary_image_t *bad = (cbae_binary_image_t *)1;
        assert(cbae_elf_load_buffer(f->b, 100, "t.ko", &bad) == CBAE_ERR_PARSE && bad == NULL);
        assert(strstr(cbae_last_error(), "") != NULL);               /* the error context is per thread */
    }
    return NULL;
}

static void test_threads(void) {
    eb_spec_t sp = eb_spec_default();
    eb_layout_t L;
    eb_file_t f = eb_build(&sp, &L);
    pthread_t th[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&th[i], NULL, worker, &f) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(th[i], NULL) == 0);
    eb_free(&f);
    PASS("four threads load the same bytes concurrently: no shared state");
}

int main(void) {
    printf("=== test_elf_hostile ===\n");
    test_prefixes();
    test_one_lie();
    test_string_bytes();
    test_random_damage();
    test_amplification();
    test_threads();
    printf("All ELF hostile-input tests passed.\n");
    return 0;
}
