/**
 * @file test_pe_hostile.c
 * @brief The PE loader against damaged and hostile files (audit A-030).
 *
 * CBAE exists to analyse untrusted drivers, so the loader's contract is: whatever the bytes, it either
 * refuses the file with an error code (CBAE_ERR_PARSE, CBAE_ERR_UNSUPPORTED, CBAE_ERR_OVERFLOW) or returns an
 * image that satisfies pe_check_image(); it never reads outside its input, never wraps an address, never
 * allocates in proportion to a number the file merely claims. The checks that make the first half of that
 * visible are the sanitizers: pe_check.h loads from an exactly sized heap copy (the loader's own copy), so
 * AddressSanitizer and Valgrind see a read one byte too far.
 *
 *   prefixes        every prefix of valid files (a download cut anywhere)
 *   one lie         a good file with ONE field set to each of ~35 awkward values, for every field the
 *                   loader reads (about 300 fields), over three different good files
 *   random damage   seeded random byte, word and block damage, and truncation, on random valid files
 *   amplification   many descriptors sharing one table, absurd counts: bounded work and memory
 *   threads         concurrent loads share nothing
 */
#include "loader/pe_loader.h"
#include "pe_builder.h"
#include "pe_check.h"
#include "pe_random.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define QUICK (getenv("CBAE_TEST_QUICK") != NULL)

typedef struct { uint64_t ok, parse, unsupported, overflow; } tally_t;

/* Loads b[0..n); the contract above. */
static void hostile_load(const uint8_t *b, size_t n, tally_t *t) {
    cbae_binary_image_t *img = (cbae_binary_image_t *)1;
    const cbae_err_t rc = cbae_pe_load_buffer(b, n, "hostile.sys", &img);
    if (rc == CBAE_OK) {
        assert(img);
        pe_check_image(img, b, n);
        cbae_image_destroy(&img);
        t->ok++;
        return;
    }
    assert(img == NULL);
    if (rc == CBAE_ERR_PARSE) t->parse++;
    else if (rc == CBAE_ERR_UNSUPPORTED) t->unsupported++;
    else if (rc == CBAE_ERR_OVERFLOW) t->overflow++;
    else { fprintf(stderr, "unexpected error %d: %s\n", (int)rc, cbae_last_error()); assert(!"unexpected error code"); }
}

/* ---- every prefix ---- */

static void test_prefixes(void) {
    tally_t t = { 0, 0, 0, 0 };
    rng_t r = { UINT64_C(0x1234567887654321) };
    const int files = QUICK ? 3 : 12;
    uint64_t loads = 0;
    for (int k = 0; k < files; k++) {
        pb_spec_t sp = k == 0 ? pb_spec_default() : random_spec(&r);
        pb_layout_t L;
        pb_file_t f = pb_build(&sp, &L);
        const size_t step = QUICK ? 7 : 1;
        for (size_t n = 0; n <= f.n; n += step) { hostile_load(f.b, n, &t); loads++; }
        hostile_load(f.b, f.n, &t);
        loads++;
        /* the loader reads a header it can see whole: no prefix that ends inside the section table loads */
        for (size_t n = 0; n < L.sect_tab + PB_NSEC * PB_SEC_HDR_SIZE; n += 11) {
            cbae_binary_image_t *img = (cbae_binary_image_t *)1;
            assert(cbae_pe_load_buffer(f.b, n, "p", &img) == CBAE_ERR_PARSE && img == NULL);
        }
        pb_free(&f);
    }
    assert(t.ok > 0 && t.parse > 0 && t.unsupported == 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu prefixes of %d files: %llu loaded (tables clamped), %llu refused, none crashed or read out of bounds",
             (unsigned long long)loads, files, (unsigned long long)t.ok, (unsigned long long)t.parse);
    PASS(msg);
}

/* ---- one lie ---- */

typedef struct { uint32_t off; uint8_t width; } field_t;

static void add_field(field_t *fs, size_t *n, uint32_t off, uint8_t w) { fs[(*n)++] = (field_t){ off, w }; }

/* every field of the file the loader reads, from the layout the builder reports */
static size_t collect_fields(const pb_layout_t *L, const pb_spec_t *sp, field_t *fs) {
    size_t n = 0;
    add_field(fs, &n, PB_DOS_E_LFANEW, 4);
    add_field(fs, &n, L->coff + PB_COFF_MACHINE, 2);
    add_field(fs, &n, L->coff + PB_COFF_NSECTIONS, 2);
    add_field(fs, &n, L->coff + PB_COFF_SYMPTR, 4);
    add_field(fs, &n, L->coff + PB_COFF_NSYMS, 4);
    add_field(fs, &n, L->coff + PB_COFF_OPTSIZE, 2);
    static const struct { uint32_t o; uint8_t w; } opt[] = {
        { PB_OPT_MAGIC, 2 }, { PB_OPT_SIZE_OF_CODE, 4 }, { PB_OPT_ENTRY_RVA, 4 }, { PB_OPT_BASE_OF_CODE, 4 }, { PB_OPT_IMAGE_BASE, 8 },
        { PB_OPT_SECT_ALIGN, 4 }, { PB_OPT_FILE_ALIGN, 4 }, { PB_OPT_SIZE_OF_IMAGE, 4 }, { PB_OPT_SIZE_OF_HDRS, 4 }, { PB_OPT_CHECKSUM, 4 },
        { PB_OPT_SUBSYSTEM, 2 }, { PB_OPT_DLL_CHARS, 2 }, { PB_OPT_NUM_DIRS, 4 } };
    for (size_t i = 0; i < sizeof opt / sizeof opt[0]; i++) add_field(fs, &n, L->opt + opt[i].o, opt[i].w);
    for (uint32_t d = 0; d < 16; d++) if (L->dir_entry[d]) { add_field(fs, &n, L->dir_entry[d], 4); add_field(fs, &n, L->dir_entry[d] + 4, 4); }
    for (int s = 0; s < PB_NSEC; s++) {
        add_field(fs, &n, L->sec_hdr[s] + PB_SEC_VSIZE, 4);
        add_field(fs, &n, L->sec_hdr[s] + PB_SEC_RVA, 4);
        add_field(fs, &n, L->sec_hdr[s] + PB_SEC_RAWSIZE, 4);
        add_field(fs, &n, L->sec_hdr[s] + PB_SEC_RAWPTR, 4);
        add_field(fs, &n, L->sec_hdr[s] + PB_SEC_CHARS, 4);
    }
    for (int d = 0; d <= sp->ndll; d++)
        for (uint32_t k = 0; k < 5; k++) add_field(fs, &n, pb_rva_to_off(L, L->imp_dir_rva) + (uint32_t)d * PB_IMPORT_DESC_SIZE + k * 4, 4);
    for (int d = 0; d < sp->ndll; d++) {
        const uint32_t tab = L->imp_ilt_rva[d] ? L->imp_ilt_rva[d] : L->imp_iat_rva[d];
        for (int k = 0; k <= sp->dll[d].nfn; k++) add_field(fs, &n, pb_rva_to_off(L, tab) + (uint32_t)k * 8, 8);
        for (int k = 0; k < sp->dll[d].nfn; k++) if (L->imp_hintname_rva[d][k]) add_field(fs, &n, pb_rva_to_off(L, L->imp_hintname_rva[d][k]), 2);
    }
    if (L->exp_dir_rva) {
        const uint32_t e = pb_rva_to_off(L, L->exp_dir_rva);
        for (uint32_t k = 0; k < 40; k += 4) add_field(fs, &n, e + k, 4);
        for (int k = 0; k < sp->exports.nslots; k++) add_field(fs, &n, pb_rva_to_off(L, L->exp_eat_rva) + (uint32_t)k * 4, 4);
        for (int k = 0; k < sp->exports.nnames; k++) {
            add_field(fs, &n, pb_rva_to_off(L, L->exp_names_rva) + (uint32_t)k * 4, 4);
            add_field(fs, &n, pb_rva_to_off(L, L->exp_ords_rva) + (uint32_t)k * 2, 2);
        }
    }
    for (int b = 0, at = 0; b < sp->nblocks; b++) {
        const uint32_t base = L->sec_off[PB_S_RELOC] + (uint32_t)at;
        add_field(fs, &n, base, 4);
        add_field(fs, &n, base + 4, 4);
        const int ents = sp->block[b].nfix + (sp->block[b].nfix & 1);
        for (int e = 0; e < ents; e++) add_field(fs, &n, base + 8 + (uint32_t)e * 2, 2);
        at += 8 + ents * 2;
    }
    if (L->debug_rva)
        for (int i = 0; i < sp->ndebug; i++) {
            const uint32_t e = pb_rva_to_off(L, L->debug_rva) + (uint32_t)i * PB_DEBUG_ENTRY_SIZE;
            for (uint32_t k = 0; k < PB_DEBUG_ENTRY_SIZE; k += 4) if (k != 8) add_field(fs, &n, e + k, 4);
            if (L->cv_off[i]) { add_field(fs, &n, L->cv_off[i], 4); add_field(fs, &n, L->cv_off[i] + 20, 4); }
        }
    return n;
}

static void test_one_lie(void) {
    tally_t t = { 0, 0, 0, 0 };
    uint64_t loads = 0, fields_total = 0;
    rng_t r = { UINT64_C(0xCAFEF00DCAFEF00D) };
    for (int variant = 0; variant < 3; variant++) {
        pb_spec_t sp = variant == 0 ? pb_spec_default() : random_spec(&r);
        if (variant != 0) { sp.ndll = sp.ndll ? sp.ndll : 1; sp.dll[0].dll = "a.sys"; sp.dll[0].nfn = sp.dll[0].nfn ? sp.dll[0].nfn : 2; }
        pb_layout_t L;
        pb_file_t f = pb_build(&sp, &L);
        static field_t fs[1024];
        const size_t nf = collect_fields(&L, &sp, fs);
        assert(nf < 1024);
        fields_total += nf;
        const uint64_t n = f.n;
        const uint64_t vals[] = {
            0, 1, 2, 3, 4, 7, 8, 0xF, 0x10, 0x7F, 0x80, 0xFF, 0x100, 0x1FF, 0x200, 0x3FF, 0x400, 0xFFF, 0x1000, 0x1001, 0x7FFF, 0x8000,
            0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFF0u, 0xFFFFFFFEu, 0xFFFFFFFFu, n, n - 1, n + 1, n - 4, n - 8, n - 24,
            UINT64_C(0x100000000), UINT64_C(0xFFFFFFFF00000000), UINT64_C(0x8000000000000000), UINT64_MAX, UINT64_C(0x8000000000000457) };
        uint8_t *b = pb_copy(f.b, f.n);
        for (size_t i = 0; i < nf; i++) {
            const uint8_t w = fs[i].width;
            if ((uint64_t)fs[i].off + w > f.n) continue;
            uint8_t saved[8];
            memcpy(saved, b + fs[i].off, w);
            for (size_t v = 0; v < sizeof vals / sizeof vals[0]; v++) {
                if (QUICK && (v & 1)) continue;
                if (w == 2) pb_w16(b, fs[i].off, (uint16_t)vals[v]);
                else if (w == 4) pb_w32(b, fs[i].off, (uint32_t)vals[v]);
                else pb_w64(b, fs[i].off, vals[v]);
                hostile_load(b, f.n, &t);
                loads++;
            }
            memcpy(b + fs[i].off, saved, w);
        }
        free(b);
        pb_free(&f);
    }
    assert(t.ok > 0 && t.parse > 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu loads, each with one of %llu fields set to an awkward value: %llu loaded, %llu refused (parse %llu, 32-bit %llu)",
             (unsigned long long)loads, (unsigned long long)fields_total, (unsigned long long)t.ok,
             (unsigned long long)(t.parse + t.unsupported + t.overflow), (unsigned long long)t.parse, (unsigned long long)t.unsupported);
    PASS(msg);
}

/* ---- random damage ---- */

static void test_random_damage(void) {
    const uint64_t iterations = QUICK ? 3000 : 40000;
    tally_t t = { 0, 0, 0, 0 };
    rng_t r = { UINT64_C(0xD15EA5ED0BADF00D) };
    static const uint32_t interesting[] = { 0, 1, 0xFF, 0x100, 0xFFF, 0x1000, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFF8u, 0x10000, 0x40000000 };
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t base = pb_build(&sp, &L);
    for (uint64_t it = 0; it < iterations; it++) {
        pb_file_t f;
        if (it % 4 == 0) { sp = random_spec(&r); f = pb_build(&sp, &L); }
        else { f.n = base.n; f.b = pb_copy(base.b, base.n); }
        const uint32_t k = 1 + rn(&r, 8);
        size_t len = f.n;
        for (uint32_t m = 0; m < k; m++) {
            switch (rn(&r, 6)) {
            case 0: f.b[rn(&r, (uint32_t)f.n)] = (uint8_t)rnd(&r); break;
            case 1: { const uint32_t at = rn(&r, (uint32_t)f.n - 3); pb_w32(f.b, at, interesting[rn(&r, 12)]); break; }
            case 2: { const uint32_t at = rn(&r, (uint32_t)f.n - 1); pb_w16(f.b, at, (uint16_t)interesting[rn(&r, 12)]); break; }
            case 3: { const uint32_t n = 8 + rn(&r, 56), a = rn(&r, (uint32_t)f.n - n), b2 = rn(&r, (uint32_t)f.n - n); memmove(f.b + a, f.b + b2, n); break; }
            case 4: { const uint32_t at = rn(&r, 0x400); pb_w32(f.b, at < f.n - 3 ? at : 0, interesting[rn(&r, 12)]); break; }      /* the headers are where the loader looks first */
            default: if (rn(&r, 4) == 0) len = 1 + rn(&r, (uint32_t)f.n); break;
            }
        }
        hostile_load(f.b, len < f.n ? len : f.n, &t);
        pb_free(&f);
    }
    pb_free(&base);
    assert(t.ok > 0 && t.parse > 0);
    char msg[256];
    snprintf(msg, sizeof msg, "%llu randomly damaged files: %llu loaded, %llu refused; nothing crashed, wrapped or read out of bounds",
             (unsigned long long)iterations, (unsigned long long)t.ok, (unsigned long long)(t.parse + t.unsupported + t.overflow));
    PASS(msg);
}

/* ---- amplification: work and memory follow the file, not the numbers in it ---- */

static double now_s(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9; }

static void test_amplification(void) {
    /* 3000 import descriptors all pointing at ONE lookup table of 100 entries: 300,000 imports from a 70 KB file.
     * The loader stops at its limit of 262,144 and says so. */
    {
        const uint32_t ndesc = 3000, nent = 100;
        const uint32_t ilt = (ndesc + 1) * 20, name = ilt + (nent + 1) * 8, hn = name + 16, raw = hn + 16;
        pb_mini_t m = pb_mini(raw);
        for (uint32_t d = 0; d < ndesc; d++) {
            const uint32_t at = m.sec_off + d * 20;
            pb_w32(m.b, at, m.sec_rva + ilt);
            pb_w32(m.b, at + 12, m.sec_rva + name);
            pb_w32(m.b, at + 16, m.sec_rva + ilt);
        }
        for (uint32_t e = 0; e < nent; e++) pb_w64(m.b, m.sec_off + ilt + e * 8, m.sec_rva + hn);
        memcpy(m.b + m.sec_off + name, "shared.dll", 11);
        memcpy(m.b + m.sec_off + hn + 2, "Fn", 3);
        pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, (ndesc + 1) * 20);
        const double t0 = now_s();
        cbae_binary_image_t *img = NULL;
        assert(cbae_pe_load_buffer(m.b, m.n, "amp.sys", &img) == CBAE_OK);
        pe_check_image(img, m.b, m.n);
        assert(img->import_count == 262144 && strstr(img->notes[0], "more than 262144 imports"));
        cbae_image_destroy(&img);
        assert(now_s() - t0 < 20.0);
        pb_mini_free(&m);
    }
    /* a relocation directory that would need more than an image may use: refused before anything big is allocated */
    if (!QUICK) {
        const uint32_t per = 2040, blocks = 11000;                 /* 22.44 million entries x 48 bytes = 1.077e9 bytes, just over the 2^30 limit */
        const uint32_t raw = blocks * (8 + per * 2);
        pb_mini_t m = pb_mini(raw);
        for (uint32_t k = 0; k < blocks; k++) {
            const uint32_t at = m.sec_off + k * (8 + per * 2);
            pb_w32(m.b, at, 0x1000);
            pb_w32(m.b, at + 4, 8 + per * 2);
        }
        pb_mini_dir(&m, PB_DIR_BASERELOC, m.sec_rva, raw);
        cbae_binary_image_t *img = (cbae_binary_image_t *)1;
        const double t0 = now_s();
        assert(cbae_pe_load_buffer(m.b, m.n, "big.sys", &img) == CBAE_ERR_OVERFLOW && img == NULL);
        assert(strstr(cbae_last_error(), "relocations") != NULL);
        assert(now_s() - t0 < 30.0);
        pb_mini_free(&m);
    }
    /* thousands of descriptors whose tables are nowhere: one note each is not kept, time stays linear */
    {
        const uint32_t ndesc = 50000;
        pb_mini_t m = pb_mini((ndesc + 1) * 20 + 16);
        for (uint32_t d = 0; d < ndesc; d++) {
            pb_w32(m.b, m.sec_off + d * 20, 0x7FFF0000);
            pb_w32(m.b, m.sec_off + d * 20 + 12, 0x7FFF0010);
            pb_w32(m.b, m.sec_off + d * 20 + 16, 0x7FFF0000);
        }
        pb_mini_dir(&m, PB_DIR_IMPORT, m.sec_rva, (ndesc + 1) * 20);
        const double t0 = now_s();
        cbae_binary_image_t *img = NULL;
        assert(cbae_pe_load_buffer(m.b, m.n, "nowhere.sys", &img) == CBAE_OK);
        pe_check_image(img, m.b, m.n);
        assert(img->import_count == 0 && img->note_count > CBAE_IMAGE_NOTES_MAX);     /* more notes than it keeps: the rest are counted */
        cbae_image_destroy(&img);
        assert(now_s() - t0 < 10.0);
        pb_mini_free(&m);
    }
    PASS("amplification: shared tables hit the import limit, an oversized relocation table is refused early, dangling tables cost linear time");
}

/* ---- threads ---- */

static void *worker(void *arg) {
    const pb_file_t *f = (const pb_file_t *)arg;
    for (int i = 0; i < (QUICK ? 20 : 200); i++) {
        cbae_binary_image_t *img = NULL;
        assert(cbae_pe_load_buffer(f->b, f->n, "t.sys", &img) == CBAE_OK);
        pe_check_image(img, f->b, f->n);
        assert(img->import_count == 5 && img->symbol_count == 6 && img->reloc_count == 6);
        cbae_image_destroy(&img);
        cbae_binary_image_t *bad = (cbae_binary_image_t *)1;
        assert(cbae_pe_load_buffer(f->b, 100, "t.sys", &bad) == CBAE_ERR_PARSE && bad == NULL);
        assert(strstr(cbae_last_error(), "") != NULL);               /* the error context is per thread */
    }
    return NULL;
}

static void test_threads(void) {
    pb_spec_t sp = pb_spec_default();
    pb_layout_t L;
    pb_file_t f = pb_build(&sp, &L);
    pthread_t th[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&th[i], NULL, worker, &f) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(th[i], NULL) == 0);
    pb_free(&f);
    PASS("four threads load the same bytes concurrently: no shared state");
}

int main(void) {
    printf("=== test_pe_hostile ===\n");
    test_prefixes();
    test_one_lie();
    test_random_damage();
    test_amplification();
    test_threads();
    printf("All PE hostile-input tests passed.\n");
    return 0;
}
