/*
 * elf_random.h - seeded random but well-formed ELF descriptions (elf_builder.h's eb_spec_t): relocatable
 * objects and linked files, for x86-64 and others, with odd alignments, huge and empty sections, every
 * symbol type and binding, undefined/absolute/common/out-of-range section indices (some stored in the
 * extended index table), and relocations of every known and several unknown types, some outside their
 * section and some naming symbols that are not there. "Well-formed" means the file is laid out as the
 * format says; what the fields hold is deliberately awkward. elf_model.h says what the loader must make
 * of each. The generator starts from whatever seed the test gives, so a failure repeats.
 *
 * Limits that keep a case inside the model's scope: at most 8 sections (so each can have its own
 * relocation section), no section named .modinfo or __ksymtab_strings, no SHT_NULL section.
 */
#ifndef CBAE_TEST_ELF_RANDOM_H
#define CBAE_TEST_ELF_RANDOM_H

#include "elf_builder.h"
#include "pe_random.h"          /* rng_t, rnd, rn */

#define ER_MAX_USER_SECTIONS 8
#define ER_DATA_MAX 512

typedef struct {
    eb_spec_t spec;
    uint8_t   bytes[EB_MAX_SEC][ER_DATA_MAX];
    char      long_sec[160], long_sym[260];
} elf_case_t;

static inline uint64_t er_u64(rng_t *r) { return ((uint64_t)rnd(r) << 32) | rnd(r); }

static inline void er_random_case(rng_t *r, elf_case_t *c) {
    static const char *const secnames[] = { ".text", ".rodata", ".data", ".bss", ".init.text", ".exit.text", "__param", ".note.gnu.build-id", ".comment", ".debug_str", ".gnu.linkonce.this_module", "", NULL };
    static const char *const symnames[] = { "init_module", "cleanup_module", "printk", "kmalloc", "kfree", "memcpy", "my_func", "my_data", "_ZN3fooEv", "x", ".text", NULL };
    static const uint64_t aligns[] = { 0, 1, 2, 4, 8, 16, 32, 64, 0x1000, 0x2000, 3, 24, 0x200000, UINT64_C(1) << 40, 0x3000, 0x1800, 0x100000, 0x100001 };
    static const uint64_t bigs[] = { 0, 0x10, 0x100, 0x1000, 0x12345, (uint64_t)1 << 20, (uint64_t)1 << 30, ((uint64_t)1 << 40) + 5, (uint64_t)1 << 41 };
    static const uint32_t rtypes[] = { 0, 1, 2, 4, 9, 10, 11, 24, 41, 42, 3, 7, 0x99, 0xFFFFFFFFu };

    memset(c, 0, sizeof *c);
    eb_spec_t *s = &c->spec;
    for (size_t i = 0; i < sizeof c->long_sec - 1; i++) c->long_sec[i] = (char)('a' + i % 26);
    for (size_t i = 0; i < sizeof c->long_sym - 1; i++) c->long_sym[i] = (char)('A' + i % 26);

    const uint32_t et = rn(r, 20);
    s->etype = et < 14 ? EB_ET_REL : et < 17 ? EB_ET_EXEC : EB_ET_DYN;
    const uint32_t mk = rn(r, 20);
    s->machine = mk < 15 ? EB_EM_X86_64 : mk < 17 ? EB_EM_AARCH64 : mk < 19 ? 3 : 0;
    s->ei_class = EB_CLASS64;
    s->ei_data = EB_DATA_LSB;
    const bool rel = s->etype == EB_ET_REL;
    s->entry = rn(r, 4) == 0 ? 0 : rel ? 0x1000 : 0x401000 + rn(r, 0x1000);

    /* sections */
    s->nsec = 2 + (int)rn(r, ER_MAX_USER_SECTIONS - 1);
    for (int i = 0; i < s->nsec; i++) {
        eb_section_t *u = &s->sec[i];
        const uint32_t k = rn(r, 10);
        u->name = rn(r, 40) == 0 ? c->long_sec : secnames[rn(r, 13)];
        if (k < 5)      { u->type = EB_SHT_PROGBITS; u->flags = EB_SHF_ALLOC | (rn(r, 2) ? EB_SHF_EXECINSTR : 0) | (rn(r, 3) == 0 ? EB_SHF_WRITE : 0); }
        else if (k < 7) { u->type = EB_SHT_NOBITS;   u->flags = EB_SHF_ALLOC | EB_SHF_WRITE; }
        else if (k < 9) { u->type = EB_SHT_PROGBITS; u->flags = 0; }
        else            { u->type = EB_SHT_NOTE;     u->flags = EB_SHF_ALLOC; }
        u->align = aligns[rn(r, (uint32_t)(sizeof aligns / sizeof aligns[0]))];
        u->entsize = rn(r, 4) == 0 ? rn(r, 32) : 0;
        u->link = rn(r, 3) == 0 ? rn(r, 20) : 0;
        u->info = rn(r, 3) == 0 ? rn(r, 20) : 0;
        if (u->type == EB_SHT_NOBITS) {
            u->size = bigs[rn(r, 9)];
            u->data = NULL;
        } else {
            u->size = rn(r, 8) == 0 ? 0 : rn(r, 0x180);
            if (u->size) {
                for (uint64_t b = 0; b < u->size; b++) c->bytes[i][b] = (uint8_t)rnd(r);
                u->data = c->bytes[i];
            }
        }
        if (!rel) u->addr = rn(r, 40) == 0 ? UINT64_MAX - rn(r, 0x40) : 0x400000 + (uint64_t)i * 0x2000 + 8 * rn(r, 0x100);
    }

    /* symbols */
    s->nsym = (int)rn(r, 31);
    for (int k = 0; k < s->nsym; k++) {
        eb_symbol_t *y = &s->sym[k];
        const uint32_t kt = rn(r, 20);
        unsigned type = kt < 4 ? EB_STT_NOTYPE : kt < 8 ? EB_STT_OBJECT : kt < 13 ? EB_STT_FUNC : kt < 15 ? EB_STT_SECTION : kt < 16 ? EB_STT_FILE
                      : kt < 17 ? EB_STT_COMMON : kt < 18 ? EB_STT_TLS : kt < 19 ? EB_STT_GNU_IFUNC : 13u;
        const uint32_t kb = rn(r, 20);
        unsigned bind = kb < 8 ? EB_STB_LOCAL : kb < 16 ? EB_STB_GLOBAL : kb < 19 ? EB_STB_WEAK : EB_STB_GNU_UNIQUE;
        const uint32_t ks = rn(r, 100);
        uint32_t shndx;
        if (type == EB_STT_FILE) shndx = EB_SHN_ABS;
        else if (type == EB_STT_COMMON) shndx = EB_SHN_COMMON;
        else if (type == EB_STT_SECTION) shndx = 1 + rn(r, (uint32_t)s->nsec);
        else if (ks < 20) shndx = EB_SHN_UNDEF;
        else if (ks < 25) shndx = EB_SHN_ABS;
        else if (ks < 30) shndx = EB_SHN_COMMON;
        else if (ks < 85) shndx = 1 + rn(r, (uint32_t)s->nsec);
        else if (ks < 89) shndx = (uint32_t)s->nsec + 1 + rn(r, 4);          /* a section the builder added: .symtab, .strtab, ... */
        else if (ks < 94) shndx = 100 + rn(r, 0xFD00);                       /* not a section */
        else shndx = EB_SHN_LORESERVE + rn(r, 0xF0);                         /* reserved */
        if (type == EB_STT_SECTION) bind = EB_STB_LOCAL;
        y->info = EB_ST_INFO_OF(bind, type);
        y->other = (uint8_t)rn(r, 4);
        y->shndx = shndx;
        y->xindex = rn(r, 7) == 0;
        y->name = type == EB_STT_SECTION ? NULL : rn(r, 40) == 0 ? c->long_sym : rn(r, 10) == 0 ? NULL : symnames[rn(r, 11)];
        const uint64_t sz = shndx >= 1 && shndx <= (uint32_t)s->nsec ? s->sec[shndx - 1].size : rn(r, 0x200);
        if (!rel) y->value = rn(r, 4) == 0 ? er_u64(r) : 0x400000 + rn(r, 0x10000);
        else y->value = rn(r, 4) == 0 ? sz + rn(r, 3) : rn(r, (uint32_t)(sz > 0x7FFFFFFF ? 0x7FFFFFFF : sz) + 1);
        if (rn(r, 9) == 0) y->value = er_u64(r);
        y->size = rn(r, 0x40);
    }

    /* relocations */
    s->nrel = (int)rn(r, 41);
    for (int i = 0; i < s->nrel; i++) {
        eb_rela_t *e = &s->rel[i];
        e->target = 1 + rn(r, (uint32_t)s->nsec);
        const uint64_t tsize = s->sec[e->target - 1].size;
        const uint32_t ko = rn(r, 20);
        e->offset = ko == 0 ? UINT64_MAX - rn(r, 4) : ko < 4 ? tsize + rn(r, 8) : rn(r, (uint32_t)(tsize > 0x7FFFFFFF ? 0x7FFFFFFF : tsize) + 1);
        const uint32_t ksym = rn(r, 20);
        if (ksym < 3 || (ksym < 18 && s->nsym == 0)) e->sym = 0;
        else if (ksym < 18) e->sym = 1 + rn(r, (uint32_t)s->nsym);                    /* a symbol that is there */
        else e->sym = (uint32_t)s->nsym + 1 + rn(r, 3);                               /* one that is not */
        e->type = rtypes[rn(r, 14)];
        e->addend = (int64_t)er_u64(r);
    }
}

#endif /* CBAE_TEST_ELF_RANDOM_H */
