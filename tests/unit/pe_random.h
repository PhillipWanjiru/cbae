/*
 * pe_random.h - a seeded xorshift generator and a generator of random but valid PE specifications
 * (pe_builder.h's pb_spec_t): random imports, exports (named, unnamed, aliased, forwarded, data), relocation
 * blocks and debug entries, over a few image bases and machine types. The tests that use it print no
 * seed because there is no hidden one: the generator starts from a constant, so a failure repeats.
 */
#ifndef CBAE_TEST_PE_RANDOM_H
#define CBAE_TEST_PE_RANDOM_H

#include "pe_builder.h"

typedef struct { uint64_t s; } rng_t;
static inline uint32_t rnd(rng_t *r) { r->s ^= r->s << 13; r->s ^= r->s >> 7; r->s ^= r->s << 17; return (uint32_t)(r->s >> 11); }
static inline uint32_t rn(rng_t *r, uint32_t n) { return n ? rnd(r) % n : 0; }

/* The export names of the returned spec point into a static buffer: valid until the next call. */
static inline pb_spec_t random_spec(rng_t *r) {
    static const char *dlls[] = { "ntoskrnl.exe", "HAL.dll", "FLTMGR.SYS", "ksecdd.sys" };
    static const char *fns[]  = { "IoCreateDevice", "ExAllocatePool2", "KeBugCheckEx", "ZwClose", "RtlInitUnicodeString", "ObReferenceObjectByHandle", "MmGetSystemRoutineAddress", "x" };
    static const char *fwds[] = { "NTDLL.RtlFoo", "KERNEL32.#12", "api-ms-win-core-heap-l1-1-0.HeapAlloc" };
    static const char *pdbs[] = { NULL, "x.pdb", "C:\\a\\b.pdb", "" };
    pb_spec_t sp = pb_spec_default();
    static const uint64_t bases[] = { UINT64_C(0x140000000), UINT64_C(0x10000), UINT64_C(0xFFFFF80000000000), UINT64_C(0x7FF600000000), UINT64_C(0x180000000) };
    sp.image_base = bases[rn(r, 5)];
    sp.entry_rva = rn(r, 3) ? 0x1000 + rn(r, 0x1F0) : 0;
    sp.subsystem = (uint16_t)(1 + rn(r, 16));
    sp.dll_chars = (uint16_t)rn(r, 0x10000);
    sp.checksum = rnd(r);
    sp.machine = rn(r, 4) ? PB_MACHINE_AMD64 : rn(r, 2) ? PB_MACHINE_ARM64 : 0x1C0;
    sp.text_vsize_zero = rn(r, 4) == 0;
    sp.ndll = (int)rn(r, 5);
    for (int d = 0; d < sp.ndll; d++) {
        sp.dll[d].dll = dlls[d];
        sp.dll[d].nfn = (int)rn(r, 9);
        sp.dll[d].no_ilt = rn(r, 3) == 0;
        for (int k = 0; k < sp.dll[d].nfn; k++) {
            if (rn(r, 4) == 0) sp.dll[d].fn[k] = (pb_import_t){ NULL, 0, (uint16_t)(1 + rn(r, 65535)), true };
            else sp.dll[d].fn[k] = (pb_import_t){ fns[rn(r, 8)], (uint16_t)rn(r, 0x10000), 0, false };
        }
    }
    memset(&sp.exports, 0, sizeof sp.exports);
    sp.exports.present = rn(r, 3) != 0;
    if (sp.exports.present) {
        pb_exports_t *E = &sp.exports;
        E->dll_name = "gen.sys";
        E->base = rn(r, 4) == 0 ? 0 : 1 + rn(r, 100);
        E->nslots = 1 + (int)rn(r, 8);
        for (int s = 0; s < E->nslots; s++) {
            const uint32_t k = rn(r, 10);
            if (k < 2) E->slot[s] = (pb_slot_t){ 0, NULL };
            else if (k < 6) E->slot[s] = (pb_slot_t){ 0x1000 + rn(r, 0x1F0), NULL };
            else if (k < 8) E->slot[s] = (pb_slot_t){ 0x3000 + rn(r, 0x3F0), NULL };
            else E->slot[s] = (pb_slot_t){ 0, fwds[rn(r, 3)] };
        }
        E->nnames = (int)rn(r, (uint32_t)E->nslots + 3);
        static char namebuf[PB_MAX][24];
        for (int i = 0; i < E->nnames; i++) {
            snprintf(namebuf[i], sizeof namebuf[i], "Exp%02d_%u", i, rn(r, 1000));
            E->name[i] = (pb_export_name_t){ namebuf[i], (uint16_t)rn(r, (uint32_t)E->nslots) };
        }
    }
    sp.nblocks = (int)rn(r, 5);
    for (int b = 0; b < sp.nblocks; b++) {
        sp.block[b].page_rva = (rn(r, 6)) * 0x1000 + 0x1000;
        sp.block[b].nfix = (int)rn(r, 11);
        static const uint8_t types[] = { 0, 1, 2, 3, 4, 5, 9, 10, 10, 10 };
        for (int e = 0; e < sp.block[b].nfix; e++) sp.block[b].fix[e] = (pb_fixup_t){ types[rn(r, 10)], (uint16_t)rn(r, 0x1000) };
    }
    sp.ndebug = (int)rn(r, 4);
    for (int i = 0; i < sp.ndebug; i++) {
        const uint32_t t = rn(r, 4);
        sp.debug[i] = (pb_debug_t){ t == 0 ? 1 : t == 1 ? 13 : 2, t >= 2, pdbs[rn(r, 4)] };
        if (sp.debug[i].type != 2) sp.debug[i].rsds = false;
    }
    sp.npdata = (int)rn(r, 20);
    return sp;
}


#endif /* CBAE_TEST_PE_RANDOM_H */
