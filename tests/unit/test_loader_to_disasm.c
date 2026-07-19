/**
 * @file test_loader_to_disasm.c
 * @brief Integration test: cbae_pe_load() -> cbae_cfg_build().
 *
 * Unlike the other Phase 3 unit tests (which hand-populate a minimal
 * cbae_binary_image_t directly to isolate cfg_builder.c's own logic),
 * this test goes through the REAL PE32+ parser from Phase 2, proving
 * the loader's output (section VA/data mapping, entry_point) feeds
 * correctly into Phase 3's disassembler and CFG construction with no
 * adaptation layer in between -- exactly how CDIS's production
 * pipeline will use both phases together.
 */
#include "loader/pe_loader.h"
#include "disasm/cfg.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define DOS_MAGIC     0x5A4D
#define PE_SIG        0x00004550
#define OPT_PE32P     0x020B
#define MACH_AMD64    0x8664
#define SUBSYS_NATIVE 1
#define IBASE         UINT64_C(0xFFFFF80000000000)

#pragma pack(push,1)
typedef struct { uint16_t magic; uint8_t _[58]; uint32_t lfanew; } t_dos;
typedef struct {
    uint16_t machine,nsec,ts0,ts1; uint32_t sp,ns; uint16_t optsz,chars;
} t_coff;
typedef struct { uint32_t rva,sz; } t_dd;
typedef struct {
    uint16_t magic,ml,mn; uint32_t cs,is,us,ep,cb;
    uint64_t ibase;
    uint32_t sa,fa; uint8_t _w[16];
    uint32_t imgsz,hdrsz,ck; uint16_t sub,dc;
    uint8_t _s[32]; uint32_t ndirs; t_dd dirs[16];
} t_opt;
typedef struct {
    uint8_t name[8]; uint32_t vsz,va,rsz,roff; uint8_t _[12]; uint32_t chars;
} t_sec;
#pragma pack(pop)

static char g_tmp[256];
static void cleanup(void) { if (g_tmp[0]) unlink(g_tmp); }

/* Realistic minimal function: standard prologue, one NOP, standard
 * epilogue. Straight-line -- no branches, no calls -- so the resulting
 * CFG must be exactly one basic block with 7 instructions.
 *
 *   55                push rbp
 *   48 89 E5          mov rbp, rsp
 *   48 83 EC 20       sub rsp, 0x20
 *   90                nop
 *   48 89 EC          mov rsp, rbp
 *   5D                pop rbp
 *   C3                ret
 */
static const uint8_t FUNC_BYTES[] = {
    0x55,
    0x48,0x89,0xE5,
    0x48,0x83,0xEC,0x20,
    0x90,
    0x48,0x89,0xEC,
    0x5D,
    0xC3
};
#define FUNC_LEN  sizeof(FUNC_BYTES)

static void write_synthetic_pe(void) {
    uint8_t buf[0x600];
    memset(buf, 0, sizeof(buf));

    t_dos *dos = (t_dos *)buf;
    dos->magic  = DOS_MAGIC;
    dos->lfanew = 0x40;

    *(uint32_t *)(buf + 0x40) = PE_SIG;

    t_coff *coff = (t_coff *)(buf + 0x44);
    coff->machine = MACH_AMD64;
    coff->nsec    = 1;
    coff->optsz   = (uint16_t)sizeof(t_opt);
    coff->chars   = 0x0002;

    t_opt *opt = (t_opt *)(buf + 0x44 + sizeof(t_coff));
    opt->magic     = OPT_PE32P;
    opt->ep        = 0x1000;      /* DriverEntry at the start of .text  */
    opt->ibase     = IBASE;
    opt->sa        = 0x1000;
    opt->fa        = 0x200;
    opt->imgsz     = 0x3000;
    opt->hdrsz     = 0x400;
    opt->sub       = SUBSYS_NATIVE;
    opt->ndirs     = 16;
    /* All data directories left zeroed -- no imports/exports/relocs.
     * cbae_pe_load's soft-error handling means this is a fully valid,
     * if minimal, driver image. */

    t_sec *sec = (t_sec *)((uint8_t *)opt + sizeof(t_opt));
    memcpy(sec->name, ".text\0\0\0", 8);
    sec->vsz   = 0x1000;
    sec->va    = 0x1000;
    sec->rsz   = (uint32_t)FUNC_LEN;
    sec->roff  = 0x400;
    sec->chars = 0x60000020; /* exec + read + code */

    memcpy(buf + 0x400, FUNC_BYTES, FUNC_LEN);

    snprintf(g_tmp, sizeof(g_tmp), "/tmp/cbae_loader_to_disasm_%d.sys",
             (int)getpid());
    atexit(cleanup);
    FILE *f = fopen(g_tmp, "wb");
    assert(f);
    fwrite(buf, 1, sizeof(buf), f);
    fclose(f);
}

static void t_full_pipeline(void) {
    cbae_binary_image_t *img = NULL;
    assert(cbae_pe_load(g_tmp, &img) == CBAE_OK);
    assert(img != NULL);
    assert(img->entry_point == IBASE + 0x1000);

    /* Confirm Phase 2 mapped the bytes correctly before handing off. */
    const uint8_t *p = cbae_image_va_to_ptr(img, img->entry_point);
    assert(p != NULL);
    assert(p[0] == 0x55); /* push rbp -- first byte of our function */

    cbae_disassembler_t *d;
    assert(cbae_disasm_create(CBAE_ARCH_X86_64, &d) == CBAE_OK);

    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, img->entry_point, &arena, &cfg) == CBAE_OK);

    /* Straight-line prologue/epilogue -> exactly one basic block. */
    assert(cbae_cfg_block_count(&cfg) == 1);

    cbae_basic_block_t *b = cbae_cfg_block_at(&cfg, img->entry_point);
    assert(b != NULL);
    assert(b->instruction_count == 7);
    assert(b->ends_in_ret);
    assert(b->successor_count == 0);

    /* Verify the exact instruction sequence Phase 3 decoded matches
     * what Phase 2 handed it, end to end. */
    assert(b->instructions[0].iclass == CBAE_ICLASS_STACK); /* push rbp */
    assert(b->instructions[1].iclass == CBAE_ICLASS_MOV);   /* mov rbp,rsp */
    assert(b->instructions[2].iclass == CBAE_ICLASS_ARITH); /* sub rsp,0x20 */
    assert(b->instructions[3].iclass == CBAE_ICLASS_NOP);
    assert(b->instructions[4].iclass == CBAE_ICLASS_MOV);   /* mov rsp,rbp */
    assert(b->instructions[5].iclass == CBAE_ICLASS_STACK); /* pop rbp */
    assert(b->instructions[6].iclass == CBAE_ICLASS_RET);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] full pipeline: cbae_pe_load -> cbae_cfg_build, "
           "1 block, 7 instructions, correct sequence\n");
}

int main(void) {
    printf("=== test_loader_to_disasm ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    write_synthetic_pe();
    printf("  synthetic PE: %s\n", g_tmp);

    t_full_pipeline();

    printf("All loader-to-disassembler integration tests passed.\n");
    return 0;
}
