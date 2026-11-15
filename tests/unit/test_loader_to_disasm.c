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
#include "pe_builder.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define IBASE         UINT64_C(0xFFFFF80000000000)



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
    /* one executable section, written by the independent spec-based builder (pe_builder.h), not through a
     * struct the loader shares: a struct copied from the loader hid a two-byte layout error for two phases */
    pb_mini_t m = pb_mini((uint32_t)FUNC_LEN);
    const uint32_t sh = m.opt + PB_OPT_PE32P_SIZE;                        /* the section header */
    memcpy(m.b + sh + PB_SEC_NAME, ".text\0\0\0", 8);
    pb_w32(m.b, sh + PB_SEC_VSIZE, 0x1000);
    pb_w32(m.b, sh + PB_SEC_CHARS, PB_SCN_CODE | PB_SCN_EXEC | PB_SCN_READ);
    pb_w32(m.b, m.opt + PB_OPT_ENTRY_RVA, 0x1000);                        /* DriverEntry at the start of .text */
    pb_w64(m.b, m.opt + PB_OPT_IMAGE_BASE, IBASE);
    memcpy(m.b + m.sec_off, FUNC_BYTES, FUNC_LEN);

    snprintf(g_tmp, sizeof(g_tmp), "/tmp/cbae_loader_to_disasm_%d.sys", (int)getpid());
    atexit(cleanup);
    const pb_file_t file = { m.b, m.n };
    assert(pb_write(g_tmp, &file));
    pb_mini_free(&m);
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
