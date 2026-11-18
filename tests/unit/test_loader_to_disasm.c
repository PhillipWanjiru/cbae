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

/* What the decoder must report for each instruction of FUNC_BYTES, in order: where it starts, how long it is, its
 * mnemonic, its class and its operands (a register, or an immediate). Only fields that do not depend on the Capstone
 * version are checked here; the decoder's own test pins the others. */
typedef struct { cbae_operand_kind_t kind; int64_t v; } opnd_exp_t;     /* v: the register, or the immediate */
typedef struct {
    uint8_t off, len;
    const char *mnemonic;
    cbae_insn_class_t iclass;
    uint8_t nops;
    opnd_exp_t op[2];
} insn_exp_t;

static const insn_exp_t EXPECT[] = {
    {  0, 1, "push", CBAE_ICLASS_STACK, 1, {{CBAE_OPND_REG, CBAE_REG_RBP}} },
    {  1, 3, "mov",  CBAE_ICLASS_MOV,   2, {{CBAE_OPND_REG, CBAE_REG_RBP}, {CBAE_OPND_REG, CBAE_REG_RSP}} },
    {  4, 4, "sub",  CBAE_ICLASS_ARITH, 2, {{CBAE_OPND_REG, CBAE_REG_RSP}, {CBAE_OPND_IMM, 0x20}} },
    {  8, 1, "nop",  CBAE_ICLASS_NOP,   0, {{0, 0}} },
    {  9, 3, "mov",  CBAE_ICLASS_MOV,   2, {{CBAE_OPND_REG, CBAE_REG_RSP}, {CBAE_OPND_REG, CBAE_REG_RBP}} },
    { 12, 1, "pop",  CBAE_ICLASS_STACK, 1, {{CBAE_OPND_REG, CBAE_REG_RBP}} },
    { 13, 1, "ret",  CBAE_ICLASS_RET,   0, {{0, 0}} },
};
#define N_EXPECT (sizeof(EXPECT) / sizeof(EXPECT[0]))

static void t_full_pipeline(void) {
    cbae_binary_image_t *img = NULL;
    assert(cbae_pe_load(g_tmp, &img) == CBAE_OK);
    assert(img != NULL);
    assert(img->entry_point == IBASE + 0x1000);

    /* Phase 2 must have mapped every byte of the function, in order, at the entry point. */
    const uint8_t *p = cbae_image_va_to_ptr(img, img->entry_point);
    assert(p != NULL);
    assert(memcmp(p, FUNC_BYTES, FUNC_LEN) == 0);

    cbae_disassembler_t *d;
    assert(cbae_disasm_create(CBAE_ARCH_X86_64, &d) == CBAE_OK);

    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, img->entry_point, &arena, &cfg) == CBAE_OK);

    /* Straight-line prologue/epilogue -> exactly one basic block, found by its start address only. */
    assert(cbae_cfg_block_count(&cfg) == 1);
    cbae_basic_block_t *b = cbae_cfg_block_at(&cfg, img->entry_point);
    assert(b != NULL);
    assert(cbae_cfg_block_at_index(&cfg, 0) == b);
    assert(cbae_cfg_block_at_index(&cfg, 1) == NULL);
    assert(cbae_cfg_block_at(&cfg, img->entry_point + 1) == NULL);
    assert(b->start_addr == img->entry_point);
    assert(b->end_addr == img->entry_point + FUNC_LEN);
    assert(b->instruction_count == N_EXPECT);
    assert(b->ends_in_ret);
    assert(!b->ends_in_call && !b->ends_in_unresolved_branch);
    assert(b->successor_count == 0);

    /* The exact instruction sequence Phase 3 decoded from what Phase 2 handed it, end to end. */
    uint32_t covered = 0;
    for (uint32_t i = 0; i < N_EXPECT; i++) {
        const insn_exp_t *e = &EXPECT[i];
        const cbae_instruction_t *in = &b->instructions[i];
        assert(e->off == covered);
        assert(in->address == img->entry_point + e->off);
        assert(in->length == e->len);
        assert(memcmp(in->raw, FUNC_BYTES + e->off, e->len) == 0);
        assert(strcmp(in->mnemonic, e->mnemonic) == 0);
        assert(in->iclass == e->iclass);
        assert(in->operand_count == e->nops);
        for (uint8_t k = 0; k < e->nops; k++) {
            assert(in->operands[k].kind == e->op[k].kind);
            if (e->op[k].kind == CBAE_OPND_REG) assert((int64_t)in->operands[k].u.reg.reg == e->op[k].v);
            else                                 assert(in->operands[k].u.imm.value == e->op[k].v);
        }
        /* only the return is a branch, and it has no direct target */
        const bool is_ret = e->iclass == CBAE_ICLASS_RET;
        assert(in->is_ret == is_ret && in->is_branch == is_ret);
        assert(!in->is_call && !in->is_conditional && !in->branch_target_is_direct);
        covered += e->len;
    }
    assert(covered == FUNC_LEN);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] full pipeline: cbae_pe_load -> cbae_cfg_build, 1 block, 7 instructions, each checked for "
           "address, bytes, mnemonic, class and operands\n");
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
