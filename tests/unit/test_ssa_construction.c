/**
 * @file test_ssa_construction.c
 * @brief Phi placement correctness on CFGs with known oracle: hand-traced
 *        straight-line, diamond-merge, and loop-back-edge cases.
 *
 * The loop test's final assertion is the one that matters most in this
 * file: it specifically checks that the loop header's phi merges
 * [const(0) from entry, ADD's real result from the back-edge] -- NOT
 * a self-referential [phi, phi] pair, which is what an earlier,
 * incorrect version of the SSA constructor produced (conflating "what
 * should a placeholder created IN this block resolve to" with "what
 * does this block CONTRIBUTE to a successor," caught by hand-tracing
 * before this test was even written -- see cir_ssa_constructor.c's
 * file header and PHASE4.md for the full story).
 */
#include "cir/cir_lifter.h"
#include "cir/cir_ssa.h"
#include "cir/cir_printer.h"
#include "disasm/cfg.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static cbae_binary_image_t *make_code_image(const uint8_t *code, size_t len,
                                              cbae_addr_t base) {
    cbae_binary_image_t *img = NULL;
    cbae_image_create(0, &img);
    img->format      = CBAE_FMT_PE32PLUS;
    img->arch        = CBAE_ARCH_X86_64;
    img->os_origin   = CBAE_OS_WINDOWS;
    img->load_base   = base;
    img->entry_point = base;

    img->sections = CBAE_ARENA_ALLOC(&img->arena, cbae_section_t);
    img->section_count = 1;
    uint8_t *data = cbae_arena_alloc(&img->arena, len, 1);
    memcpy(data, code, len);

    strncpy(img->sections[0].name, ".text", CBAE_SEC_NAME_MAX - 1);
    img->sections[0].virt_addr   = base;
    img->sections[0].virt_size   = len;
    img->sections[0].file_offset = 0;
    img->sections[0].file_size   = len;
    img->sections[0].flags       = CBAE_SEC_EXEC | CBAE_SEC_READ;
    img->sections[0].data        = data;

    cbae_image_build_indexes(img);
    return img;
}

static uint32_t count_opcode(const cbae_cir_block_t *blk, cbae_cir_opcode_t op) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < blk->instruction_count; i++)
        if (blk->instructions[i]->opcode == op) n++;
    return n;
}

/* ── Test 1: straight-line -- no phis, entry reads become params ─────── */
static void t_straight_line_no_phi(void) {
    /* mov rax,[rbx]; add rax,5; ret -- reused from test_cir_lifter.c */
    uint8_t code[] = { 0x48,0x8B,0x03, 0x48,0x83,0xC0,0x05, 0xC3 };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x2000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x2000, &arena, &cfg) == CBAE_OK);
    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "straight", &f) == CBAE_OK);
    assert(cbae_cir_construct_ssa(f) == CBAE_OK);

    cbae_cir_block_t *blk = cbae_cir_function_block_at(f, 0x2000);
    assert(count_opcode(blk, CIR_OP_PHI) == 0); /* no joins -> no phis */

    cbae_cir_instruction_t *load = blk->instructions[0];
    assert(load->operands[0]->kind == CIR_VAL_PARAM); /* RBX resolved to a
                                                         * function param,
                                                         * not left dangling */
    assert(load->operands[0]->u.param_reg == CBAE_REG_RBX);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] straight-line: zero phis, RBX resolved to a param\n");
}

/* ── Test 2: if-else diamond -- exactly one phi merging two constants ── */
static void t_diamond_real_phi(void) {
    /*   0x1000: 0F 84 0F 00 00 00              je 0x1015        (6 bytes)
     *   0x1006: 48 B8 0A 00 00 00 00 00 00 00  mov rax, 10      (10 bytes)
     *   0x1010: E9 0A 00 00 00                 jmp 0x101F       (5 bytes)
     *   0x1015: 48 B8 14 00 00 00 00 00 00 00  mov rax, 20      (10 bytes) <- je target
     *   0x101F: C3                             ret                        <- join point
     *
     * Hand-traced CFG: block[0x1000] JE, 2 succ; block[0x1006] movabs+jmp,
     * 1 succ->0x101F; block[0x1015] movabs, falls through->0x101F;
     * block[0x101F] ret, 2 PREDECESSORS (0x1006 and 0x1015).
     */
    uint8_t code[] = {
        0x0F,0x84,0x0F,0x00,0x00,0x00,
        0x48,0xB8,0x0A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xE9,0x0A,0x00,0x00,0x00,
        0x48,0xB8,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xC3
    };
    assert(sizeof(code) == 32);

    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x1000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x1000, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 4);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "diamond", &f) == CBAE_OK);
    assert(cbae_cir_construct_ssa(f) == CBAE_OK);

    printf("\n--- CIR (post-SSA) for t_diamond_real_phi ---\n");
    cbae_cir_print_function(f, stdout);
    printf("--- end ---\n\n");

    cbae_cir_block_t *join = cbae_cir_function_block_at(f, 0x101F);
    assert(join != NULL);
    assert(cbae_vector_count(&join->predecessors) == 2);
    assert(count_opcode(join, CIR_OP_PHI) == 1); /* exactly one phi */

    cbae_cir_instruction_t *phi = join->instructions[0];
    assert(phi->opcode == CIR_OP_PHI);
    assert(phi->phi_incoming_count == 2);

    bool saw_10 = false, saw_20 = false;
    for (uint32_t i = 0; i < phi->phi_incoming_count; i++) {
        cbae_cir_value_t *v = phi->phi_incoming_values[i];
        assert(v->kind == CIR_VAL_CONST); /* both incoming are real
                                            * constants, not placeholders
                                            * or self-references          */
        if (v->u.const_val == 10) saw_10 = true;
        if (v->u.const_val == 20) saw_20 = true;
    }
    assert(saw_10 && saw_20);

    /* RET returns exactly the phi's result */
    cbae_cir_instruction_t *ret = join->instructions[1];
    assert(ret->opcode == CIR_OP_RETURN);
    assert(ret->operands[0] == phi->result);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] diamond: exactly 1 phi merging const(10) and const(20)\n");
}

/* ── Test 3: loop back-edge -- the critical cycle-breaking correctness
 *           test, verifying the phi is NOT self-referential ──────────── */
static void t_loop_back_edge_phi(void) {
    /*   0x2000: 48 B8 00 00 00 00 00 00 00 00  mov rax, 0    (10 bytes)
     *   0x200A: 48 83 C0 01                    add rax, 1    (4 bytes)   <- loop head
     *   0x200E: 48 83 F8 0A                    cmp rax, 10   (4 bytes)
     *   0x2012: 0F 8C F2 FF FF FF               jl 0x200A     (6 bytes)  <- back edge
     *   0x2018: C3                              ret                     <- exit
     *
     * Hand-traced CFG: entry[0x2000] movabs(rax=0), falls through into
     * loop head via Phase 3's mid-block SPLIT (jl's target 0x200A lands
     * exactly on the "add" instruction inside what would otherwise be
     * one long block) -- loop head[0x200A] has TWO predecessors: entry
     * AND itself (the back edge).
     */
    uint8_t code[] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x48,0x83,0xC0,0x01,
        0x48,0x83,0xF8,0x0A,
        0x0F,0x8C,0xF2,0xFF,0xFF,0xFF,
        0xC3
    };
    assert(sizeof(code) == 25);

    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x2000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x2000, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 3);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "loop", &f) == CBAE_OK);
    assert(cbae_cir_construct_ssa(f) == CBAE_OK);

    printf("\n--- CIR (post-SSA) for t_loop_back_edge_phi ---\n");
    cbae_cir_print_function(f, stdout);
    printf("--- end ---\n\n");

    cbae_cir_block_t *loop_head = cbae_cir_function_block_at(f, 0x200A);
    assert(loop_head != NULL);
    assert(cbae_vector_count(&loop_head->predecessors) == 2);
    assert(count_opcode(loop_head, CIR_OP_PHI) == 1);

    cbae_cir_instruction_t *phi = loop_head->instructions[0];
    assert(phi->opcode == CIR_OP_PHI);
    assert(phi->phi_incoming_count == 2);

    cbae_cir_instruction_t *add = loop_head->instructions[1];
    assert(add->opcode == CIR_OP_ADD);
    assert(add->operands[0] == phi->result); /* add reads the phi */

    /* THE key assertion: the phi's incoming values must be
     * [const(0) from entry] and [add's OWN result from the back edge]
     * -- NEVER the phi referencing itself. A self-referential phi here
     * would mean the loop's induction variable never actually picks up
     * the loop body's computation -- silently wrong SSA that would
     * still "look" structurally plausible without this specific check. */
    bool saw_const0 = false, saw_add_result = false, saw_self_reference = false;
    for (uint32_t i = 0; i < phi->phi_incoming_count; i++) {
        cbae_cir_value_t *v = phi->phi_incoming_values[i];
        if (v == phi->result) saw_self_reference = true;
        if (v->kind == CIR_VAL_CONST && v->u.const_val == 0) saw_const0 = true;
        if (v == add->result) saw_add_result = true;
    }
    assert(!saw_self_reference);
    assert(saw_const0);
    assert(saw_add_result);

    /* The exit block's RET must resolve DIRECTLY to add's result (loop
     * head has exactly one successor path out, no phi needed there) --
     * NOT to the loop head's phi. */
    cbae_cir_block_t *exit_blk = cbae_cir_function_block_at(f, 0x2018);
    assert(exit_blk != NULL);
    assert(count_opcode(exit_blk, CIR_OP_PHI) == 0);
    cbae_cir_instruction_t *ret = exit_blk->instructions[0];
    assert(ret->opcode == CIR_OP_RETURN);
    assert(ret->operands[0] == add->result);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] loop: phi correctly merges [const(0), add's real result], "
           "not self-referential\n");
}

int main(void) {
    printf("=== test_ssa_construction ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_straight_line_no_phi();
    t_diamond_real_phi();
    t_loop_back_edge_phi();

    printf("All SSA construction tests passed.\n");
    return 0;
}
