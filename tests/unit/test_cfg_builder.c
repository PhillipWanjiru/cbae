/**
 * @file test_cfg_builder.c
 * @brief Unit tests for recursive-descent CFG construction: straight-line
 *        runs, if-else branching, call-site splitting, and the mid-block
 *        split-on-convergence case.
 *
 * Uses a minimal synthetic cbae_binary_image_t (one hand-populated
 * section, no PE/ELF parsing involved) so these tests exercise ONLY
 * cfg_builder.c's own logic against Phase 2's binary_image lookup API
 * -- not the loaders, which test_pe_loader.c / test_elf_loader.c
 * already cover.
 */
#include "disasm/cfg.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ── Minimal synthetic image builder (shared pattern for Phase 3 tests) ── */
static cbae_binary_image_t *make_code_image(const uint8_t *code, size_t len,
                                              cbae_addr_t base) {
    cbae_binary_image_t *img = NULL;
    cbae_image_create(0, &img);
    img->format     = CBAE_FMT_PE32PLUS;
    img->arch       = CBAE_ARCH_X86_64;
    img->os_origin  = CBAE_OS_WINDOWS;
    img->load_base  = base;
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

/* ── Test 1: straight-line block ─────────────────────────────────────── */
static void t_straight_line(void) {
    uint8_t code[] = {0x90, 0x90, 0x90, 0xC3}; /* nop nop nop ret */
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x1000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x1000, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 1);

    cbae_basic_block_t *b = cbae_cfg_block_at(&cfg, 0x1000);
    assert(b && b->instruction_count == 4);
    assert(b->ends_in_ret);
    assert(b->successor_count == 0);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] straight-line: 1 block, 4 instructions, ends_in_ret\n");
}

/* ── Test 2: call splits the block, return site starts a new one ────── */
static void t_call_splits_block(void) {
    /* call rel32 (target = self, harmless -- we only check structure);
     * ret */
    uint8_t code[] = {
        0xE8, 0x00,0x00,0x00,0x00,  /* call +0 -> targets next byte      */
        0xC3                         /* ret                               */
    };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x2000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x2000, &arena, &cfg) == CBAE_OK);

    cbae_basic_block_t *call_blk = cbae_cfg_block_at(&cfg, 0x2000);
    assert(call_blk && call_blk->instruction_count == 1);
    assert(call_blk->ends_in_call);
    assert(call_blk->successor_count == 1);
    assert(call_blk->successors[0].kind == CBAE_EDGE_CALL_RETURN);
    assert(call_blk->successors[0].target == 0x2005); /* addr after the 5-byte call */

    cbae_basic_block_t *ret_blk = cbae_cfg_block_at(&cfg, 0x2005);
    assert(ret_blk && ret_blk->instruction_count == 1);
    assert(ret_blk->ends_in_ret);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] CALL ends block with CALL_RETURN edge to return site\n");
}

/* ── Test 3: if-else diamond, no split needed (targets are fresh addrs) ── */
static void t_if_else_diamond(void) {
    /*
     * 0x3000: 74 04       je 0x3006      (len2, next=0x3002, target=0x3002+4=0x3006)
     * 0x3002: 90          nop
     * 0x3003: EB 02       jmp 0x3007     (len2, next=0x3005, target=0x3005+2=0x3007)
     * 0x3005: 90          nop            (filler, unreached)
     * 0x3006: C3          ret            <- JE taken target
     * 0x3007: C3          ret            <- JMP target (convergence)
     */
    uint8_t code[] = {0x74,0x04, 0x90, 0xEB,0x02, 0x90, 0xC3, 0xC3};
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x3000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x3000, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 4);

    cbae_basic_block_t *je_blk = cbae_cfg_block_at(&cfg, 0x3000);
    assert(je_blk && je_blk->instruction_count == 1);
    assert(je_blk->successor_count == 2);

    bool saw_fallthrough = false, saw_taken = false;
    for (int i = 0; i < je_blk->successor_count; i++) {
        if (je_blk->successors[i].kind == CBAE_EDGE_FALLTHROUGH &&
            je_blk->successors[i].target == 0x3002) saw_fallthrough = true;
        if (je_blk->successors[i].kind == CBAE_EDGE_BRANCH_TAKEN &&
            je_blk->successors[i].target == 0x3006) saw_taken = true;
    }
    assert(saw_fallthrough && saw_taken);

    cbae_basic_block_t *fall_blk = cbae_cfg_block_at(&cfg, 0x3002);
    assert(fall_blk && fall_blk->instruction_count == 2); /* nop + jmp */
    assert(fall_blk->successor_count == 1);
    assert(fall_blk->successors[0].target == 0x3007);

    cbae_basic_block_t *je_target = cbae_cfg_block_at(&cfg, 0x3006);
    assert(je_target && je_target->ends_in_ret);

    cbae_basic_block_t *converge = cbae_cfg_block_at(&cfg, 0x3007);
    assert(converge && converge->ends_in_ret);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] if-else diamond: 4 blocks, correct edges\n");
}

/* ── Test 4: mid-block split on convergence (the hard case) ─────────── */
static void t_split_on_convergence(void) {
    /*
     * 0x4000: 74 02       je 0x4004      (len2, next=0x4002, target=0x4002+2=0x4004)
     * 0x4002: 90          nop
     * 0x4003: 90          nop
     * 0x4004: 90          nop            <- JE taken target lands EXACTLY
     *                                       on this instruction boundary,
     *                                       which is mid-way through what
     *                                       the fallthrough path (processed
     *                                       first, per cfg_builder's
     *                                       reverse-enqueue ordering)
     *                                       already decoded as one block.
     * 0x4005: C3          ret
     */
    uint8_t code[] = {0x74,0x02, 0x90,0x90,0x90, 0xC3};
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x4000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x4000, &arena, &cfg) == CBAE_OK);

    /* Exactly 3 blocks: [0x4000 JE] [0x4002 nop,nop -> split] [0x4004 nop,ret] */
    assert(cbae_cfg_block_count(&cfg) == 3);

    cbae_basic_block_t *je_blk = cbae_cfg_block_at(&cfg, 0x4000);
    assert(je_blk && je_blk->instruction_count == 1 && je_blk->successor_count == 2);

    cbae_basic_block_t *truncated = cbae_cfg_block_at(&cfg, 0x4002);
    assert(truncated && truncated->instruction_count == 2); /* split truncated it to 2 */
    assert(truncated->successor_count == 1);
    assert(truncated->successors[0].kind == CBAE_EDGE_FALLTHROUGH);
    assert(truncated->successors[0].target == 0x4004);
    assert(!truncated->ends_in_ret); /* correctly cleared by the split */

    cbae_basic_block_t *tail = cbae_cfg_block_at(&cfg, 0x4004);
    assert(tail && tail->instruction_count == 2); /* nop + ret, sliced from
                                                     * the SAME arena array
                                                     * the truncated block
                                                     * still owns its head of */
    assert(tail->ends_in_ret);
    assert(tail->successor_count == 0);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] mid-block split on convergence (3 blocks, correct split)\n");
}

/* ── Test 5: backward branch classified as CBAE_EDGE_BACK (loop) ────── */
static void t_back_edge_loop(void) {
    /*
     * 0x5000: 90          nop            <- loop head
     * 0x5001: 90          nop
     * 0x5002: EB FC       jmp -4         (len2, next=0x5004, target=0x5004-4=0x5000)
     */
    uint8_t code[] = {0x90, 0x90, 0xEB, 0xFC};
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x5000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x5000, &arena, &cfg) == CBAE_OK);

    cbae_basic_block_t *b = cbae_cfg_block_at(&cfg, 0x5000);
    assert(b && b->instruction_count == 3); /* nop, nop, jmp */
    assert(b->successor_count == 1);
    assert(b->successors[0].kind == CBAE_EDGE_BACK);
    assert(b->successors[0].target == 0x5000);

    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] backward JMP classified as CBAE_EDGE_BACK (loop)\n");
}

int main(void) {
    printf("=== test_cfg_builder ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_straight_line();
    t_call_splits_block();
    t_if_else_diamond();
    t_split_on_convergence();
    t_back_edge_loop();

    printf("All CFG builder tests passed.\n");
    return 0;
}
