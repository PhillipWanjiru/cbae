/**
 * @file lift_helpers.h
 * @brief Header-only test helper: raw x86-64 bytes -> SSA-form CIR function.
 *
 * The Phase 5 analyses are tested on two kinds of input:
 *   - functions built by hand with the CIR builder, where every value and
 *     every edge is chosen so the expected answer can be derived on paper;
 *   - functions lifted from real machine code, to confirm the analyses
 *     hold up on what the lifter and SSA constructor actually produce.
 * This header serves the second kind. It does exactly what the Phase 4
 * tests do inline (image -> CFG -> lift -> SSA), in one call, and asserts
 * on any failure: a test that cannot even build its input has nothing
 * useful to report.
 *
 * Each translation unit includes it, so every function is `static inline`.
 */
#ifndef CBAE_TEST_LIFT_HELPERS_H
#define CBAE_TEST_LIFT_HELPERS_H

#include "cir/cir_lifter.h"
#include "cir/cir_ssa.h"
#include "cir/cir_verifier.h"
#include "cir/cir_builder.h"
#include "disasm/cfg.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct lifted {
    cbae_binary_image_t *img;
    cbae_disassembler_t *dis;
    cbae_arena_t         arena;
    cbae_cfg_t           cfg;
    cbae_cir_function_t *func;      /* SSA form, structurally verified */
} lifted_t;

static inline cbae_binary_image_t *lh_make_image(const uint8_t *code, size_t len,
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

/** Lift `code` (loaded at `base`, entry at `base`) into SSA-form CIR, and
 *  check it with the structural verifier. Release with lifted_destroy(). */
static inline void lift_x86(lifted_t *L, const uint8_t *code, size_t len,
                             cbae_addr_t base, const char *name) {
    memset(L, 0, sizeof(*L));
    L->img = lh_make_image(code, len, base);
    cbae_err_t e = cbae_disasm_create(CBAE_ARCH_X86_64, &L->dis);
    assert(e == CBAE_OK);
    cbae_arena_init(&L->arena, 1024 * 1024);
    e = cbae_cfg_build(L->img, L->dis, base, &L->arena, &L->cfg);
    assert(e == CBAE_OK);
    e = cbae_cir_lift_function(L->img, &L->cfg, NULL, &L->arena, name, &L->func);
    assert(e == CBAE_OK);
    e = cbae_cir_construct_ssa(L->func);
    assert(e == CBAE_OK);
    cbae_cir_verify_result_t vr = cbae_cir_verify_function(L->func);
    assert(vr.ok);
    (void)e; (void)vr;
}

static inline void lifted_destroy(lifted_t *L) {
    cbae_cir_function_destroy(L->func);
    cbae_cfg_destroy(&L->cfg);
    cbae_arena_destroy(&L->arena);
    cbae_disasm_destroy(&L->dis);
    cbae_image_destroy(&L->img);
    memset(L, 0, sizeof(*L));
}

static inline cbae_cir_block_t *lh_block(const cbae_cir_function_t *f, uint32_t id) {
    cbae_cir_block_t **bp = cbae_vector_at(&f->blocks, id);
    return bp ? *bp : NULL;
}

/** The n-th (0-based) instruction with opcode `op`, scanning blocks in id
 *  order and each block front to back. NULL if there are fewer than n+1. */
static inline cbae_cir_instruction_t *lh_nth_insn(const cbae_cir_function_t *f,
                                                    cbae_cir_opcode_t op, uint32_t n) {
    uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    for (uint32_t b = 0; b < nb; b++) {
        cbae_cir_block_t *blk = lh_block(f, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++)
            if (blk->instructions[i]->opcode == op && n-- == 0)
                return blk->instructions[i];
    }
    return NULL;
}

#endif /* CBAE_TEST_LIFT_HELPERS_H */
