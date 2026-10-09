/**
 * @file cir_test_util.h
 * @brief Test support: building small CIR functions by hand.
 *
 * Each test builds the function whose answer it derived on paper, so the
 * construction is spelled out value by value. This header holds the plumbing
 * those tests share: a function with its arena, a builder cursor, one-line
 * wrappers for the common operations, and a way to name the instruction an
 * emitting call just produced (the builder returns values, not instructions).
 *
 * Everything is `static inline`, so a test that does not use a helper is not
 * warned about it.
 */
#ifndef CBAE_TEST_CIR_TEST_UTIL_H
#define CBAE_TEST_CIR_TEST_UTIL_H

#include "cir/cir_builder.h"
#include "cir/cir_verifier.h"
#include "platform/memory.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define T64 cir_type_i(64)
#define T32 cir_type_i(32)
#define T8  cir_type_i(8)

typedef struct {
    cbae_arena_t         arena;
    cbae_cir_function_t *f;
    cbae_cir_builder_t   bld;
    cbae_cir_block_t    *b0;
} fn_t;

/* The arena has a fixed capacity and the builder returns NULL when it is
 * spent, so tests that build thousands of blocks ask for more. */
static inline void fn_init_sized(fn_t *x, const char *name, size_t arena_bytes) {
    memset(x, 0, sizeof *x);
    assert(cbae_arena_init(&x->arena, arena_bytes) == CBAE_OK);
    assert(cbae_cir_function_create(&x->arena, 0x1000, name, &x->f) == CBAE_OK);
    assert(cbae_cir_block_create(x->f, 0x1000, &x->b0) == CBAE_OK);
    cbae_cir_builder_init(&x->bld, x->f, x->b0);
}

static inline void fn_init(fn_t *x, const char *name) { fn_init_sized(x, name, 512 * 1024); }

static inline cbae_cir_block_t *fn_block(fn_t *x, cbae_addr_t addr) {
    cbae_cir_block_t *b;
    assert(cbae_cir_block_create(x->f, addr, &b) == CBAE_OK);
    return b;
}

/** Point the builder at `blk`. */
static inline void fn_at(fn_t *x, cbae_cir_block_t *blk) { cbae_cir_builder_init(&x->bld, x->f, blk); }

static inline void fn_done(fn_t *x) {
    cbae_cir_function_destroy(x->f);
    cbae_arena_destroy(&x->arena);
}

/** Fail loudly (with the verifier's message) if the hand-built function is not
 *  structurally valid: a test on a broken input would prove nothing. */
static inline void fn_verify(const fn_t *x) {
    const cbae_cir_verify_result_t vr = cbae_cir_verify_function(x->f);
    if (!vr.ok) fprintf(stderr, "hand-built function is invalid: %s\n", vr.message);
    assert(vr.ok);
}

/* ── One-line builders ────────────────────────────────────────────────── */

static inline cbae_cir_value_t *k_const(cbae_cir_builder_t *b, int64_t v) { return cbae_cir_const(b, T64, v); }
static inline cbae_cir_value_t *k_add(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_ADD, x, y, T64, 0);
}
static inline cbae_cir_value_t *k_sub(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_SUB, x, y, T64, 0);
}
static inline cbae_cir_value_t *k_mul(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_MUL, x, y, T64, 0);
}
static inline cbae_cir_value_t *k_load(cbae_cir_builder_t *b, cbae_cir_value_t *addr) {
    return cbae_cir_load(b, addr, T64, 0);
}
static inline cbae_cir_value_t *k_load_t(cbae_cir_builder_t *b, cbae_cir_value_t *addr, cbae_cir_type_t t) {
    return cbae_cir_load(b, addr, t, 0);
}

/** The instruction most recently appended to the builder's block. */
static inline cbae_cir_instruction_t *k_last(const cbae_cir_builder_t *b) {
    assert(b->block->instruction_count > 0);
    return b->block->instructions[b->block->instruction_count - 1];
}

/** The instruction that defines `v` (which must be an instruction result). */
static inline cbae_cir_instruction_t *k_def(const cbae_cir_value_t *v) {
    assert(v && v->kind == CIR_VAL_INSN_RESULT);
    return v->u.def_insn;
}

/** Emit a STORE and return its instruction. */
static inline cbae_cir_instruction_t *k_store(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                              cbae_cir_value_t *val) {
    cbae_cir_store(b, addr, val, 0);
    return k_last(b);
}

/** Emit a CALL with no arguments and return its instruction. */
static inline cbae_cir_instruction_t *k_call(cbae_cir_builder_t *b, const char *name) {
    cbae_cir_value_t *r = cbae_cir_call(b, name, NULL, 0, T64, 0);
    assert(r);
    return k_def(r);
}

/** Emit any opcode with no result and return its instruction (for opcodes
 *  and operand counts the convenience wrappers do not cover). */
static inline cbae_cir_instruction_t *k_raw(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                            cbae_cir_value_t **ops, uint8_t n) {
    cbae_cir_emit(b, op, cir_type_void(), 0, ops, n);
    return k_last(b);
}

#endif /* CBAE_TEST_CIR_TEST_UTIL_H */
