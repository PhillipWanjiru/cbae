/**
 * @file test_alias_analysis.c
 * @brief Alias analysis.
 *
 * Every NO / MUST / MAY below is derived on paper from the function being
 * queried -- the form of each address and the arithmetic on its offsets --
 * not read off the analysis output. Each query is checked in both argument
 * orders (the relation is symmetric).
 *
 *   - straight-line shapes: one root with offsets, stack frames, absolute
 *     addresses, loaded pointers, indexed addressing, the atom cap,
 *     wrap-around, budget limits;
 *   - loops: unstable atoms must give MAY, stable roots inside a loop must
 *     still be precise, and redundant phis (loop-invariant registers,
 *     nested loops, push/pop pairs) must resolve to their real value;
 *   - lifted machine code, including the case that motivated the
 *     protection against the lifter's single "other" register.
 *
 * The concrete-execution soundness check lives in test_alias_soundness.c.
 */
#include "dataflow/alias_analysis.h"
#include "cir/cir_builder.h"
#include "cir/cir_verifier.h"
#include "platform/logging.h"
#include "lift_helpers.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Tiny construction helpers ───────────────────────────────────────── */

#define T64 cir_type_i(64)

static cbae_cir_value_t *k_const(cbae_cir_builder_t *b, int64_t v) { return cbae_cir_const(b, T64, v); }
static cbae_cir_value_t *k_add(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_ADD, x, y, T64, 0);
}
static cbae_cir_value_t *k_sub(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_SUB, x, y, T64, 0);
}
static cbae_cir_value_t *k_mul(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_MUL, x, y, T64, 0);
}
static cbae_cir_value_t *k_shl(cbae_cir_builder_t *b, cbae_cir_value_t *x, cbae_cir_value_t *y) {
    return cbae_cir_binop(b, CIR_OP_SHL, x, y, T64, 0);
}
static cbae_cir_value_t *k_neg(cbae_cir_builder_t *b, cbae_cir_value_t *x) {
    cbae_cir_value_t *ops[1] = { x };
    return cbae_cir_emit(b, CIR_OP_NEG, T64, 0, ops, 1);
}
static cbae_cir_value_t *k_load(cbae_cir_builder_t *b, cbae_cir_value_t *addr) {
    return cbae_cir_load(b, addr, T64, 0);
}
static cbae_cir_value_t *k_copy(cbae_cir_builder_t *b, cbae_cir_value_t *x) {
    cbae_cir_value_t *ops[1] = { x };
    return cbae_cir_emit(b, CIR_OP_COPY, T64, 0, ops, 1);
}

typedef struct {
    cbae_arena_t         arena;
    cbae_cir_function_t *f;
    cbae_cir_builder_t   bld;
    cbae_cir_block_t    *b0;
} fn_t;

/* The arena has a fixed capacity and the builder returns NULL when it is spent,
 * so the tests that build hundreds of blocks ask for more. */
static void fn_init_sized(fn_t *x, const char *name, size_t arena_bytes) {
    memset(x, 0, sizeof *x);
    assert(cbae_arena_init(&x->arena, arena_bytes) == CBAE_OK);
    assert(cbae_cir_function_create(&x->arena, 0x1000, name, &x->f) == CBAE_OK);
    assert(cbae_cir_block_create(x->f, 0x1000, &x->b0) == CBAE_OK);
    cbae_cir_builder_init(&x->bld, x->f, x->b0);
}

static void fn_init(fn_t *x, const char *name) { fn_init_sized(x, name, 512 * 1024); }

static cbae_cir_block_t *fn_block(fn_t *x, cbae_addr_t addr) {
    cbae_cir_block_t *b;
    assert(cbae_cir_block_create(x->f, addr, &b) == CBAE_OK);
    return b;
}

static void fn_done(fn_t *x) {
    cbae_cir_function_destroy(x->f);
    cbae_arena_destroy(&x->arena);
}

typedef struct {
    cbae_use_def_t    ud;
    cbae_alias_ctx_t  ctx;
} an_t;

static void an_build(an_t *a, const cbae_cir_function_t *f) {
    cbae_cir_verify_result_t vr = cbae_cir_verify_function(f);
    if (!vr.ok) fprintf(stderr, "hand-built function is invalid: %s\n", vr.message);
    assert(vr.ok);
    assert(cbae_use_def_build(f, &a->ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&a->ud, &a->ctx) == CBAE_OK);
}

static void an_free(an_t *a) {
    cbae_alias_ctx_destroy(&a->ctx);
    cbae_use_def_destroy(&a->ud);
}

/* For functions that are not valid SSA (or not valid at all) on purpose. */
static void an_build_unchecked(an_t *a, const cbae_cir_function_t *f) {
    assert(cbae_use_def_build(f, &a->ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&a->ud, &a->ctx) == CBAE_OK);
}

/* `v` stands for itself: offset 0 and the single term v with coefficient 1. */
static bool is_atom(const cbae_addr_info_t *i, const cbae_cir_value_t *v) {
    return i->offset == 0 && i->term_count == 1 &&
           i->terms[0].value == v && i->terms[0].coeff == 1;
}

static const char *rname(cbae_alias_result_t r) {
    return r == CBAE_ALIAS_NO ? "NO" : r == CBAE_ALIAS_MUST ? "MUST" : "MAY";
}

static void expect(const an_t *an, const char *what,
                   const cbae_cir_value_t *a, uint32_t sa,
                   const cbae_cir_value_t *b, uint32_t sb, cbae_alias_result_t want) {
    const cbae_alias_result_t g1 = cbae_alias_query(&an->ctx, a, sa, b, sb);
    const cbae_alias_result_t g2 = cbae_alias_query(&an->ctx, b, sb, a, sa);
    if (g1 != want || g2 != want)
        fprintf(stderr, "FAIL [%s]: want %s, got %s (swapped: %s)\n",
                what, rname(want), rname(g1), rname(g2));
    assert(g1 == want && g2 == want);
}

#define NO   CBAE_ALIAS_NO
#define MAY  CBAE_ALIAS_MAY
#define MUST CBAE_ALIAS_MUST

/* ── Straight-line ───────────────────────────────────────────────────── */

static void t_same_root_offsets(void) {
    fn_t x; fn_init(&x, "same_root");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c0 = k_const(b, 0), *c4 = k_const(b, 4), *c7 = k_const(b, 7), *c8 = k_const(b, 8);
    cbae_cir_value_t *p8  = k_add(b, p, c8);
    cbae_cir_value_t *p4  = k_add(b, p, c4);
    cbae_cir_value_t *p7  = k_add(b, p, c7);
    cbae_cir_value_t *pm8 = k_sub(b, p, c8);
    cbae_cir_value_t *p0b = k_add(b, p, c0);
    cbae_cir_value_t *pmax  = k_add(b, p, k_const(b, (int64_t)CBAE_ALIAS_MAX_ACCESS_SIZE));
    cbae_cir_value_t *pmax1 = k_add(b, p, k_const(b, (int64_t)CBAE_ALIAS_MAX_ACCESS_SIZE + 1));
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    /* One root p. Access A at offset a, size sa; B at b, size sb:
     * disjoint iff b >= a+sa or b+sb <= a; identical iff same offset+size. */
    expect(&an, "p+0/8 vs p+8/8 (adjacent)",   p, 8, p8, 8, NO);
    expect(&an, "p+0/8 vs p+0/8 (identical)",  p, 8, p,  8, MUST);
    expect(&an, "p+0/8 vs (p+0)+0/8 (other SSA value, same form)", p, 8, p0b, 8, MUST);
    expect(&an, "p+0/8 vs p+4/8 (partial overlap)", p, 8, p4, 8, MAY);
    expect(&an, "p+0/8 vs p+0/4 (same start, sizes differ)", p, 8, p, 4, MAY);
    expect(&an, "p+0/4 vs p+4/4",              p, 4, p4, 4, NO);
    expect(&an, "p+0/4 vs p+4/8",              p, 4, p4, 8, NO);
    expect(&an, "p+0/8 vs p-8/8",              p, 8, pm8, 8, NO);
    expect(&an, "p+0/8 vs p+7/1 (last byte)",  p, 8, p7, 1, MAY);
    expect(&an, "p+0/8 vs p+8/1 (first byte after)", p, 8, p8, 1, NO);
    expect(&an, "p+0/1 vs p+0/1",              p, 1, p, 1, MUST);
    expect(&an, "unknown size A",              p, CBAE_ALIAS_UNKNOWN_SIZE, p8, 8, MAY);
    expect(&an, "unknown size B",              p, 8, p, CBAE_ALIAS_UNKNOWN_SIZE, MAY);
    /* [p, p+MAX) and [p+MAX, p+MAX+8) are disjoint, and MAX is still supported. */
    expect(&an, "largest supported size can still prove NO",   p, CBAE_ALIAS_MAX_ACCESS_SIZE, pmax, 8, NO);
    expect(&an, "largest supported size, same start: overlap", p, CBAE_ALIAS_MAX_ACCESS_SIZE, p, 8, MAY);
    /* One byte more and the analysis declines, though [p, p+MAX+1) and
     * [p+MAX+1, p+MAX+9) are disjoint on paper. */
    expect(&an, "size beyond the maximum is not reasoned about", p, CBAE_ALIAS_MAX_ACCESS_SIZE + 1, pmax1, 8, MAY);
    expect(&an, "NULL address",                NULL, 8, p, 8, MAY);

    cbae_alias_ctx_t *c = &an.ctx;
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(c, p7, &info) && info.offset == 7 && info.term_count == 1 &&
           info.terms[0].value == p && info.terms[0].coeff == 1);
    assert(cbae_alias_decompose(c, pm8, &info) && info.offset == -8);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] one root, constant offsets: adjacency, partial overlap, sizes, limits\n");
}

static void t_stack_frame(void) {
    fn_t x; fn_init(&x, "stack");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *rsp0 = cbae_cir_param(b, CBAE_REG_RSP);
    cbae_cir_value_t *c8 = k_const(b, 8), *c28 = k_const(b, 0x28), *c20 = k_const(b, 0x20), *c18 = k_const(b, 0x18);

    /* push, push, then 'add rsp, 8': s1 = rsp0-8, s2 = s1-8, s3 = s2+8 = rsp0-8 */
    cbae_cir_value_t *s1 = k_sub(b, rsp0, c8);
    cbae_cir_value_t *s2 = k_sub(b, s1, c8);
    cbae_cir_value_t *s3 = k_add(b, s2, c8);
    /* sub rsp,0x28 ; slots at [rsp+0x20] and [rsp+0x18] */
    cbae_cir_value_t *fr = k_sub(b, rsp0, c28);
    cbae_cir_value_t *y  = k_add(b, fr, c20);        /* rsp0 - 8    */
    cbae_cir_value_t *z  = k_add(b, fr, c18);        /* rsp0 - 0x10 */
    cbae_cir_return(b, rsp0, 0);
    an_t an; an_build(&an, x.f);

    expect(&an, "[rsp-8] vs [rsp-16]",              s1, 8, s2, 8, NO);
    expect(&an, "[rsp-8] vs [rsp0]",                s1, 8, rsp0, 8, NO);
    expect(&an, "[s2+8] is [s1]",                   s3, 8, s1, 8, MUST);
    expect(&an, "[rsp-16] vs [s2+8]",               s2, 8, s3, 8, NO);
    expect(&an, "frame slots 0x20 vs 0x18",         y, 8, z, 8, NO);
    expect(&an, "frame slot 0x20 is the first push", y, 8, s1, 8, MUST);
    expect(&an, "frame slot 0x18 is the second push", z, 8, s2, 8, MUST);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] stack frame: push/sub chains reduce to entry-rsp offsets\n");
}

static void t_absolute(void) {
    fn_t x; fn_init(&x, "absolute");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *g0 = k_const(b, 0x1000), *g8 = k_const(b, 0x1008), *g4 = k_const(b, 0x1004);
    cbae_cir_value_t *c8 = k_const(b, 8);
    cbae_cir_value_t *gsum = k_add(b, k_const(b, 0x1000), c8);          /* folds to 0x1008 */
    cbae_cir_value_t *m8 = k_const(b, -8), *zero = k_const(b, 0);
    cbae_cir_value_t *m8b = k_sub(b, k_const(b, 0), c8);                /* 0 - 8 */
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_return(b, g0, 0);
    an_t an; an_build(&an, x.f);

    expect(&an, "0x1000 vs 0x1008",           g0, 8, g8, 8, NO);
    expect(&an, "0x1000 vs 0x1004",           g0, 8, g4, 8, MAY);
    expect(&an, "0x1008 vs 0x1000+8",         g8, 8, gsum, 8, MUST);
    expect(&an, "0x1000 vs 0x1000",           g0, 8, g0, 8, MUST);
    expect(&an, "-8 vs 0 (negative address)", m8, 8, zero, 8, NO);
    expect(&an, "-8 vs 0-8",                  m8, 8, m8b, 8, MUST);
    expect(&an, "absolute vs parameter",      g0, 8, p, 8, MAY);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, gsum, &info) && info.term_count == 0 && info.offset == 0x1008);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] absolute addresses: constants fold, no atoms, plain arithmetic\n");
}

static void t_distinct_atoms(void) {
    fn_t x; fn_init(&x, "atoms");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p1 = cbae_cir_param(b, CBAE_REG_RBX), *p2 = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c8 = k_const(b, 8);
    cbae_cir_value_t *q    = k_add(b, p1, k_mul(b, p2, c8));
    cbae_cir_value_t *p1_8 = k_add(b, p1, c8), *p2_8 = k_add(b, p2, c8);
    cbae_cir_return(b, p1, 0);
    an_t an; an_build(&an, x.f);

    expect(&an, "two different parameters",          p1, 8, p2, 8, MAY);
    expect(&an, "base vs base+index*8",              p1, 8, q, 8, MAY);
    expect(&an, "different parameters, same offset", p1_8, 8, p2_8, 8, MAY);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] different atoms are never related\n");
}

static void t_loaded_pointer(void) {
    fn_t x; fn_init(&x, "loaded");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c8 = k_const(b, 8);
    cbae_cir_value_t *v  = k_load(b, p);                    /* a pointer read from memory */
    cbae_cir_value_t *v8 = k_add(b, v, c8);
    cbae_cir_return(b, v, 0);
    an_t an; an_build(&an, x.f);

    expect(&an, "[v] vs [v+8]: loaded pointer, acyclic block", v, 8, v8, 8, NO);
    expect(&an, "[v] vs [v]",                                  v, 8, v, 8, MUST);
    expect(&an, "[v] vs [p]",                                  v, 8, p, 8, MAY);
    assert(cbae_alias_value_is_stable(&an.ctx, v));

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] loaded pointer: a stable atom, so field offsets are precise\n");
}

static void t_indexed(void) {
    fn_t x; fn_init(&x, "indexed");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *base = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *i = cbae_cir_param(b, CBAE_REG_RCX), *j = cbae_cir_param(b, CBAE_REG_RDX);
    cbae_cir_value_t *c3 = k_const(b, 3), *c4 = k_const(b, 4), *c8 = k_const(b, 8), *c16 = k_const(b, 16);

    /* The lifter emits a FRESH mul for every access: [base + i*8] twice
     * gives two different mul instructions. */
    cbae_cir_value_t *a1  = k_add(b, base, k_mul(b, i, c8));                     /* base + 8i      */
    cbae_cir_value_t *a2  = k_add(b, k_add(b, base, k_mul(b, i, c8)), c4);       /* base + 8i + 4  */
    cbae_cir_value_t *a3  = k_add(b, base, k_shl(b, i, c3));                     /* base + (i<<3)  */
    cbae_cir_value_t *a4  = k_add(b, base, k_mul(b, j, c8));                     /* base + 8j      */
    cbae_cir_value_t *a5  = k_add(b, base, k_mul(b, i, c16));                    /* base + 16i     */
    cbae_cir_value_t *a6  = k_sub(b, base, k_mul(b, i, c8));                     /* base - 8i      */
    cbae_cir_value_t *a7  = k_add(b, k_mul(b, c8, i), base);                     /* 8i + base      */
    cbae_cir_value_t *a8  = k_add(b, base, k_neg(b, k_mul(b, i, c8)));           /* base + (-(8i)) */
    cbae_cir_value_t *a9  = k_mul(b, k_add(b, base, c4), c8);                    /* 8*base + 32    */
    cbae_cir_value_t *a10 = k_mul(b, k_sub(b, base, c4), c8);                    /* 8*base - 32    */
    cbae_cir_return(b, base, 0);
    an_t an; an_build(&an, x.f);

    expect(&an, "[b+8i] vs [b+8i+4], 4 bytes",        a1, 4, a2, 4, NO);
    expect(&an, "[b+8i] vs [b+8i+4], 8 bytes",        a1, 8, a2, 8, MAY);
    expect(&an, "mul by 8 vs shift by 3",             a1, 8, a3, 8, MUST);
    expect(&an, "different index register",           a1, 8, a4, 8, MAY);
    expect(&an, "different scale",                    a1, 8, a5, 8, MAY);
    expect(&an, "base - 8i vs base + 8i",             a1, 8, a6, 8, MAY);
    expect(&an, "operands of add and mul swapped",    a1, 8, a7, 8, MUST);
    expect(&an, "base - 8i vs base + neg(8i)",        a6, 8, a8, 8, MUST);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, a2, &info));
    assert(info.offset == 4 && info.term_count == 2);
    assert(info.terms[0].value->id < info.terms[1].value->id);       /* sorted by id */
    assert(info.terms[0].value == base && info.terms[0].coeff == 1);
    assert(info.terms[1].value == i    && info.terms[1].coeff == 8);

    /* A constant inside a scaled sub-expression is scaled with it. */
    assert(cbae_alias_decompose(&an.ctx, a9, &info));
    assert(info.offset == 32 && info.term_count == 1 &&
           info.terms[0].value == base && info.terms[0].coeff == 8);
    assert(cbae_alias_decompose(&an.ctx, a10, &info));
    assert(info.offset == -32 && info.term_count == 1 &&
           info.terms[0].value == base && info.terms[0].coeff == 8);
    expect(&an, "(base+4)*8 vs (base-4)*8: 64 bytes apart", a9, 8, a10, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] indexed addressing: fresh muls, shifts, negation and operand order all reduce to one form\n");
}

static void t_term_cap(void) {
    fn_t x; fn_init(&x, "cap");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p1 = cbae_cir_param(b, CBAE_REG_RAX), *p2 = cbae_cir_param(b, CBAE_REG_RBX),
                     *p3 = cbae_cir_param(b, CBAE_REG_RCX), *p4 = cbae_cir_param(b, CBAE_REG_RDX),
                     *p5 = cbae_cir_param(b, CBAE_REG_RSI);
    cbae_cir_value_t *c8 = k_const(b, 8);
    cbae_cir_value_t *s4  = k_add(b, k_add(b, k_add(b, p1, p2), p3), p4);   /* 4 atoms: fits  */
    cbae_cir_value_t *s4b = k_add(b, s4, c8);
    cbae_cir_value_t *s5  = k_add(b, s4, p5);                                /* 5 atoms: opaque */
    cbae_cir_value_t *s5b = k_add(b, s5, c8);
    cbae_cir_return(b, p1, 0);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, s4, &info) && info.term_count == 4 && info.offset == 0);
    assert(cbae_alias_decompose(&an.ctx, s5, &info));
    assert(info.term_count == 1 && info.terms[0].value == s5 && info.terms[0].coeff == 1);

    expect(&an, "4 atoms still compare",                s4, 8, s4b, 8, NO);
    expect(&an, "opaque atom against itself",           s5, 8, s5, 8, MUST);
    expect(&an, "opaque atoms are unrelated to each other", s5, 8, s5b, 8, MAY);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] atom cap: 4 atoms compare, 5 collapse to one opaque atom (sound, unrelated)\n");
}

static void t_wraparound(void) {
    fn_t x; fn_init(&x, "wrap");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *hi    = k_add(b, p, k_const(b, INT64_MAX));            /* p + (2^63-1) */
    cbae_cir_value_t *hi8   = k_add(b, p, k_const(b, INT64_MAX - 7));        /* p + (2^63-8) */
    cbae_cir_value_t *lo    = k_add(b, p, k_const(b, INT64_MIN));            /* p - 2^63 == p + 2^63 */
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    /* mod 2^64: lo - hi = 2^63 - (2^63 - 1) = 1, so the ranges overlap by 7 bytes. */
    expect(&an, "p+(2^63-1) vs p-2^63: one byte apart modulo 2^64", hi, 8, lo, 8, MAY);
    /* lo - hi8 = 2^63 - (2^63 - 8) = 8: back to back. */
    expect(&an, "p+(2^63-8) vs p-2^63: adjacent across the wrap", hi8, 8, lo, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] wrap-around: offsets compare modulo 2^64\n");
}

static void t_limits_and_budget(void) {
    fn_t x; fn_init(&x, "budget");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c8 = k_const(b, 8);

    /* A chain far deeper than the expansion depth cap. */
    cbae_cir_value_t *chain = p;
    for (int k = 0; k < 2000; k++) chain = k_add(b, chain, c8);
    cbae_cir_value_t *chain8 = k_add(b, chain, c8);

    /* x_{k+1} = x_k + x_k: expanding it fully visits 2^20 nodes. */
    cbae_cir_value_t *dbl = p;
    for (int k = 0; k < 20; k++) dbl = k_add(b, dbl, dbl);

    /* The same shape, small enough to expand in full: 2^5 * p. */
    cbae_cir_value_t *d5 = p;
    for (int k = 0; k < 5; k++) d5 = k_add(b, d5, d5);
    cbae_cir_value_t *d5_8 = k_add(b, d5, c8);
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    /* Cut off early the atoms differ, so no relation may be claimed -- but a
     * wrong MUST would be a bug; and a value always matches itself. */
    const cbae_alias_result_t r = cbae_alias_query(&an.ctx, chain, 8, chain8, 8);
    assert(r == MAY || r == NO);
    expect(&an, "deep chain against itself", chain, 8, chain, 8, MUST);
    expect(&an, "doubling DAG against itself (budget cut-off is deterministic)", dbl, 8, dbl, 8, MUST);
    expect(&an, "doubling DAG against its root: different atoms", dbl, 8, p, 8, MAY);

    /* Within the limits the expansion is exact, coefficients multiply. */
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, d5, &info));
    assert(info.offset == 0 && info.term_count == 1 &&
           info.terms[0].value == p && info.terms[0].coeff == 32);
    expect(&an, "32p vs 32p+8, expanded in full", d5, 8, d5_8, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] budget: 2000-deep chain and a 2^20-node DAG terminate and stay sound\n");
}

/* ── Loops ───────────────────────────────────────────────────────────── */

static void t_loop_unstable_vs_stable(void) {
    /*   b0: p = param ; jump b1
     *   b1: i = phi [0, b0] [i2, b2] ; cmp i, N ; branch b2, b3
     *   b2: q1 = p + i ; q2 = q1 + 8 ; pp = p + 8 ; y = load [p] ; y8 = y + 8
     *       i2 = i + 8 ; jump b1
     *   b3: x = load [p] ; x8 = x + 8 ; return                               */
    fn_t x; fn_init(&x, "loop");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c0 = k_const(b, 0), *cN = k_const(b, 100), *c8 = k_const(b, 8);
    cbae_cir_jump(b, b1, 0);

    cbae_cir_value_t *i = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_builder_init(b, x.f, b1);
    cbae_cir_value_t *cmp = cbae_cir_binop(b, CIR_OP_CMP, i, cN, cir_type_i1(), 0);
    cbae_cir_branch(b, cmp, b2, b3, 0);

    cbae_cir_builder_init(b, x.f, b2);
    cbae_cir_value_t *q1 = k_add(b, p, i);
    cbae_cir_value_t *q2 = k_add(b, q1, c8);
    cbae_cir_value_t *pp = k_add(b, p, c8);
    cbae_cir_value_t *y  = k_load(b, p);
    cbae_cir_value_t *y8 = k_add(b, y, c8);
    cbae_cir_value_t *i2 = k_add(b, i, c8);
    cbae_cir_jump(b, b1, 0);

    cbae_cir_builder_init(b, x.f, b3);
    cbae_cir_value_t *xv = k_load(b, p);
    cbae_cir_value_t *x8 = k_add(b, xv, c8);
    cbae_cir_return(b, xv, 0);

    assert(cbae_cir_phi_add_incoming(x.f, i->u.def_insn, c0, x.b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, i->u.def_insn, i2, b2->id) == CBAE_OK);
    an_t an; an_build(&an, x.f);

    assert(!cbae_alias_block_on_cycle(&an.ctx, x.b0->id));
    assert( cbae_alias_block_on_cycle(&an.ctx, b1->id));
    assert( cbae_alias_block_on_cycle(&an.ctx, b2->id));
    assert(!cbae_alias_block_on_cycle(&an.ctx, b3->id));
    assert(!cbae_alias_block_on_cycle(&an.ctx, 99));
    assert(!cbae_alias_block_on_cycle(&an.ctx, an.ctx.block_count));      /* one past the end */

    assert( cbae_alias_value_is_stable(&an.ctx, p));
    assert( cbae_alias_value_is_stable(&an.ctx, c0));
    assert(!cbae_alias_value_is_stable(&an.ctx, i));
    assert(!cbae_alias_value_is_stable(&an.ctx, i2));
    assert(!cbae_alias_value_is_stable(&an.ctx, y));        /* load inside the loop */
    assert( cbae_alias_value_is_stable(&an.ctx, xv));       /* load after the loop  */

    /* i = phi(0, i+8): the incomings 0 and i+8 differ, so i stays an atom. */
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, i, &info) && info.term_count == 1 && info.terms[0].value == i);

    expect(&an, "p+i vs p+i+8: induction variable is unstable", q1, 8, q2, 8, MAY);
    expect(&an, "p+i against itself, still unstable",           q1, 8, q1, 8, MAY);
    expect(&an, "p vs p+8 inside the loop: p is a parameter",   p, 8, pp, 8, NO);
    expect(&an, "[y] vs [y+8], y loaded INSIDE the loop",       y, 8, y8, 8, MAY);
    expect(&an, "[x] vs [x+8], x loaded after the loop",        xv, 8, x8, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] loop: unstable atoms give MAY, parameters and post-loop values stay precise\n");
}

static void t_invariant_phi(void) {
    /*   b0: base0 = param ; jump b1
     *   b1: bh = phi [base0, b0] [bh, b2] ; branch b2, b3
     *   b2: b8 = bh + 8 ; jump b1
     *   b3: return
     * bh never changes, but the SSA constructor leaves it as a phi. */
    fn_t x; fn_init(&x, "invariant");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *base0 = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c8 = k_const(b, 8), *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_jump(b, b1, 0);

    cbae_cir_value_t *bh = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_builder_init(b, x.f, b1);
    cbae_cir_branch(b, cc, b2, b3, 0);
    cbae_cir_builder_init(b, x.f, b2);
    cbae_cir_value_t *b8 = k_add(b, bh, c8);
    cbae_cir_value_t *base8 = k_add(b, base0, c8);
    cbae_cir_jump(b, b1, 0);
    cbae_cir_builder_init(b, x.f, b3);
    cbae_cir_return(b, base0, 0);
    assert(cbae_cir_phi_add_incoming(x.f, bh->u.def_insn, base0, x.b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, bh->u.def_insn, bh, b2->id) == CBAE_OK);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, bh, &info));
    assert(info.offset == 0 && info.term_count == 1 && info.terms[0].value == base0);

    expect(&an, "[bh] vs [bh+8]",        bh, 8, b8, 8, NO);
    expect(&an, "[bh] is [base0]",       bh, 8, base0, 8, MUST);
    expect(&an, "[bh+8] is [base0+8]",   b8, 8, base8, 8, MUST);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] invariant phi: phi [base0, itself] resolves to the parameter\n");
}

static void t_nested_phi_cluster(void) {
    /*   b0: base0 = param ; jump bO
     *   bO: O = phi [base0, b0] [I, bL] ; jump bI
     *   bI: I = phi [O, bO] [I, bI] ; branch bI, bL           (inner loop)
     *   bL: branch bO, bX                                      (outer latch)
     *   bX: return
     * Neither phi is trivial alone: O = phi(base0, I) and I = phi(O, I).
     * I is first seen to equal O; then O's other incoming is O itself. */
    fn_t x; fn_init(&x, "nested");
    cbae_cir_block_t *bO = fn_block(&x, 0x1010), *bI = fn_block(&x, 0x1020),
                     *bL = fn_block(&x, 0x1030), *bX = fn_block(&x, 0x1040);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *base0 = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c8 = k_const(b, 8), *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_jump(b, bO, 0);

    cbae_cir_value_t *O = cbae_cir_phi_create(x.f, bO, T64);
    cbae_cir_builder_init(b, x.f, bO);
    cbae_cir_jump(b, bI, 0);

    cbae_cir_value_t *I = cbae_cir_phi_create(x.f, bI, T64);
    cbae_cir_builder_init(b, x.f, bI);
    cbae_cir_value_t *I8 = k_add(b, I, c8);
    cbae_cir_branch(b, cc, bI, bL, 0);

    cbae_cir_builder_init(b, x.f, bL);
    cbae_cir_branch(b, cc, bO, bX, 0);
    cbae_cir_builder_init(b, x.f, bX);
    cbae_cir_return(b, base0, 0);

    assert(cbae_cir_phi_add_incoming(x.f, O->u.def_insn, base0, x.b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, O->u.def_insn, I, bL->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, I->u.def_insn, O, bO->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, I->u.def_insn, I, bI->id) == CBAE_OK);
    an_t an; an_build(&an, x.f);

    expect(&an, "inner phi is the parameter",  I, 8, base0, 8, MUST);
    expect(&an, "outer phi is the parameter",  O, 8, base0, 8, MUST);
    expect(&an, "[I] vs [I+8]",                I, 8, I8, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] nested loops: a cluster of mutually-referring phis resolves to the parameter\n");
}

static void t_affine_phi(void) {
    /* A push/pop pair inside a loop:
     *   b0: rsp0 = param ; jump b1
     *   b1: rh = phi [rsp0, b0] [rl, b1] ; s = rh - 8 ; store [s] ; l = load [s]
     *       rl = s + 8 ; branch b1, b2
     *   b2: return
     * rl = (rh - 8) + 8 = rh, so the phi is rsp0 even though the incoming
     * value is not literally the phi. */
    fn_t x; fn_init(&x, "affine");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *rsp0 = cbae_cir_param(b, CBAE_REG_RSP);
    cbae_cir_value_t *c8 = k_const(b, 8), *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_jump(b, b1, 0);

    cbae_cir_value_t *rh = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_builder_init(b, x.f, b1);
    cbae_cir_value_t *s = k_sub(b, rh, c8);
    cbae_cir_store(b, s, k_const(b, 7), 0);
    cbae_cir_value_t *l = k_load(b, s); (void)l;
    cbae_cir_value_t *rl = k_add(b, s, c8);
    cbae_cir_value_t *want = k_sub(b, rsp0, c8);
    cbae_cir_branch(b, cc, b1, b2, 0);
    cbae_cir_builder_init(b, x.f, b2);
    cbae_cir_return(b, rsp0, 0);
    assert(cbae_cir_phi_add_incoming(x.f, rh->u.def_insn, rsp0, x.b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, rh->u.def_insn, rl, b1->id) == CBAE_OK);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, rl, &info));
    assert(info.offset == 0 && info.term_count == 1 && info.terms[0].value == rsp0);

    expect(&an, "[rh-8] is [rsp0-8]",   s, 8, want, 8, MUST);
    expect(&an, "[rh-8] vs [rsp0]",     s, 8, rsp0, 8, NO);
    expect(&an, "[rh-8] vs [rl]",       s, 8, rl, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] affine phi: phi [rsp0, (phi-8)+8] resolves to rsp0\n");
}

static void t_unresolvable_phi(void) {
    /*   b0: p1, p2 = params ; branch b1, b2
     *   b1: jump b3 ; b2: jump b3
     *   b3: m = phi [p1, b1] [p2, b2] ; same = phi [p1, b1] [p1, b2] ; ret    */
    fn_t x; fn_init(&x, "unresolvable");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p1 = cbae_cir_param(b, CBAE_REG_RBX), *p2 = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c8 = k_const(b, 8), *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_value_t *p1_8 = k_add(b, p1, c8);
    cbae_cir_branch(b, cc, b1, b2, 0);
    cbae_cir_builder_init(b, x.f, b1); cbae_cir_jump(b, b3, 0);
    cbae_cir_builder_init(b, x.f, b2); cbae_cir_jump(b, b3, 0);

    cbae_cir_value_t *m    = cbae_cir_phi_create(x.f, b3, T64);
    cbae_cir_value_t *same = cbae_cir_phi_create(x.f, b3, T64);
    cbae_cir_value_t *off  = cbae_cir_phi_create(x.f, b3, T64);    /* phi [p1, p1+8]: not one value */
    cbae_cir_builder_init(b, x.f, b3);
    cbae_cir_value_t *m8 = k_add(b, m, c8);
    cbae_cir_return(b, m, 0);
    assert(cbae_cir_phi_add_incoming(x.f, m->u.def_insn, p1, b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, m->u.def_insn, p2, b2->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, same->u.def_insn, p1, b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, same->u.def_insn, p1, b2->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, off->u.def_insn, p1, b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, off->u.def_insn, p1_8, b2->id) == CBAE_OK);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, m, &info) && info.term_count == 1 && info.terms[0].value == m);
    assert(cbae_alias_decompose(&an.ctx, off, &info) && is_atom(&info, off));

    expect(&an, "[m] vs [m+8]: merge of two pointers, executes once", m, 8, m8, 8, NO);
    expect(&an, "[m] vs [p1]: could be either",                       m, 8, p1, 8, MAY);
    expect(&an, "phi [p1, p1] is p1",                                 same, 8, p1, 8, MUST);
    expect(&an, "phi [p1, p1+8] is neither p1 nor p1+8",              off, 8, p1, 8, MAY);
    expect(&an, "phi [p1, p1+8] vs p1+8",                             off, 8, p1_8, 8, MAY);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] diamond phis: equal incomings resolve, different incomings stay one stable atom\n");
}

static void t_phi_pass_cap(void) {
    /* A ladder of phis, each resolvable only AFTER the next one, which the
     * ascending scan reaches later:  A_i = phi [p, d_i] [A_{i+1}, c_{i+1}],
     * A_N = phi [p, d_N]. Resolving A_{N-k} takes k+1 passes, so without a cap
     * a hostile function costs quadratic time. Within the cap the analysis is
     * exact; beyond it the phi stays an atom, which is sound.
     *
     *   b0 -> d_N ;  d_i: branch c_i, d_{i-1}  (d_1: jump c_1)
     *   c_i: A_i = phi ... ; jump c_{i-1}      (c_1: return)                  */
    enum { N = 100 };
    _Static_assert(N > CBAE_ALIAS_RESOLVE_PASSES + 1, "the ladder must be longer than the pass cap");
    const int P = (int)CBAE_ALIAS_RESOLVE_PASSES;
    fn_t x; fn_init(&x, "ladder");
    cbae_cir_block_t *c[N + 2], *d[N + 2];
    for (int i = 1; i <= N; i++) c[i] = fn_block(&x, 0x20000 + 0x10 * (cbae_addr_t)i);
    for (int i = 1; i <= N; i++) d[i] = fn_block(&x, 0x80000 + 0x10 * (cbae_addr_t)i);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p  = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_jump(b, d[N], 0);

    cbae_cir_value_t *A[N + 2];
    for (int i = 1; i <= N; i++) { A[i] = cbae_cir_phi_create(x.f, c[i], T64); assert(A[i]); }
    for (int i = N; i >= 1; i--) {
        cbae_cir_builder_init(b, x.f, d[i]);
        if (i > 1) cbae_cir_branch(b, cc, c[i], d[i - 1], 0);
        else       cbae_cir_jump(b, c[1], 0);
    }
    for (int i = N; i >= 1; i--) {
        cbae_cir_builder_init(b, x.f, c[i]);
        if (i > 1) cbae_cir_jump(b, c[i - 1], 0);
        else       cbae_cir_return(b, p, 0);
    }
    for (int i = 1; i <= N; i++) {
        assert(cbae_cir_phi_add_incoming(x.f, A[i]->u.def_insn, p, d[i]->id) == CBAE_OK);
        if (i < N)
            assert(cbae_cir_phi_add_incoming(x.f, A[i]->u.def_insn, A[i + 1], c[i + 1]->id) == CBAE_OK);
    }
    an_t an; an_build(&an, x.f);
    assert(an.ctx.phi_count == N);

    /* A_{N-k} resolves in pass k+1: the last one inside the cap is k = P-1. */
    for (int k = 0; k < P; k++) {
        char what[64];
        snprintf(what, sizeof what, "A_%d resolves to p (pass %d)", N - k, k + 1);
        expect(&an, what, A[N - k], 8, p, 8, MUST);
    }
    expect(&an, "first phi past the cap stays an atom", A[N - P], 8, p, 8, MAY);
    expect(&an, "A_1 would need 100 passes: also an atom", A[1], 8, p, 8, MAY);
    expect(&an, "an unresolved phi is still a usable atom", A[1], 8, A[1], 8, MUST);
    /* A_{N-P} equals A_{N-P+1} (hence p) on paper, but the analysis stopped. */
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, A[N - P], &info) && info.term_count == 1 &&
           info.terms[0].value == A[N - P]);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] phi ladder: resolution is exact within the pass cap and sound beyond it\n");
}

static void t_phi_chain_depth(void) {
    /* A long chain of phis, each equal to the next:
     *   A_i = phi [A_{i+1}, c_{i+1}] [A_{i+1}, e_{i+1}],   A_M = phi [p, b0].
     * All resolve in the first pass (equal incomings). Expanding A_i walks the
     * chain; the depth limit applies to phis too, so it stops at the phi that
     * lies deeper than EXPAND_DEPTH, and that phi becomes the atom.
     *
     *   b0 -> c_M ;  c_i: branch c_{i-1}, e_i ;  e_i: jump c_{i-1} ;  c_1: return */
    enum { M = CBAE_ALIAS_EXPAND_DEPTH + 40, D = CBAE_ALIAS_EXPAND_DEPTH };
    fn_t x; fn_init_sized(&x, "phi_chain", 16u * 1024 * 1024);
    cbae_cir_block_t *c[M + 2], *e[M + 2];
    for (int i = 1; i <= M; i++) c[i] = fn_block(&x, 0x20000 + 0x10 * (cbae_addr_t)i);
    for (int i = 2; i <= M; i++) e[i] = fn_block(&x, 0x80000 + 0x10 * (cbae_addr_t)i);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p  = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_jump(b, c[M], 0);

    cbae_cir_value_t *A[M + 2];
    for (int i = 1; i <= M; i++) { A[i] = cbae_cir_phi_create(x.f, c[i], T64); assert(A[i]); }
    for (int i = M; i >= 1; i--) {
        cbae_cir_builder_init(b, x.f, c[i]);
        if (i > 1) cbae_cir_branch(b, cc, c[i - 1], e[i], 0);
        else       cbae_cir_return(b, p, 0);
    }
    for (int i = M; i >= 2; i--) {
        cbae_cir_builder_init(b, x.f, e[i]);
        cbae_cir_jump(b, c[i - 1], 0);
    }
    assert(cbae_cir_phi_add_incoming(x.f, A[M]->u.def_insn, p, x.b0->id) == CBAE_OK);
    for (int i = 1; i < M; i++) {
        assert(cbae_cir_phi_add_incoming(x.f, A[i]->u.def_insn, A[i + 1], c[i + 1]->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, A[i]->u.def_insn, A[i + 1], e[i + 1]->id) == CBAE_OK);
    }
    an_t an; an_build(&an, x.f);
    assert(an.ctx.phi_count == M);

    /* From A_s the last phi A_M sits at depth M - s: reachable iff M - s <= DEPTH. */
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, A[M - D], &info) && is_atom(&info, p));
    assert(cbae_alias_decompose(&an.ctx, A[M - D - 1], &info) && is_atom(&info, A[M]));
    expect(&an, "A_{M-DEPTH} is p", A[M - D], 8, p, 8, MUST);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] phi chain: expansion through %d resolved phis stops at the depth limit\n", (int)M);
}

static void t_other_register(void) {
    fn_t x; fn_init(&x, "other");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *o  = cbae_cir_param(b, CBAE_REG_OTHER);
    cbae_cir_value_t *c8 = k_const(b, 8);
    cbae_cir_value_t *o8 = k_add(b, o, c8);
    cbae_cir_value_t *p  = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_return(b, o, 0);
    an_t an; an_build(&an, x.f);

    assert(!cbae_alias_value_is_stable(&an.ctx, o));
    assert( cbae_alias_value_is_stable(&an.ctx, p));
    expect(&an, "[other] vs [other+8]", o, 8, o8, 8, MAY);
    expect(&an, "[other] vs itself",    o, 8, o, 8, MAY);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] the lifter's 'other' register is never a stable value\n");
}

/* ── Limits, cancellation, narrow types, odd opcodes ─────────────────── */

static void t_expansion_limits(void) {
    /* The work limits are part of the contract, so they are pinned exactly.
     *
     * DEPTH. chain[k] = p + k as k nested ADDs. The ADD at depth d is looked
     * through iff d <= EXPAND_DEPTH, so chain[DEPTH+1] reaches p and
     * chain[DEPTH+2] stops one ADD short of it (that ADD becomes the atom).
     *
     * BUDGET. dag[1] = 1+1, dag[k] = dag[k-1] + dag[k-1]; expanding dag[k] in
     * full visits 2^k - 1 instructions. dag[12] is 4095 of them, r1 adds the
     * 4096th (exactly the budget), r2 the 4097th, which is cut off. */
    _Static_assert(CBAE_ALIAS_EXPAND_BUDGET == 4096u, "the DAG is built for a budget of 4096");
    enum { K1 = CBAE_ALIAS_EXPAND_DEPTH + 1, K2 = CBAE_ALIAS_EXPAND_DEPTH + 2 };
    fn_t x; fn_init(&x, "limits");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c0 = k_const(b, 0), *c1 = k_const(b, 1);

    cbae_cir_value_t *chain[K2 + 1];
    chain[0] = p;
    for (int k = 1; k <= K2; k++) chain[k] = k_add(b, chain[k - 1], c1);

    cbae_cir_value_t *dag[13];
    dag[0] = NULL;
    dag[1] = k_add(b, c1, c1);
    for (int k = 2; k <= 12; k++) dag[k] = k_add(b, dag[k - 1], dag[k - 1]);
    cbae_cir_value_t *r1 = k_add(b, dag[12], c0);
    cbae_cir_value_t *r2 = k_add(b, r1, c0);
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, chain[K1], &info));
    assert(info.offset == K1 && info.term_count == 1 &&
           info.terms[0].value == p && info.terms[0].coeff == 1);
    assert(cbae_alias_decompose(&an.ctx, chain[K2], &info));
    assert(info.offset == K1 && info.term_count == 1 &&
           info.terms[0].value == chain[1] && info.terms[0].coeff == 1);

    assert(cbae_alias_decompose(&an.ctx, r1, &info));
    assert(info.offset == 4096 && info.term_count == 0);
    assert(cbae_alias_decompose(&an.ctx, r2, &info));
    assert(info.offset == 4094 && info.term_count == 1 &&
           info.terms[0].value == dag[1] && info.terms[0].coeff == 1);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] limits: depth %u and budget %u hold exactly, one past each gives an atom\n",
           (unsigned)CBAE_ALIAS_EXPAND_DEPTH, (unsigned)CBAE_ALIAS_EXPAND_BUDGET);
}

static void t_cancellation(void) {
    fn_t x; fn_init(&x, "cancel");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c2 = k_const(b, 2), *c3 = k_const(b, 3), *c8 = k_const(b, 8);
    cbae_cir_value_t *zero   = k_sub(b, q, q);                                         /* 0, absolute  */
    cbae_cir_value_t *just_p = k_sub(b, k_add(b, p, q), q);                            /* p            */
    cbae_cir_value_t *pn     = k_add(b, p, k_neg(b, p));                               /* 0            */
    cbae_cir_value_t *mix    = k_sub(b, k_sub(b, k_mul(b, p, c3), k_mul(b, p, c2)), p);/* 3p-2p-p = 0  */
    cbae_cir_value_t *z8     = k_add(b, zero, c8);                                     /* absolute 8   */
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, zero, &info) && info.term_count == 0 && info.offset == 0);
    assert(cbae_alias_decompose(&an.ctx, pn,   &info) && info.term_count == 0 && info.offset == 0);
    assert(cbae_alias_decompose(&an.ctx, mix,  &info) && info.term_count == 0 && info.offset == 0);
    assert(cbae_alias_decompose(&an.ctx, just_p, &info) && is_atom(&info, p));
    expect(&an, "(p+q)-q is p",        just_p, 8, p, 8, MUST);
    expect(&an, "q-q+8 vs q-q",        z8, 8, zero, 8, NO);
    expect(&an, "p+(-p) is absolute 0", pn, 8, zero, 8, MUST);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] cancellation: terms whose coefficients cancel leave the form\n");
}

static void t_work_cap_is_sticky(void) {
    /* Nine atoms exceed the working capacity (8). The excess must not simply be
     * dropped: subtracting four atoms afterwards would then leave a form that
     * looks like p4+p5+p6+p7 while the real value also contains p8. */
    fn_t x; fn_init(&x, "sticky");
    cbae_cir_builder_t *b = &x.bld;
    static const cbae_reg_t regs[9] = { CBAE_REG_RAX, CBAE_REG_RBX, CBAE_REG_RCX, CBAE_REG_RDX,
                                        CBAE_REG_RSI, CBAE_REG_RDI, CBAE_REG_R8,  CBAE_REG_R9,
                                        CBAE_REG_R10 };
    cbae_cir_value_t *p[9];
    for (int i = 0; i < 9; i++) p[i] = cbae_cir_param(b, regs[i]);
    cbae_cir_value_t *s = p[0];
    for (int i = 1; i < 9; i++) s = k_add(b, s, p[i]);               /* p0 + ... + p8             */
    cbae_cir_value_t *d = s;
    for (int i = 0; i < 4; i++) d = k_sub(b, d, p[i]);               /* p4 + p5 + p6 + p7 + p8    */
    cbae_cir_value_t *t = k_add(b, k_add(b, k_add(b, p[4], p[5]), p[6]), p[7]);   /* p4+p5+p6+p7  */
    cbae_cir_return(b, p[0], 0);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, d, &info) && is_atom(&info, d));
    expect(&an, "p4..p8 is not p4..p7", d, 8, t, 8, MAY);

    /* Eight atoms still fit: the same subtraction on p0..p7 is exact. */
    cbae_alias_ctx_destroy(&an.ctx);
    cbae_use_def_destroy(&an.ud);
    fn_done(&x);

    fn_init(&x, "eight");
    b = &x.bld;
    for (int i = 0; i < 8; i++) p[i] = cbae_cir_param(b, regs[i]);
    s = p[0];
    for (int i = 1; i < 8; i++) s = k_add(b, s, p[i]);               /* p0 + ... + p7             */
    d = s;
    for (int i = 0; i < 4; i++) d = k_sub(b, d, p[i]);               /* p4 + p5 + p6 + p7         */
    t = k_add(b, k_add(b, k_add(b, p[4], p[5]), p[6]), p[7]);
    cbae_cir_return(b, p[0], 0);
    an_build(&an, x.f);
    assert(cbae_alias_decompose(&an.ctx, d, &info) && info.term_count == 4 && info.offset == 0);
    expect(&an, "p0..p7 minus p0..p3 is exactly p4..p7", d, 8, t, 8, MUST);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] working capacity: 8 atoms fit; a 9th is never dropped, even if later terms cancel\n");
}

static void t_narrow_arithmetic(void) {
    /* A 32-bit add wraps at 32 bits, not at 2^64: it is an atom, never a form. */
    fn_t x; fn_init(&x, "narrow_add");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p   = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *a32 = cbae_cir_load(b, p, cir_type_i(32), 0);
    cbae_cir_value_t *n4  = cbae_cir_const(b, cir_type_i(32), 4);
    cbae_cir_value_t *s1  = cbae_cir_binop(b, CIR_OP_ADD, a32, n4, cir_type_i(32), 0);
    cbae_cir_value_t *s2  = cbae_cir_binop(b, CIR_OP_ADD, s1,  n4, cir_type_i(32), 0);
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, s1, &info) && is_atom(&info, s1));
    assert(cbae_alias_decompose(&an.ctx, s2, &info) && is_atom(&info, s2));
    expect(&an, "i32 add chain: separate atoms", s1, 4, s2, 4, MAY);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] narrow arithmetic: i32 adds are atoms, not 64-bit forms\n");
}

static void t_copy_and_shifts(void) {
    fn_t x; fn_init(&x, "copy_shift");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *i = cbae_cir_param(b, CBAE_REG_RCX),
                     *j = cbae_cir_param(b, CBAE_REG_RDX);
    cbae_cir_value_t *cp  = k_copy(b, p);
    cbae_cir_value_t *cp2 = k_add(b, k_copy(b, k_copy(b, p)), k_const(b, 8));
    cbae_cir_value_t *s0  = k_shl(b, i, k_const(b, 0));
    cbae_cir_value_t *s63 = k_shl(b, i, k_const(b, 63));
    cbae_cir_value_t *s64 = k_shl(b, i, k_const(b, 64));       /* count out of range: refused */
    cbae_cir_value_t *sm1 = k_shl(b, i, k_const(b, -1));       /* negative count: refused     */
    cbae_cir_value_t *sv  = k_shl(b, i, j);                    /* variable count: an atom     */
    cbae_cir_value_t *mv  = k_mul(b, i, j);                    /* variable product: an atom   */
    cbae_cir_value_t *mc  = k_mul(b, k_const(b, 3), k_const(b, 5));
    cbae_cir_value_t *mz  = k_mul(b, i, k_const(b, 0));                              /* i*0       = 0 */
    cbae_cir_value_t *sz  = k_shl(b, k_shl(b, i, k_const(b, 32)), k_const(b, 32));   /* i*2^64    = 0 */
    cbae_cir_return(b, p, 0);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, mz, &info) && info.term_count == 0 && info.offset == 0);
    assert(cbae_alias_decompose(&an.ctx, sz, &info) && info.term_count == 0 && info.offset == 0);
    assert(cbae_alias_decompose(&an.ctx, cp, &info) && is_atom(&info, p));
    assert(cbae_alias_decompose(&an.ctx, cp2, &info) && info.offset == 8 &&
           info.term_count == 1 && info.terms[0].value == p && info.terms[0].coeff == 1);
    assert(cbae_alias_decompose(&an.ctx, s0, &info) && is_atom(&info, i));
    assert(cbae_alias_decompose(&an.ctx, s63, &info) && info.offset == 0 && info.term_count == 1 &&
           info.terms[0].value == i && info.terms[0].coeff == INT64_MIN);
    assert(cbae_alias_decompose(&an.ctx, s64, &info) && is_atom(&info, s64));
    assert(cbae_alias_decompose(&an.ctx, sm1, &info) && is_atom(&info, sm1));
    assert(cbae_alias_decompose(&an.ctx, sv,  &info) && is_atom(&info, sv));
    assert(cbae_alias_decompose(&an.ctx, mv,  &info) && is_atom(&info, mv));
    assert(cbae_alias_decompose(&an.ctx, mc,  &info) && info.term_count == 0 && info.offset == 15);
    expect(&an, "copy of a copy of p, plus 8, vs p", cp2, 8, p, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] COPY looks through; SHL expands for counts 0..63 only; variable shift/mul are atoms\n");
}

static void t_scaled_phi(void) {
    /*   b0: q, r = params ; q8r = (q + r) + 8 ; jump b1
     *   b1: h = phi [q8r, b0] [h, b2] ; branch b2, b3
     *   b2: jump b1
     *   b3: a = h*4 + 3 ; n = -h ; return
     * h is q + r + 8 for the whole run, so a = 4q + 4r + 35 and n = -q - r - 8:
     * a resolved phi's offset and coefficients are scaled by the use. */
    fn_t x; fn_init(&x, "scaled");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *q = cbae_cir_param(b, CBAE_REG_RBX), *r = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c3 = k_const(b, 3), *c4 = k_const(b, 4), *c8 = k_const(b, 8);
    cbae_cir_value_t *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_value_t *q8r = k_add(b, k_add(b, q, r), c8);
    cbae_cir_jump(b, b1, 0);

    cbae_cir_value_t *h = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_builder_init(b, x.f, b1);
    cbae_cir_branch(b, cc, b2, b3, 0);
    cbae_cir_builder_init(b, x.f, b2);
    cbae_cir_jump(b, b1, 0);
    cbae_cir_builder_init(b, x.f, b3);
    cbae_cir_value_t *a    = k_add(b, k_mul(b, h, c4), c3);
    cbae_cir_value_t *n    = k_neg(b, h);
    cbae_cir_value_t *want = k_add(b, k_add(b, k_mul(b, q, c4), k_mul(b, r, c4)), k_const(b, 35));
    cbae_cir_return(b, a, 0);
    assert(cbae_cir_phi_add_incoming(x.f, h->u.def_insn, q8r, x.b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, h->u.def_insn, h, b2->id) == CBAE_OK);
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, a, &info));
    assert(info.offset == 35 && info.term_count == 2);
    assert(info.terms[0].value == q && info.terms[0].coeff == 4);
    assert(info.terms[1].value == r && info.terms[1].coeff == 4);
    assert(cbae_alias_decompose(&an.ctx, n, &info));
    assert(info.offset == -8 && info.term_count == 2);
    assert(info.terms[0].value == q && info.terms[0].coeff == -1);
    assert(info.terms[1].value == r && info.terms[1].coeff == -1);
    expect(&an, "[4h+3] is [4q+4r+35]", a, 8, want, 8, MUST);
    expect(&an, "[h] is [q+r+8]",       h, 8, q8r, 8, MUST);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] resolved phi with offset and two terms is scaled correctly by its uses\n");
}

static void t_phi_recurrences(void) {
    /*   b0: p, q = params ; jump b1
     *   b1: u = phi [p, b0] [u*2, b2] ; v = phi [p, b0] [v+q, b2] ; w = phi [p, b0] [w+8, b2]
     *   b2: jump b1 (after computing the three recurrences) ; b1 also branches to b3: return
     * Each phi has one incoming (p) that is not itself and one recurrence that is NOT a
     * plain copy of the phi, so none may be resolved to p. The phis are created first so
     * that v has a lower id than q: a check that looked only at the first term of v+q
     * would see "v" alone and wrongly call it a copy. */
    fn_t x; fn_init(&x, "recurrences");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *u = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_value_t *v = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_value_t *w = cbae_cir_phi_create(x.f, b1, T64);
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c2 = k_const(b, 2), *c8 = k_const(b, 8);
    cbae_cir_value_t *cc = cbae_cir_const(b, cir_type_i1(), 1);
    cbae_cir_jump(b, b1, 0);
    cbae_cir_builder_init(b, x.f, b1);
    cbae_cir_branch(b, cc, b2, b3, 0);
    cbae_cir_builder_init(b, x.f, b2);
    cbae_cir_value_t *u2 = k_mul(b, u, c2), *v2 = k_add(b, v, q), *w2 = k_add(b, w, c8);
    cbae_cir_jump(b, b1, 0);
    cbae_cir_builder_init(b, x.f, b3);
    cbae_cir_return(b, p, 0);
    assert(v->id < q->id);
    cbae_cir_value_t *phis[3] = { u, v, w }, *rec[3] = { u2, v2, w2 };
    for (int k = 0; k < 3; k++) {
        assert(cbae_cir_phi_add_incoming(x.f, phis[k]->u.def_insn, p, x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, phis[k]->u.def_insn, rec[k], b2->id) == CBAE_OK);
    }
    an_t an; an_build(&an, x.f);

    cbae_addr_info_t info;
    for (int k = 0; k < 3; k++) {
        assert(cbae_alias_decompose(&an.ctx, phis[k], &info) && is_atom(&info, phis[k]));
        expect(&an, "recurrence phi vs p", phis[k], 8, p, 8, MAY);
    }

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] recurrences u*2, v+q, w+8 are not copies: their phis stay atoms\n");
}

static void t_phi_guards(void) {
    /* Not valid SSA, on purpose (the checked builder path is bypassed): the analysis
     * must still behave. (1) A phi whose every incoming is itself is equal to nothing;
     * it must stay an atom, not collapse to the empty form 0. (2) A phi must never be
     * recorded as equal to a form that mentions the phi itself. */
    {
        /*   b0: jump b1 ; b1: h = phi [h, b0] [h, b1] ; branch b1, b2 ; b2: return h */
        fn_t x; fn_init(&x, "all_self");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *h  = cbae_cir_phi_create(x.f, b1, T64);
        cbae_cir_value_t *cc = cbae_cir_const(b, cir_type_i1(), 1);
        cbae_cir_jump(b, b1, 0);
        cbae_cir_builder_init(b, x.f, b1);
        cbae_cir_branch(b, cc, b1, b2, 0);
        cbae_cir_builder_init(b, x.f, b2);
        cbae_cir_return(b, h, 0);
        assert(cbae_cir_phi_add_incoming(x.f, h->u.def_insn, h, x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, h->u.def_insn, h, b1->id) == CBAE_OK);
        an_t an; an_build_unchecked(&an, x.f);

        cbae_addr_info_t info;
        assert(cbae_alias_decompose(&an.ctx, h, &info) && is_atom(&info, h));
        an_free(&an);
        fn_done(&x);
    }
    {
        /*   b0: jump b1 ; b1: g = phi [xv, b0] [xv, b1] ; xv = g + 8 ; branch b1, b2 ; b2: return
         * xv is used on the b0 edge before it exists (invalid), and both incomings have the
         * form g+8, which mentions g. */
        fn_t x; fn_init(&x, "mentions_self");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *g  = cbae_cir_phi_create(x.f, b1, T64);
        cbae_cir_value_t *c8 = k_const(b, 8), *cc = cbae_cir_const(b, cir_type_i1(), 1);
        cbae_cir_jump(b, b1, 0);
        cbae_cir_builder_init(b, x.f, b1);
        cbae_cir_value_t *xv = k_add(b, g, c8);
        cbae_cir_branch(b, cc, b1, b2, 0);
        cbae_cir_builder_init(b, x.f, b2);
        cbae_cir_return(b, g, 0);
        assert(cbae_cir_phi_add_incoming(x.f, g->u.def_insn, xv, x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, g->u.def_insn, xv, b1->id) == CBAE_OK);
        an_t an; an_build_unchecked(&an, x.f);

        cbae_addr_info_t info;
        assert(cbae_alias_decompose(&an.ctx, g, &info) && is_atom(&info, g));
        assert(cbae_alias_decompose(&an.ctx, xv, &info) && info.offset == 8 &&
               info.term_count == 1 && info.terms[0].value == g && info.terms[0].coeff == 1);
        an_free(&an);
        fn_done(&x);
    }
    printf("  [PASS] phi guards: all-self and self-mentioning phis are never resolved\n");
}

static void t_malformed_operand(void) {
    fn_t x; fn_init(&x, "malformed");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *s = k_add(b, p, k_const(b, 8));
    cbae_cir_value_t *t = k_add(b, s, k_const(b, 8));
    cbae_cir_value_t *u = k_add(b, p, k_const(b, 8));
    cbae_cir_return(b, p, 0);
    s->u.def_insn->operands[0] = NULL;                       /* corrupt: a missing first operand */
    u->u.def_insn->operands[1] = NULL;                       /* corrupt: a missing last operand  */
    an_t an; an_build_unchecked(&an, x.f);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, u, &info) && is_atom(&info, u));
    assert(cbae_alias_decompose(&an.ctx, s, &info) && is_atom(&info, s));   /* opaque, not +8 */
    assert(cbae_alias_decompose(&an.ctx, t, &info) && info.offset == 8 &&
           info.term_count == 1 && info.terms[0].value == s);
    expect(&an, "[s] vs [s+8], s opaque but stable", s, 8, t, 8, NO);

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] a missing operand makes the value an opaque atom, no crash\n");
}

/* ── API edges ───────────────────────────────────────────────────────── */

static void t_api_edges(void) {
    cbae_alias_ctx_t c;
    assert(cbae_alias_ctx_build(NULL, &c) == CBAE_ERR_INVALID);
    cbae_alias_ctx_destroy(NULL);

    /* No blocks at all. */
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    cbae_cir_function_t *empty;
    assert(cbae_cir_function_create(&arena, 0x100, "empty", &empty) == CBAE_OK);
    cbae_use_def_t ud; assert(cbae_use_def_build(empty, &ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&ud, &c) == CBAE_OK);
    assert(c.block_count == 0 && c.phi_count == 0);
    assert(!cbae_alias_block_on_cycle(&c, 0));
    cbae_alias_ctx_destroy(&c);
    cbae_alias_ctx_destroy(&c);                  /* second destroy is a no-op */
    cbae_use_def_destroy(&ud);
    cbae_cir_function_destroy(empty);
    cbae_arena_destroy(&arena);

    /* Queries and accessors with absent or foreign arguments. */
    fn_t x; fn_init(&x, "edges");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c8 = k_const(b, 8);
    cbae_cir_value_t *ld = cbae_cir_load(b, p, cir_type_i(8), 0);
    cbae_cir_value_t *v32 = cbae_cir_const(b, cir_type_i(32), 5);
    cbae_cir_store(b, p, v32, 0);
    cbae_cir_value_t *ld1 = cbae_cir_load(b, p, cir_type_i1(), 0);
    cbae_cir_value_t *sum = k_add(b, p, c8);
    cbae_cir_return(b, ld, 0);
    an_t an; an_build(&an, x.f);

    assert(cbae_alias_query(NULL, p, 8, p, 8) == MAY);
    assert(!cbae_alias_decompose(NULL, p, &(cbae_addr_info_t){0}));
    assert(!cbae_alias_decompose(&an.ctx, NULL, &(cbae_addr_info_t){0}));
    assert(!cbae_alias_decompose(&an.ctx, p, NULL));
    assert(!cbae_alias_value_is_stable(NULL, p));
    assert(!cbae_alias_value_is_stable(&an.ctx, NULL));
    assert( cbae_alias_query_info(NULL, NULL, 8, NULL, 8) == MAY);

    /* A value from another function is not stable and gives no precision. */
    fn_t other; fn_init(&other, "other_fn");
    cbae_cir_value_t *foreign = cbae_cir_param(&other.bld, CBAE_REG_RBX);   /* id 0, like p */
    assert(foreign->id == p->id);
    assert(!cbae_alias_value_is_stable(&an.ctx, foreign));
    expect(&an, "foreign value", foreign, 8, foreign, 8, MAY);
    /* ... including one whose id is exactly one past this function's last value. */
    cbae_cir_value_t *edge = foreign;
    while (edge->id < an.ud.value_count) edge = cbae_cir_const(&other.bld, T64, 0);
    assert(edge->id == an.ud.value_count);
    assert(!cbae_alias_value_is_stable(&an.ctx, edge));
    fn_done(&other);

    /* Access extraction: size comes from the loaded type / stored value. */
    const cbae_cir_value_t *addr = NULL; uint32_t size = 99;
    cbae_cir_instruction_t *l8 = ld->u.def_insn, *l1 = ld1->u.def_insn;
    assert(cbae_alias_mem_access(l8, &addr, &size) && addr == p && size == 1);
    assert(cbae_alias_mem_access(l1, &addr, &size) && addr == p && size == 1);
    cbae_cir_instruction_t *st = lh_nth_insn(x.f, CIR_OP_STORE, 0);
    assert(st && cbae_alias_mem_access(st, &addr, &size) && addr == p && size == 4);
    assert(!cbae_alias_mem_access(sum->u.def_insn, &addr, &size));
    assert(!cbae_alias_mem_access(NULL, &addr, &size));

    an_free(&an);
    fn_done(&x);
    printf("  [PASS] API edges: null/foreign arguments, empty function, access sizes from types\n");
}

/* ── Lifted machine code ─────────────────────────────────────────────── */

static cbae_alias_result_t lifted_query(const an_t *an, const lifted_t *L,
                                        cbae_cir_opcode_t opa, uint32_t na,
                                        cbae_cir_opcode_t opb, uint32_t nb) {
    const cbae_cir_instruction_t *ia = lh_nth_insn(L->func, opa, na);
    const cbae_cir_instruction_t *ib = lh_nth_insn(L->func, opb, nb);
    assert(ia && ib);
    const cbae_cir_value_t *aa, *ab; uint32_t sa, sb;
    assert(cbae_alias_mem_access(ia, &aa, &sa) && cbae_alias_mem_access(ib, &ab, &sb));
    const cbae_alias_result_t r1 = cbae_alias_query(&an->ctx, aa, sa, ab, sb);
    const cbae_alias_result_t r2 = cbae_alias_query(&an->ctx, ab, sb, aa, sa);
    assert(r1 == r2);
    return r1;
}

static void t_lifted_loop_invariant_base(void) {
    /*   0x4000: 48 8B 03        mov rax, [rbx]
     *   0x4003: 48 89 43 08     mov [rbx+8], rax
     *   0x4007: 48 83 C1 01     add rcx, 1
     *   0x400B: 48 83 F9 0A     cmp rcx, 10
     *   0x400F: 7C EF           jl 0x4000            (target 0x4011 - 17)
     *   0x4011: C3              ret
     * rbx is never written, but the loop header is also the function entry,
     * so the lifter adds a synthetic entry block and the SSA constructor
     * gives rbx a phi at the header: phi [param rbx, entry] [phi, loop].
     * The load of [rbx] and the store to [rbx+8] are in a loop, yet they
     * are provably disjoint -- but only because the phi is resolved. */
    static const uint8_t code[] = {
        0x48,0x8B,0x03, 0x48,0x89,0x43,0x08, 0x48,0x83,0xC1,0x01,
        0x48,0x83,0xF9,0x0A, 0x7C,0xEF, 0xC3 };
    lifted_t L; lift_x86(&L, code, sizeof code, 0x4000, "invariant_loop");
    an_t an;
    assert(cbae_use_def_build(L.func, &an.ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&an.ud, &an.ctx) == CBAE_OK);

    const cbae_cir_instruction_t *ld = lh_nth_insn(L.func, CIR_OP_LOAD, 0);
    const cbae_cir_value_t *addr; uint32_t size;
    assert(ld && cbae_alias_mem_access(ld, &addr, &size) && size == 8);
    assert(addr->kind == CIR_VAL_INSN_RESULT && addr->u.def_insn->opcode == CIR_OP_PHI);

    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, addr, &info));
    assert(info.offset == 0 && info.term_count == 1);
    assert(info.terms[0].value->kind == CIR_VAL_PARAM &&
           info.terms[0].value->u.param_reg == CBAE_REG_RBX);

    assert(lifted_query(&an, &L, CIR_OP_LOAD, 0, CIR_OP_STORE, 0) == NO);
    assert(lifted_query(&an, &L, CIR_OP_LOAD, 0, CIR_OP_LOAD, 0) == MUST);

    an_free(&an);
    lifted_destroy(&L);
    printf("  [PASS] lifted loop: [rbx] vs [rbx+8] is NO, through the loop-header phi\n");
}

static void t_lifted_stack_frame(void) {
    /*   0x5000: 48 83 EC 28        sub rsp, 0x28
     *   0x5004: 48 89 4C 24 20     mov [rsp+0x20], rcx
     *   0x5009: 48 89 54 24 18     mov [rsp+0x18], rdx
     *   0x500E: 48 8B 44 24 20     mov rax, [rsp+0x20]
     *   0x5013: 48 83 C4 28        add rsp, 0x28
     *   0x5017: C3                 ret
     * Offsets from the entry rsp: store1 -8, store2 -0x10, load -8. */
    static const uint8_t code[] = {
        0x48,0x83,0xEC,0x28, 0x48,0x89,0x4C,0x24,0x20, 0x48,0x89,0x54,0x24,0x18,
        0x48,0x8B,0x44,0x24,0x20, 0x48,0x83,0xC4,0x28, 0xC3 };
    lifted_t L; lift_x86(&L, code, sizeof code, 0x5000, "frame");
    an_t an;
    assert(cbae_use_def_build(L.func, &an.ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&an.ud, &an.ctx) == CBAE_OK);

    assert(lifted_query(&an, &L, CIR_OP_STORE, 0, CIR_OP_STORE, 1) == NO);
    assert(lifted_query(&an, &L, CIR_OP_STORE, 0, CIR_OP_LOAD,  0) == MUST);
    assert(lifted_query(&an, &L, CIR_OP_STORE, 1, CIR_OP_LOAD,  0) == NO);

    const cbae_cir_instruction_t *st0 = lh_nth_insn(L.func, CIR_OP_STORE, 0);
    const cbae_cir_value_t *addr; uint32_t size;
    assert(cbae_alias_mem_access(st0, &addr, &size));
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, addr, &info));
    assert(info.offset == -8 && info.term_count == 1 &&
           info.terms[0].value->kind == CIR_VAL_PARAM &&
           info.terms[0].value->u.param_reg == CBAE_REG_RSP);

    an_free(&an);
    lifted_destroy(&L);
    printf("  [PASS] lifted frame: [rsp+0x20] after sub rsp,0x28 is entry-rsp-8, distinct from [rsp+0x18]\n");
}

static void t_lifted_indexed(void) {
    /*   0x6000: 48 8B 04 CB        mov rax, [rbx+rcx*8]
     *   0x6004: 48 8B 54 CB 08     mov rdx, [rbx+rcx*8+8]
     *   0x6009: 48 8B 34 CB        mov rsi, [rbx+rcx*8]
     *   0x600D: C3                 ret
     * Three loads, three different mul instructions. */
    static const uint8_t code[] = {
        0x48,0x8B,0x04,0xCB, 0x48,0x8B,0x54,0xCB,0x08, 0x48,0x8B,0x34,0xCB, 0xC3 };
    lifted_t L; lift_x86(&L, code, sizeof code, 0x6000, "indexed");
    an_t an;
    assert(cbae_use_def_build(L.func, &an.ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&an.ud, &an.ctx) == CBAE_OK);

    assert(lifted_query(&an, &L, CIR_OP_LOAD, 0, CIR_OP_LOAD, 1) == NO);
    assert(lifted_query(&an, &L, CIR_OP_LOAD, 0, CIR_OP_LOAD, 2) == MUST);
    assert(lifted_query(&an, &L, CIR_OP_LOAD, 1, CIR_OP_LOAD, 2) == NO);

    an_free(&an);
    lifted_destroy(&L);
    printf("  [PASS] lifted indexed loads: [b+8c] vs [b+8c+8] is NO, repeated [b+8c] is MUST\n");
}

static void t_lifted_narrow_register_conflation(void) {
    /*   0x7000: 48 63 C1           movsxd rax, ecx
     *   0x7003: 48 8B 14 83        mov rdx, [rbx+rax*4]
     *   0x7007: 48 63 F7           movsxd rsi, edi
     *   0x700A: 48 8B 0C B3        mov rcx, [rbx+rsi*4]
     *   0x700E: C3                 ret
     * ecx and edi are different registers, but both lift to the one
     * parameter "other". Without the protection the two loads would look
     * like the SAME address and be reported MUST. */
    static const uint8_t code[] = {
        0x48,0x63,0xC1, 0x48,0x8B,0x14,0x83, 0x48,0x63,0xF7, 0x48,0x8B,0x0C,0xB3, 0xC3 };
    lifted_t L; lift_x86(&L, code, sizeof code, 0x7000, "narrow");
    an_t an;
    assert(cbae_use_def_build(L.func, &an.ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&an.ud, &an.ctx) == CBAE_OK);

    const cbae_cir_instruction_t *l0 = lh_nth_insn(L.func, CIR_OP_LOAD, 0);
    const cbae_cir_value_t *addr; uint32_t size;
    assert(cbae_alias_mem_access(l0, &addr, &size));
    cbae_addr_info_t info;
    assert(cbae_alias_decompose(&an.ctx, addr, &info));
    bool has_other = false;
    for (uint32_t k = 0; k < info.term_count; k++)
        if (info.terms[k].value->kind == CIR_VAL_PARAM &&
            info.terms[k].value->u.param_reg == CBAE_REG_OTHER) has_other = true;
    assert(has_other);                      /* the index really is the "other" param */

    assert(lifted_query(&an, &L, CIR_OP_LOAD, 0, CIR_OP_LOAD, 1) == MAY);
    assert(lifted_query(&an, &L, CIR_OP_LOAD, 0, CIR_OP_LOAD, 0) == MAY);

    an_free(&an);
    lifted_destroy(&L);
    printf("  [PASS] lifted narrow registers: two different 32-bit indices are never reported as the same\n");
}

int main(void) {
    printf("Alias analysis tests:\n");
    t_same_root_offsets();
    t_stack_frame();
    t_absolute();
    t_distinct_atoms();
    t_loaded_pointer();
    t_indexed();
    t_term_cap();
    t_wraparound();
    t_limits_and_budget();
    t_expansion_limits();
    t_cancellation();
    t_work_cap_is_sticky();
    t_narrow_arithmetic();
    t_copy_and_shifts();
    t_malformed_operand();
    t_loop_unstable_vs_stable();
    t_invariant_phi();
    t_nested_phi_cluster();
    t_affine_phi();
    t_scaled_phi();
    t_phi_recurrences();
    t_phi_guards();
    t_unresolvable_phi();
    t_phi_pass_cap();
    t_phi_chain_depth();
    t_other_register();
    t_api_edges();
    t_lifted_loop_invariant_base();
    t_lifted_stack_frame();
    t_lifted_indexed();
    t_lifted_narrow_register_conflation();
    printf("All alias analysis tests passed.\n");
    return 0;
}
