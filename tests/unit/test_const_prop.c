/**
 * @file test_const_prop.c
 * @brief Constant propagation: hand-derived cases.
 *
 * Every expected number below was worked out on paper from the function being
 * analysed (what 0xFFFFFFFF + 1 is in 32 bits, what a shift by 64 does, which
 * edge a constant condition leaves open) and not read off the analysis output.
 * Where the analysis is deliberately weaker than the truth the test says so,
 * so that an improvement is a conscious change to the test.
 *
 *   - arithmetic at 64 bits, on pointers, and at narrow widths (wrap-around);
 *   - COPY that truncates, widens, or stays the same width;
 *   - operands of different widths, which are never folded unless the low bits
 *     alone decide the result;
 *   - shifts (count modulo 64, only at 64 bits, a zero shifted whatever the count);
 *   - the identities that give a constant from an unknown value, and the one
 *     place they do not hold (the lifter's conflated register "other");
 *   - phis: equal, unequal, self-referential, induction variables, narrow incomings;
 *   - the conditional part: constant conditions (an i1 constant is its low bit),
 *     folded branches, dead blocks and the phis that must ignore them;
 *   - opcodes that are never folded, lookups of foreign values, bad arguments;
 *   - large functions, and machine code through the lifter.
 *
 * The check against real executions is test_const_prop_soundness.c.
 *
 * MUTATION TESTING (const_prop.c, 290 single-edit mutants, this file plus the
 * soundness test, the survivors re-run under ASan/UBSan/LeakSanitizer): every
 * mutant is killed except 17 that cannot change what the analysis answers on a
 * valid function. They are listed so that a later run is not a surprise:
 *   - unreachable `default:` arms of the three dispatch switches (arith, unary,
 *     shift): eval_insn sends only the opcodes each handles;
 *   - the `.k == LAT_CONST` guards of the all-ones test and of meet(), and the
 *     zeroing of a lowered value: a state that is not CONSTANT carries the value 0,
 *     so the guards and the zeroing back each other up (each is needed alone only
 *     if the other is removed);
 *   - the shift-width tests `< 8`, `!= 64`, `!= 64`: CIR has no integer type of
 *     2 to 7 bits or of more than 64, so a looser comparison admits the same set;
 *   - lower() keeping a CONSTANT whose new value differs: every transfer function
 *     is monotone, so a result that was CONSTANT is recomputed to the same constant
 *     or to VARYING, never to another constant;
 *   - five performance-only choices (the early exit of the phi loop; not
 *     re-marking an open edge; queuing a new block's phis as well as visiting it;
 *     queuing every instruction of an old block rather than its phis): evaluating
 *     more, or again, reaches the same fixed point;
 *   - is_other_param() testing the value's kind first: on a valid function the
 *     union field it then reads belongs to a parameter.
 */
#include "dataflow/const_prop.h"
#include "cir/cir_printer.h"
#include "platform/logging.h"
#include "cir_test_util.h"
#include "lift_helpers.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T1  cir_type_i1()
#define T16 cir_type_i(16)
#define TP  cir_type_ptr()

typedef cbae_cir_value_t *val_t;

typedef struct {
    cbae_use_def_t    ud;
    cbae_const_prop_t cp;
} cpx_t;

static void cpx_build_unchecked(cpx_t *x, const cbae_cir_function_t *f) {
    assert(cbae_use_def_build(f, &x->ud) == CBAE_OK);
    assert(cbae_const_prop_run(&x->ud, &x->cp) == CBAE_OK);
}

static void cpx_build(cpx_t *x, const fn_t *f) {
    fn_verify(f);
    cpx_build_unchecked(x, f->f);
}

static void cpx_free(cpx_t *x) {
    cbae_const_prop_destroy(&x->cp);
    cbae_use_def_destroy(&x->ud);
}

/* ── Checks ───────────────────────────────────────────────────────────── */

static void expect_const(const cpx_t *x, const char *what, const cbae_cir_value_t *v, uint64_t want) {
    const cbae_cp_value_t r = cbae_const_prop_value(&x->cp, v);
    if (r.kind != CBAE_CP_CONSTANT || r.value != want)
        fprintf(stderr, "FAIL [%s] %%v%u: kind=%d value=%#llx, want CONSTANT %#llx\n", what, v->id,
                (int)r.kind, (unsigned long long)r.value, (unsigned long long)want);
    assert(r.kind == CBAE_CP_CONSTANT && r.value == want);
    uint64_t out = ~want;
    assert(cbae_const_prop_is_constant(&x->cp, v, &out) && out == want);
    assert(cbae_const_prop_is_constant(&x->cp, v, NULL));
}

static void expect_kind(const cpx_t *x, const char *what, const cbae_cir_value_t *v, cbae_cp_kind_t want) {
    const cbae_cp_value_t r = cbae_const_prop_value(&x->cp, v);
    if (r.kind != want || r.value != 0)
        fprintf(stderr, "FAIL [%s] %%v%u: kind=%d value=%#llx, want kind %d\n", what, v->id,
                (int)r.kind, (unsigned long long)r.value, (int)want);
    assert(r.kind == want && r.value == 0);
    uint64_t out = 0x1234;
    assert(!cbae_const_prop_is_constant(&x->cp, v, &out) && out == 0x1234);
}

#define expect_varying(x, what, v)   expect_kind((x), (what), (v), CBAE_CP_VARYING)
#define expect_unreached(x, what, v) expect_kind((x), (what), (v), CBAE_CP_UNREACHED)

static void expect_block(const cpx_t *x, const char *what, uint32_t b, bool want) {
    const bool got = cbae_const_prop_block_executable(&x->cp, b);
    if (got != want) fprintf(stderr, "FAIL [%s] block %u executable=%d, want %d\n", what, b, (int)got, (int)want);
    assert(got == want);
}

static void expect_edge(const cpx_t *x, const char *what, uint32_t from, uint32_t to, bool want) {
    const bool got = cbae_const_prop_edge_executable(&x->cp, from, to);
    if (got != want)
        fprintf(stderr, "FAIL [%s] edge %u->%u executable=%d, want %d\n", what, from, to, (int)got, (int)want);
    assert(got == want);
}

/* ── Builders ─────────────────────────────────────────────────────────── */

static val_t ci(cbae_cir_builder_t *b, cbae_cir_type_t t, int64_t v) {
    val_t r = cbae_cir_const(b, t, v);
    assert(r);
    return r;
}

static val_t bin(cbae_cir_builder_t *b, cbae_cir_opcode_t op, val_t x, val_t y, cbae_cir_type_t t) {
    val_t r = cbae_cir_binop(b, op, x, y, t, 0);
    assert(r);
    return r;
}

static val_t un(cbae_cir_builder_t *b, cbae_cir_opcode_t op, val_t x, cbae_cir_type_t t) {
    val_t ops[1] = { x };
    val_t r = cbae_cir_emit(b, op, t, 0, ops, 1);
    assert(r);
    return r;
}

static val_t phi(fn_t *x, cbae_cir_block_t *blk, cbae_cir_type_t t) {
    val_t r = cbae_cir_phi_create(x->f, blk, t);
    assert(r);
    return r;
}

static void incoming(fn_t *x, val_t ph, val_t v, const cbae_cir_block_t *from) {
    assert(cbae_cir_phi_add_incoming(x->f, ph->u.def_insn, v, from->id) == CBAE_OK);
}

static void ret(fn_t *x, cbae_cir_block_t *blk) {
    fn_at(x, blk);
    cbae_cir_return(&x->bld, NULL, 0);
}

/* ── Arithmetic ───────────────────────────────────────────────────────── */

static void t_arith64(void) {
    /*   c5 = 5, c7 = 7, all i64
     *   add 12   sub 5-7 = -2   mul 35   and 101&111 = 101 = 5   or 7   xor 010 = 2
     *   not 5 = ~5 (…FA)   neg 5 = -5 (…FB)
     *   a chain through instruction results: (12 * 3) - 1 = 35, and 12 + 35 = 47
     *   wrap-around: 2^32 * 2^32 = 2^64 = 0,  (-1) + 1 = 0,  INT64_MIN * 2 = 0
     *   pointers: ptr 0x1000 + 8 = 0x1008 (a PTR result), 0x1008 - 0x1000 = 8 (i64)       */
    fn_t x; fn_init(&x, "arith64");
    cbae_cir_builder_t *b = &x.bld;
    val_t c5 = ci(b, T64, 5), c7 = ci(b, T64, 7), c3 = ci(b, T64, 3), c1 = ci(b, T64, 1);
    val_t add = bin(b, CIR_OP_ADD, c5, c7, T64), sub = bin(b, CIR_OP_SUB, c5, c7, T64);
    val_t mul = bin(b, CIR_OP_MUL, c5, c7, T64), and_ = bin(b, CIR_OP_AND, c5, c7, T64);
    val_t or_ = bin(b, CIR_OP_OR, c5, c7, T64),  xor_ = bin(b, CIR_OP_XOR, c5, c7, T64);
    val_t not_ = un(b, CIR_OP_NOT, c5, T64),     neg = un(b, CIR_OP_NEG, c5, T64);
    val_t t = bin(b, CIR_OP_MUL, add, c3, T64), u = bin(b, CIR_OP_SUB, t, c1, T64);
    val_t sum = bin(b, CIR_OP_ADD, add, mul, T64);
    val_t w1 = bin(b, CIR_OP_MUL, ci(b, T64, INT64_C(1) << 32), ci(b, T64, INT64_C(1) << 32), T64);
    val_t w2 = bin(b, CIR_OP_ADD, ci(b, T64, -1), c1, T64);
    val_t w3 = bin(b, CIR_OP_MUL, ci(b, T64, INT64_MIN), ci(b, T64, 2), T64);
    val_t p0 = ci(b, TP, 0x1000), p1 = bin(b, CIR_OP_ADD, p0, ci(b, T64, 8), TP);
    val_t pd = bin(b, CIR_OP_SUB, p1, p0, T64);
    cbae_cir_return(b, u, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "add", add, 12);
    expect_const(&c, "sub", sub, UINT64_C(0xFFFFFFFFFFFFFFFE));
    expect_const(&c, "mul", mul, 35);
    expect_const(&c, "and", and_, 5);
    expect_const(&c, "or",  or_, 7);
    expect_const(&c, "xor", xor_, 2);
    expect_const(&c, "not", not_, UINT64_C(0xFFFFFFFFFFFFFFFA));
    expect_const(&c, "neg", neg, UINT64_C(0xFFFFFFFFFFFFFFFB));
    expect_const(&c, "chain t", t, 36);
    expect_const(&c, "chain u", u, 35);
    expect_const(&c, "chain sum", sum, 47);
    expect_const(&c, "2^32 * 2^32 wraps to 0", w1, 0);
    expect_const(&c, "-1 + 1", w2, 0);
    expect_const(&c, "INT64_MIN * 2", w3, 0);
    expect_const(&c, "ptr + 8", p1, 0x1008);
    expect_const(&c, "ptr - ptr", pd, 8);
    expect_const(&c, "a PTR constant is its address", p0, 0x1000);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] 64-bit and pointer arithmetic folds, including through chains and wrap-around\n");
}

static void t_narrow_wrap(void) {
    /*   i32:  0xFFFFFFFF + 1 = 0x1_0000_0000 -> 0         neg 1 = 0xFFFFFFFF   not 0 = 0xFFFFFFFF
     *   i16:  300 * 300 = 90000 = 65536 + 24464 -> 24464  (a constant that does not fit its type,
     *         70000 = 65536 + 4464, is held as 4464: constants live at their own width)
     *   i8:   200 + 100 = 300 = 256 + 44 -> 44            3 - 5 = -2 -> 0xFE
     *   i1:   1 ^ 1 = 0    1 + 1 = 2 -> 0    not 0 = 1    neg 1 = -1 -> 1                         */
    fn_t x; fn_init(&x, "narrow_wrap");
    cbae_cir_builder_t *b = &x.bld;
    val_t m1 = ci(b, T32, -1), one32 = ci(b, T32, 1), zero32 = ci(b, T32, 0);
    val_t a = bin(b, CIR_OP_ADD, m1, one32, T32);
    val_t n = un(b, CIR_OP_NEG, one32, T32), nt = un(b, CIR_OP_NOT, zero32, T32);
    val_t k300 = ci(b, T16, 300), k70000 = ci(b, T16, 70000);
    val_t m16 = bin(b, CIR_OP_MUL, k300, k300, T16);
    val_t big16 = bin(b, CIR_OP_ADD, k70000, ci(b, T16, 0), T16);
    val_t a8 = bin(b, CIR_OP_ADD, ci(b, T8, 200), ci(b, T8, 100), T8);
    val_t s8 = bin(b, CIR_OP_SUB, ci(b, T8, 3), ci(b, T8, 5), T8);
    val_t t1 = ci(b, T1, 1), f1 = ci(b, T1, 0);
    val_t x1 = bin(b, CIR_OP_XOR, t1, t1, T1), p1 = bin(b, CIR_OP_ADD, t1, t1, T1);
    val_t n1 = un(b, CIR_OP_NOT, f1, T1), g1 = un(b, CIR_OP_NEG, t1, T1);
    cbae_cir_return(b, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "i32 wrap", a, 0);
    expect_const(&c, "i32 neg", n, 0xFFFFFFFFu);
    expect_const(&c, "i32 not", nt, 0xFFFFFFFFu);
    expect_const(&c, "i16 mul wrap", m16, 24464);
    expect_const(&c, "i16 constant that does not fit", k70000, 4464);
    expect_const(&c, "i16 arithmetic on it", big16, 4464);
    expect_const(&c, "i8 add wrap", a8, 44);
    expect_const(&c, "i8 sub wrap", s8, 0xFE);
    expect_const(&c, "i32 constant -1", m1, 0xFFFFFFFFu);
    expect_const(&c, "i1 xor", x1, 0);
    expect_const(&c, "i1 add wrap", p1, 0);
    expect_const(&c, "i1 not", n1, 1);
    expect_const(&c, "i1 neg", g1, 1);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] narrow arithmetic wraps at the value's own width (i1 .. i32)\n");
}

/* ── COPY ─────────────────────────────────────────────────────────────── */

static void t_copy(void) {
    /*   w = 0x1_2345_6789 (i64)
     *   copy to i32 -> low 32 bits 0x23456789     to i16 -> 0x6789     to i8 -> 0x89
     *   copy to i64 / PTR (same width)            -> unchanged
     *   copy of a narrow value to a wider type    -> VARYING: CIR does not say how it is extended
     *   copy of an i8 to i8                       -> unchanged
     *   a copy of a copy                          -> still known                                */
    fn_t x; fn_init(&x, "copy");
    cbae_cir_builder_t *b = &x.bld;
    val_t w = ci(b, T64, INT64_C(0x123456789));
    val_t c32 = un(b, CIR_OP_COPY, w, T32), c16 = un(b, CIR_OP_COPY, w, T16), c8 = un(b, CIR_OP_COPY, w, T8);
    val_t c64 = un(b, CIR_OP_COPY, w, T64), cp = un(b, CIR_OP_COPY, w, TP);
    val_t cc = un(b, CIR_OP_COPY, c32, T32);
    val_t n32 = ci(b, T32, 0x7FFFFFFF);
    val_t wide = un(b, CIR_OP_COPY, n32, T64), wide16 = un(b, CIR_OP_COPY, c8, T16);
    val_t same8 = un(b, CIR_OP_COPY, c8, T8);
    val_t back = un(b, CIR_OP_COPY, wide, T32);
    cbae_cir_return(b, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "truncate to i32", c32, 0x23456789u);
    expect_const(&c, "truncate to i16", c16, 0x6789);
    expect_const(&c, "truncate to i8", c8, 0x89);
    expect_const(&c, "same width i64", c64, UINT64_C(0x123456789));
    expect_const(&c, "same width PTR", cp, UINT64_C(0x123456789));
    expect_const(&c, "copy of a copy", cc, 0x23456789u);
    expect_varying(&c, "widening i32 -> i64", wide);
    expect_varying(&c, "widening i8 -> i16", wide16);
    expect_const(&c, "i8 -> i8", same8, 0x89);
    expect_varying(&c, "truncating what was never known", back);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] COPY: truncation and same-width copies fold, widening is VARYING\n");
}

static void t_mixed_width(void) {
    /*   big = 0x1_0000_0001 (i64), small = 2 (i32)
     *   add as i64                    -> VARYING (small would have to be extended)
     *   add as i32                    -> only the low 32 bits matter: 1 + 2 = 3
     *   i64 0x10 + i32 0x80000000, i32 -> 0x80000010 (the same under zero or sign extension)
     *   2 * big as i32                -> 2 * 1 = 2
     *   i32 + i8 as i32               -> VARYING (the i8 is narrower than the result)
     *   p AND (i32 0) as i64          -> VARYING   (a narrower operand: nothing is claimed)
     *   p AND (i64 0) as i32          -> 0 (low 32 bits of an AND with zero)
     *   p AND 0x1_0000_0000 as i32    -> 0 (the constant's low 32 bits are zero)
     *   p OR 0xFFFFFFFF (i32) as i32  -> 0xFFFFFFFF;  p OR 0x1_FFFF_FFFF (i64) as i32 -> same */
    fn_t x; fn_init(&x, "mixed");
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    val_t big = ci(b, T64, INT64_C(0x100000001)), small = ci(b, T32, 2);
    val_t wadd = bin(b, CIR_OP_ADD, big, small, T64), ladd = bin(b, CIR_OP_ADD, big, small, T32);
    val_t ladd2 = bin(b, CIR_OP_ADD, ci(b, T64, 0x10), ci(b, T32, 0x80000000), T32);
    val_t lmul = bin(b, CIR_OP_MUL, small, big, T32);
    val_t i8mix = bin(b, CIR_OP_ADD, ci(b, T32, 5), ci(b, T8, 1), T32);
    val_t and_narrow = bin(b, CIR_OP_AND, p, ci(b, T32, 0), T64);
    val_t and_lo = bin(b, CIR_OP_AND, p, ci(b, T64, 0), T32);
    val_t and_hi = bin(b, CIR_OP_AND, p, ci(b, T64, INT64_C(0x100000000)), T32);
    val_t or_a = bin(b, CIR_OP_OR, p, ci(b, T32, 0xFFFFFFFF), T32);
    val_t or_b = bin(b, CIR_OP_OR, p, ci(b, T64, INT64_C(0x1FFFFFFFF)), T32);
    cbae_cir_return(b, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_varying(&c, "i64 + i32 as i64", wadd);
    expect_const(&c, "i64 + i32 as i32", ladd, 3);
    expect_const(&c, "0x10 + 0x80000000 as i32", ladd2, 0x80000010u);
    expect_const(&c, "2 * big as i32", lmul, 2);
    expect_varying(&c, "i32 + i8 as i32", i8mix);
    expect_varying(&c, "AND with a narrower zero", and_narrow);
    expect_const(&c, "AND with zero, narrowed", and_lo, 0);
    expect_const(&c, "AND with a constant whose low half is zero", and_hi, 0);
    expect_const(&c, "OR with all ones at the result width (i32)", or_a, 0xFFFFFFFFu);
    expect_const(&c, "OR with a constant whose low half is all ones", or_b, 0xFFFFFFFFu);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] mixed widths fold only when the low bits alone decide the result\n");
}

/* ── Shifts ───────────────────────────────────────────────────────────── */

static void t_shifts(void) {
    /*   64-bit, count modulo 64:
     *     5 << 64 = 5 (count 0)      1 << 63 = 0x8000...0      0x8000...0 >> 63 = 1
     *     sar(0x8000...0, 63) = all ones      sar(0x4000...0, 62) = 1      1 << 65 = 2
     *     shr(-1, 1) = 0x7FFF...F      sar(-1, 1) = -1
     *     an i8 count is enough: 1 << 3 = 8; 0x83 & 63 = 3, so 1 << 0x83 = 8
     *   never folded (VARYING): a 32-bit shift, an i1 count, an i32 value in an i64 shift, a
     *   32-bit result.                                                                            */
    fn_t x; fn_init(&x, "shifts");
    cbae_cir_builder_t *b = &x.bld;
    val_t one = ci(b, T64, 1), c5 = ci(b, T64, 5);
    val_t shl64 = bin(b, CIR_OP_SHL, c5, ci(b, T64, 64), T64);
    val_t shl63 = bin(b, CIR_OP_SHL, one, ci(b, T64, 63), T64);
    val_t shr63 = bin(b, CIR_OP_SHR, shl63, ci(b, T64, 63), T64);
    val_t sar63 = bin(b, CIR_OP_SAR, shl63, ci(b, T64, 63), T64);
    val_t sar62 = bin(b, CIR_OP_SAR, ci(b, T64, INT64_C(0x4000000000000000)), ci(b, T64, 62), T64);
    val_t shl65 = bin(b, CIR_OP_SHL, one, ci(b, T64, 65), T64);
    val_t shr1n = bin(b, CIR_OP_SHR, ci(b, T64, -1), ci(b, T64, 1), T64);
    val_t sar1n = bin(b, CIR_OP_SAR, ci(b, T64, -1), ci(b, T64, 1), T64);
    val_t cnt8  = bin(b, CIR_OP_SHL, one, ci(b, T8, 3), T64);
    val_t cnt83 = bin(b, CIR_OP_SHL, one, ci(b, T8, 0x83), T64);
    val_t sh32  = bin(b, CIR_OP_SHL, ci(b, T32, 1), ci(b, T64, 1), T32);
    val_t shi1  = bin(b, CIR_OP_SHL, one, ci(b, T1, 1), T64);
    val_t shv32 = bin(b, CIR_OP_SHL, ci(b, T32, 1), ci(b, T64, 1), T64);
    val_t shr32 = bin(b, CIR_OP_SHL, one, ci(b, T64, 1), T32);
    cbae_cir_return(b, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "5 << 64", shl64, 5);
    expect_const(&c, "1 << 63", shl63, UINT64_C(0x8000000000000000));
    expect_const(&c, "shr by 63", shr63, 1);
    expect_const(&c, "sar by 63", sar63, UINT64_MAX);
    expect_const(&c, "sar by 62", sar62, 1);
    expect_const(&c, "1 << 65", shl65, 2);
    expect_const(&c, "shr(-1, 1)", shr1n, UINT64_C(0x7FFFFFFFFFFFFFFF));
    expect_const(&c, "sar(-1, 1)", sar1n, UINT64_MAX);
    expect_const(&c, "i8 count", cnt8, 8);
    expect_const(&c, "i8 count 0x83", cnt83, 8);
    expect_varying(&c, "32-bit shift", sh32);
    expect_varying(&c, "i1 count", shi1);
    expect_varying(&c, "i32 value in a 64-bit shift", shv32);
    expect_varying(&c, "32-bit result", shr32);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] shifts: count modulo 64, only 64-bit shifts with a count of 8+ bits fold\n");
}

/* ── Identities ───────────────────────────────────────────────────────── */

static void t_identities(void) {
    /*   p = rbx (unknown), o = the lifter's conflated "other", l1/l2 = two loads
     *   p & 0 = 0, 0 & p = 0, p * 0 = 0, 0 * p = 0, p | -1 = -1, -1 | p = -1
     *   p ^ p = 0, p - p = 0, l1 ^ l1 = 0 (one SSA value read twice is one number)
     *   not known: l1 - l2 (two loads), p + p, p | 0, p & -1, p * 1, p ^ 0
     *   other: o & 0 = 0 holds; o ^ o and o - o do NOT (each read of "other" may differ)
     *   0 shifted by an unknown count is 0 (shl, shr, sar); an unknown shifted by 0 is unknown;
     *   a zero made by arithmetic (5 - 5) counts too.                                            */
    fn_t x; fn_init(&x, "identities");
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX), o = cbae_cir_param(b, CBAE_REG_OTHER);
    val_t zero = ci(b, T64, 0), ones = ci(b, T64, -1), one = ci(b, T64, 1);
    val_t l1 = k_load(b, p), l2 = k_load(b, p);
    val_t and0 = bin(b, CIR_OP_AND, p, zero, T64), and0b = bin(b, CIR_OP_AND, zero, p, T64);
    val_t mul0 = bin(b, CIR_OP_MUL, p, zero, T64), mul0b = bin(b, CIR_OP_MUL, zero, p, T64);
    val_t or1 = bin(b, CIR_OP_OR, p, ones, T64), or1b = bin(b, CIR_OP_OR, ones, p, T64);
    val_t xpp = bin(b, CIR_OP_XOR, p, p, T64), spp = bin(b, CIR_OP_SUB, p, p, T64);
    val_t xll = bin(b, CIR_OP_XOR, l1, l1, T64), sl12 = bin(b, CIR_OP_SUB, l1, l2, T64);
    val_t app = bin(b, CIR_OP_ADD, p, p, T64), orp0 = bin(b, CIR_OP_OR, p, zero, T64);
    val_t andp1 = bin(b, CIR_OP_AND, p, ones, T64), mulp1 = bin(b, CIR_OP_MUL, p, one, T64);
    val_t xorp0 = bin(b, CIR_OP_XOR, p, zero, T64);
    val_t aandp = bin(b, CIR_OP_AND, p, p, T64), aorp = bin(b, CIR_OP_OR, p, p, T64);
    val_t mulpp = bin(b, CIR_OP_MUL, p, p, T64), shlpp = bin(b, CIR_OP_SHL, p, p, T64);
    val_t xoo = bin(b, CIR_OP_XOR, o, o, T64), soo = bin(b, CIR_OP_SUB, o, o, T64);
    val_t ao0 = bin(b, CIR_OP_AND, o, zero, T64);
    val_t shl0 = bin(b, CIR_OP_SHL, zero, p, T64), shr0 = bin(b, CIR_OP_SHR, zero, p, T64);
    val_t sar0 = bin(b, CIR_OP_SAR, zero, p, T64), shp0 = bin(b, CIR_OP_SHL, p, zero, T64);
    val_t z5 = bin(b, CIR_OP_SUB, ci(b, T64, 5), ci(b, T64, 5), T64);
    val_t shz5 = bin(b, CIR_OP_SHR, z5, p, T64);
    val_t c32 = un(b, CIR_OP_COPY, p, T32);
    val_t x32 = bin(b, CIR_OP_XOR, c32, c32, T32);
    cbae_cir_return(b, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "p & 0", and0, 0);
    expect_const(&c, "0 & p", and0b, 0);
    expect_const(&c, "p * 0", mul0, 0);
    expect_const(&c, "0 * p", mul0b, 0);
    expect_const(&c, "p | -1", or1, UINT64_MAX);
    expect_const(&c, "-1 | p", or1b, UINT64_MAX);
    expect_const(&c, "p ^ p", xpp, 0);
    expect_const(&c, "p - p", spp, 0);
    expect_const(&c, "load ^ same load", xll, 0);
    expect_varying(&c, "two different loads", sl12);
    expect_varying(&c, "p + p", app);
    expect_varying(&c, "p | 0", orp0);
    expect_varying(&c, "p & -1", andp1);
    expect_varying(&c, "p * 1", mulp1);
    expect_varying(&c, "p ^ 0", xorp0);
    expect_varying(&c, "p & p", aandp);
    expect_varying(&c, "p | p", aorp);
    expect_varying(&c, "p * p", mulpp);
    expect_varying(&c, "p << p", shlpp);
    expect_varying(&c, "other ^ other", xoo);
    expect_varying(&c, "other - other", soo);
    expect_const(&c, "other & 0", ao0, 0);
    expect_const(&c, "0 << p", shl0, 0);
    expect_const(&c, "0 >> p", shr0, 0);
    expect_const(&c, "0 sar p", sar0, 0);
    expect_varying(&c, "p << 0", shp0);
    expect_const(&c, "5 - 5", z5, 0);
    expect_const(&c, "(5 - 5) >> p", shz5, 0);
    expect_const(&c, "narrow x ^ x", x32, 0);
    expect_varying(&c, "a parameter", p);
    expect_varying(&c, "the conflated parameter", o);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] identities give constants from unknown values; \"other\" is never equal to itself\n");
}

/* ── Order of evaluation ──────────────────────────────────────────────── */

static void t_transient_unknown(void) {
    /*   Found by test_const_prop_soundness.c (reference solver, seed 666). The answer must not
     *   depend on the order in which values are evaluated: an annihilator with a value that is
     *   not known YET must wait, not fall.
     *
     *   b0: p, q = params ; c = cmp p, q ; branch c, b1, b2
     *   b2: jump b1
     *   b1: z = phi [0, b0] [0, b2]          -> 0
     *       u = phi [p, b0] [q, b2]          -> VARYING
     *       m = z * u    s = z << u    a = z & u    -> all 0 (a zero annihilates, whatever the other is)
     *       o = (z - 1) | u ... not used; k = (-1 + z) | u -> -1 (all ones annihilate an OR)
     *   Both phis of b1 are queued when the edge b2->b1 opens, the later one (u) is evaluated first,
     *   so m, s and a are first evaluated while z is still unknown. Evaluating them to VARYING at
     *   that point, as an unknown-before-varying rule does, loses the constant for good.          */
    fn_t x; fn_init(&x, "transient");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX), q = cbae_cir_param(b, CBAE_REG_RCX);
    val_t c = bin(b, CIR_OP_CMP, p, q, T1);
    cbae_cir_branch(b, c, b1, b2, 0);
    fn_at(&x, b2);
    cbae_cir_jump(&x.bld, b1, 0);

    val_t u = phi(&x, b1, T64);              /* created first, so it comes second in the block */
    val_t z = phi(&x, b1, T64);
    val_t zc = phi(&x, b1, T64);
    fn_at(&x, b1);
    cbae_cir_builder_t *e = &x.bld;
    val_t m = bin(e, CIR_OP_MUL, z, u, T64);
    val_t s = bin(e, CIR_OP_SHL, z, u, T64);
    val_t a = bin(e, CIR_OP_AND, u, z, T64);
    val_t k = bin(e, CIR_OP_OR, zc, u, T64);
    cbae_cir_return(e, NULL, 0);
    incoming(&x, u, p, x.b0);              incoming(&x, u, q, b2);
    incoming(&x, z, ci(e, T64, 0), x.b0);  incoming(&x, z, ci(e, T64, 0), b2);
    incoming(&x, zc, ci(e, T64, -1), x.b0); incoming(&x, zc, ci(e, T64, -1), b2);

    cpx_t cx; cpx_build(&cx, &x);
    expect_const(&cx, "phi of zeros", z, 0);
    expect_varying(&cx, "phi of parameters", u);
    expect_const(&cx, "0 * unknown", m, 0);
    expect_const(&cx, "0 << unknown", s, 0);
    expect_const(&cx, "unknown & 0", a, 0);
    expect_const(&cx, "all ones | unknown", k, UINT64_MAX);
    cpx_free(&cx); fn_done(&x);
    printf("  [PASS] an annihilator waits for a value that is not known yet instead of falling to VARYING\n");
}

/* ── Phis ─────────────────────────────────────────────────────────────── */

static void t_phi_diamond(void) {
    /*   b0: p, q = params ; c = cmp p, q (i1, unknown) ; branch c, b1, b2
     *   b1: v1 = 2 + 3 ; jump b3          b2: v2 = 5 * 1 ; jump b3
     *   b3: same   = phi [5 (one constant object), b1] [5 (another), b2]      -> 5
     *       fromop = phi [v1, b1] [v2, b2]                                    -> 5 (both are 5)
     *       differ = phi [5, b1] [7, b2]                                      -> VARYING
     *       withp  = phi [5, b1] [p, b2]                                      -> VARYING
     *       narrow = phi i64 [5, b1] [i32 5, b2]                              -> VARYING (an incoming
     *                narrower than the phi would have to be extended)
     *       trunc  = phi i32 [i64 0x1_0000_0005, b1] [i32 5, b2]              -> 5 (low 32 bits agree)
     *       trunc2 = phi i32 [i64 0x1_0000_0005, b1] [i32 6, b2]              -> VARYING
     *       bit    = phi i1 [1, b1] [1, b2]                                   -> 1                   */
    fn_t x; fn_init(&x, "phi_diamond");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX), q = cbae_cir_param(b, CBAE_REG_RCX);
    val_t c = bin(b, CIR_OP_CMP, p, q, T1);
    cbae_cir_branch(b, c, b1, b2, 0);
    fn_at(&x, b1);
    val_t v1 = bin(&x.bld, CIR_OP_ADD, ci(&x.bld, T64, 2), ci(&x.bld, T64, 3), T64);
    cbae_cir_jump(&x.bld, b3, 0);
    fn_at(&x, b2);
    val_t v2 = bin(&x.bld, CIR_OP_MUL, ci(&x.bld, T64, 5), ci(&x.bld, T64, 1), T64);
    cbae_cir_jump(&x.bld, b3, 0);

    val_t same = phi(&x, b3, T64), fromop = phi(&x, b3, T64), differ = phi(&x, b3, T64);
    val_t withp = phi(&x, b3, T64), narrow = phi(&x, b3, T64), trunc = phi(&x, b3, T32);
    val_t trunc2 = phi(&x, b3, T32), bit = phi(&x, b3, T1);
    incoming(&x, same, ci(&x.bld, T64, 5), b1);   incoming(&x, same, ci(&x.bld, T64, 5), b2);
    incoming(&x, fromop, v1, b1);                 incoming(&x, fromop, v2, b2);
    incoming(&x, differ, ci(&x.bld, T64, 5), b1); incoming(&x, differ, ci(&x.bld, T64, 7), b2);
    incoming(&x, withp, ci(&x.bld, T64, 5), b1);  incoming(&x, withp, p, b2);
    incoming(&x, narrow, ci(&x.bld, T64, 5), b1); incoming(&x, narrow, ci(&x.bld, T32, 5), b2);
    incoming(&x, trunc, ci(&x.bld, T64, INT64_C(0x100000005)), b1);
    incoming(&x, trunc, ci(&x.bld, T32, 5), b2);
    incoming(&x, trunc2, ci(&x.bld, T64, INT64_C(0x100000005)), b1);
    incoming(&x, trunc2, ci(&x.bld, T32, 6), b2);
    incoming(&x, bit, ci(&x.bld, T1, 1), b1);     incoming(&x, bit, ci(&x.bld, T1, 1), b2);
    ret(&x, b3);

    cpx_t cx; cpx_build(&cx, &x);
    expect_const(&cx, "v1", v1, 5);
    expect_const(&cx, "v2", v2, 5);
    expect_const(&cx, "equal constants", same, 5);
    expect_const(&cx, "equal results", fromop, 5);
    expect_varying(&cx, "unequal constants", differ);
    expect_varying(&cx, "constant and unknown", withp);
    expect_varying(&cx, "narrower incoming", narrow);
    expect_const(&cx, "truncating phi, equal low bits", trunc, 5);
    expect_varying(&cx, "truncating phi, different low bits", trunc2);
    expect_const(&cx, "i1 phi", bit, 1);
    expect_varying(&cx, "the comparison", c);
    for (uint32_t i = 0; i < 4; i++) expect_block(&cx, "diamond", i, true);
    expect_edge(&cx, "branch, true edge", 0, 1, true);
    expect_edge(&cx, "branch, false edge", 0, 2, true);
    cpx_free(&cx); fn_done(&x);
    printf("  [PASS] phis: equal incomings fold, unequal, unknown and narrower incomings do not\n");
}

static void t_phi_last(void) {
    /*   A phi that is the LAST instruction of its block (the block has no terminator) is still
     *   re-evaluated when a second edge into the block opens.
     *     b0: c = cmp p, 0 (unknown) ; branch c, b1, b2
     *     b1: jump b3        b2: jump b3
     *     b3: phi [1, b1] [2, b2]       and nothing after it
     *   The false side is visited first, so the phi is first evaluated with only b2's edge open
     *   (-> 2); when b1's edge opens it must be evaluated again (-> VARYING).                    */
    fn_t x; fn_init(&x, "phi_last");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    val_t c = bin(b, CIR_OP_CMP, p, ci(b, T64, 0), T1);
    cbae_cir_branch(b, c, b1, b2, 0);
    fn_at(&x, b1); cbae_cir_jump(&x.bld, b3, 0);
    fn_at(&x, b2); cbae_cir_jump(&x.bld, b3, 0);
    val_t ph = phi(&x, b3, T64);
    incoming(&x, ph, ci(&x.bld, T64, 1), b1);
    incoming(&x, ph, ci(&x.bld, T64, 2), b2);
    assert(b3->instruction_count == 1 && b3->instructions[0]->opcode == CIR_OP_PHI);

    cpx_t cx; cpx_build(&cx, &x);
    expect_varying(&cx, "a phi that ends its block", ph);
    expect_block(&cx, "b3", 3, true);
    cpx_free(&cx); fn_done(&x);
    printf("  [PASS] a phi that is the last instruction of its block is re-evaluated by a later edge\n");
}

static void t_phi_loop(void) {
    /*   b0: p = param ; jump b1
     *   b1: x = phi [5, b0] [x, b2]            -> 5 (it only ever feeds itself)
     *       y = phi [0, b0] [y2, b2]           -> VARYING (an induction variable) ; y2 = y + 1 -> VARYING
     *       z = phi [3, b0] [z2, b2]           -> 3 ; z2 = z + 0 -> 3
     *       w = phi [1, b0] [w2, b2]           -> 1 ; w2 = w * 1 -> 1
     *       q = phi [2, b0] [q2, b2]           -> VARYING (2, then 4, ...) ; q2 = q * 2 -> VARYING
     *       cp = copy of the constant-phi chain: a = phi [3, b0] [bb, b2] ; bb = copy a -> both 3
     *       c = cmp p, 0 ; branch c, b2, b3
     *   b2: (the updates above) ; d = y - y -> 0 (the same value twice, whatever y is) ; jump b1
     *   b3: return                                                                                */
    fn_t x; fn_init(&x, "phi_loop");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_jump(b, b1, 0);

    val_t xp = phi(&x, b1, T64), y = phi(&x, b1, T64), z = phi(&x, b1, T64);
    val_t w = phi(&x, b1, T64), q = phi(&x, b1, T64), a = phi(&x, b1, T64);
    fn_at(&x, b1);
    val_t c = bin(&x.bld, CIR_OP_CMP, p, ci(&x.bld, T64, 0), T1);
    cbae_cir_branch(&x.bld, c, b2, b3, 0);

    fn_at(&x, b2);
    cbae_cir_builder_t *e = &x.bld;
    val_t y2 = bin(e, CIR_OP_ADD, y, ci(e, T64, 1), T64);
    val_t z2 = bin(e, CIR_OP_ADD, z, ci(e, T64, 0), T64);
    val_t w2 = bin(e, CIR_OP_MUL, w, ci(e, T64, 1), T64);
    val_t q2 = bin(e, CIR_OP_MUL, q, ci(e, T64, 2), T64);
    val_t bb = un(e, CIR_OP_COPY, a, T64);
    val_t d  = bin(e, CIR_OP_SUB, y, y, T64);
    cbae_cir_jump(e, b1, 0);
    ret(&x, b3);

    incoming(&x, xp, ci(e, T64, 5), x.b0); incoming(&x, xp, xp, b2);
    incoming(&x, y, ci(e, T64, 0), x.b0);  incoming(&x, y, y2, b2);
    incoming(&x, z, ci(e, T64, 3), x.b0);  incoming(&x, z, z2, b2);
    incoming(&x, w, ci(e, T64, 1), x.b0);  incoming(&x, w, w2, b2);
    incoming(&x, q, ci(e, T64, 2), x.b0);  incoming(&x, q, q2, b2);
    incoming(&x, a, ci(e, T64, 3), x.b0);  incoming(&x, a, bb, b2);

    cpx_t cx; cpx_build(&cx, &x);
    expect_const(&cx, "self-feeding phi", xp, 5);
    expect_varying(&cx, "induction variable", y);
    expect_varying(&cx, "its update", y2);
    expect_const(&cx, "phi over x + 0", z, 3);
    expect_const(&cx, "x + 0", z2, 3);
    expect_const(&cx, "phi over x * 1", w, 1);
    expect_const(&cx, "x * 1", w2, 1);
    expect_varying(&cx, "doubling variable", q);
    expect_varying(&cx, "its update", q2);
    expect_const(&cx, "phi over a copy of itself", a, 3);
    expect_const(&cx, "the copy", bb, 3);
    expect_const(&cx, "y - y in the loop", d, 0);
    for (uint32_t i = 0; i < 4; i++) expect_block(&cx, "loop", i, true);
    expect_edge(&cx, "back edge", 2, 1, true);
    cpx_free(&cx); fn_done(&x);
    printf("  [PASS] phis in loops: self-feeding and invariant phis fold, induction variables do not\n");
}

/* ── The conditional part ─────────────────────────────────────────────── */

static void t_order_independence(void) {
    /*   The answer must not depend on the order blocks happen to be visited in, even for IR in
     *   which a use is not dominated by its definition (a lifter bug the SSA verifier exists to
     *   catch, but one this analysis must still not turn into an order-dependent answer):
     *     b0: c = cmp p, 0 (unknown) ; branch c, X, Y
     *     b1: w = u + 1 ; ret             (u is defined in b2, which does not dominate b1)
     *     b2: u = 1 + 2 ; jump b1
     *   Block 0 is built twice, once leading to b1 first and once to b2 first, so that b1 is
     *   visited before b2 in one and after it in the other. In both, u = 3 and w = 4.          */
    for (int variant = 0; variant < 2; variant++) {
        fn_t x; fn_init(&x, variant ? "order_b" : "order_a");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        val_t c = bin(b, CIR_OP_CMP, p, ci(b, T64, 0), T1);
        if (variant) cbae_cir_branch(b, c, b2, b1, 0);
        else         cbae_cir_branch(b, c, b1, b2, 0);
        fn_at(&x, b2);
        val_t u = bin(&x.bld, CIR_OP_ADD, ci(&x.bld, T64, 1), ci(&x.bld, T64, 2), T64);
        cbae_cir_jump(&x.bld, b1, 0);
        fn_at(&x, b1);
        val_t w = bin(&x.bld, CIR_OP_ADD, u, ci(&x.bld, T64, 1), T64);
        cbae_cir_return(&x.bld, NULL, 0);

        cpx_t cx; cpx_build_unchecked(&cx, x.f);
        expect_const(&cx, "u", u, 3);
        expect_const(&cx, "w, a use visited before its definition", w, 4);
        expect_block(&cx, "b1", 1, true);
        expect_block(&cx, "b2", 2, true);
        cpx_free(&cx); fn_done(&x);
    }
    printf("  [PASS] the answer does not depend on the order blocks are visited in\n");
}

static void t_cond_branch(void) {
    /*   b0: branch i1 1, b1, b2
     *   b1: v1 = 10 + 1 = 11 ; jump b3          b2 (never entered): v2 = 20 + 1 = 21 ; jump b3
     *   b3: ph = phi [v1, b1] [v2, b2] -> 11 (the dead edge is ignored) ; r = ph + 1 = 12
     *   Executable: blocks 0, 1, 3 and edges 0->1, 1->3. Not: block 2, edges 0->2, 2->3.
     *   v2 is UNREACHED. With the condition 0 the roles of b1 and b2 swap.                    */
    for (int taken = 1; taken >= 0; taken--) {
        fn_t x; fn_init(&x, "cond");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_branch(b, ci(b, T1, taken), b1, b2, 0);
        fn_at(&x, b1);
        val_t v1 = bin(&x.bld, CIR_OP_ADD, ci(&x.bld, T64, 10), ci(&x.bld, T64, 1), T64);
        cbae_cir_jump(&x.bld, b3, 0);
        fn_at(&x, b2);
        val_t v2 = bin(&x.bld, CIR_OP_ADD, ci(&x.bld, T64, 20), ci(&x.bld, T64, 1), T64);
        cbae_cir_jump(&x.bld, b3, 0);
        val_t ph = phi(&x, b3, T64);
        fn_at(&x, b3);
        val_t r = bin(&x.bld, CIR_OP_ADD, ph, ci(&x.bld, T64, 1), T64);
        cbae_cir_return(&x.bld, r, 0);
        incoming(&x, ph, v1, b1);
        incoming(&x, ph, v2, b2);

        cpx_t c; cpx_build(&c, &x);
        const uint64_t live = taken ? 11 : 21, rl = taken ? 12 : 22;
        const val_t live_v = taken ? v1 : v2, dead_v = taken ? v2 : v1;
        expect_const(&c, "live value", live_v, live);
        expect_unreached(&c, "dead value", dead_v);
        expect_const(&c, "phi ignores the dead edge", ph, live);
        expect_const(&c, "user of the phi", r, rl);
        expect_block(&c, "entry", 0, true);
        expect_block(&c, "taken", 1, taken != 0);
        expect_block(&c, "not taken", 2, taken == 0);
        expect_block(&c, "join", 3, true);
        expect_edge(&c, "0->1", 0, 1, taken != 0);
        expect_edge(&c, "0->2", 0, 2, taken == 0);
        expect_edge(&c, "1->3", 1, 3, taken != 0);
        expect_edge(&c, "2->3", 2, 3, taken == 0);
        expect_edge(&c, "not a successor", 0, 3, false);
        expect_edge(&c, "backwards", 3, 1, false);
        cpx_free(&c); fn_done(&x);
    }
    printf("  [PASS] a branch on a constant i1 opens one edge; the dead block is UNREACHED and its phi input ignored\n");
}

static void t_cond_const_width(void) {
    /*   An i1 holds one bit. The builder stores whatever 64-bit number it is given, so a constant
     *   typed i1 may carry bits above the first, and the value is the LOW BIT: 2 and -2 and 0x100 are
     *   0, 3 and -1 and 0x101 are 1. The branch must follow that bit, not "the number is non-zero".
     *     b0: branch (i1 K) -> b1 if 1, b2 if 0                                                    */
    static const struct { int64_t k; int taken; } cases[] = {
        { 0, 0 }, { 1, 1 }, { 2, 0 }, { 3, 1 }, { -1, 1 }, { -2, 0 }, { 0x100, 0 }, { 0x101, 1 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        fn_t x; fn_init(&x, "cond_width");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        val_t k = ci(&x.bld, T1, cases[i].k);
        cbae_cir_branch(&x.bld, k, b1, b2, 0);
        ret(&x, b1); ret(&x, b2);

        cpx_t c; cpx_build(&c, &x);
        const int taken = cases[i].taken;
        expect_const(&c, "the condition read at its own width", k, (uint64_t)taken);
        expect_block(&c, "true target", 1, taken != 0);
        expect_block(&c, "false target", 2, taken == 0);
        expect_edge(&c, "0->1", 0, 1, taken != 0);
        expect_edge(&c, "0->2", 0, 2, taken == 0);
        cpx_free(&c); fn_done(&x);
    }
    printf("  [PASS] an i1 constant is its low bit: a branch on 2 goes false, on 3 goes true\n");
}

static void t_cond_chain(void) {
    /*   b0: k = 1 ^ 1 = 0 (i1) ; branch k, b1, b2           -> only b2
     *   b1 (dead): jump b4
     *   b2: n = not 0 = 1 (i1) ; branch n, b3, b4            -> only b3, so the edge 2->4 is closed
     *   b3: jump b4
     *   b4: ph = phi [1, b1] [2, b2] [3, b3]                 -> 3 (only the edge from b3 is open)  */
    fn_t x; fn_init(&x, "cond_chain");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_block_t *b3 = fn_block(&x, 0x1030), *b4 = fn_block(&x, 0x1040);
    cbae_cir_builder_t *b = &x.bld;
    val_t k = bin(b, CIR_OP_XOR, ci(b, T1, 1), ci(b, T1, 1), T1);
    cbae_cir_branch(b, k, b1, b2, 0);
    fn_at(&x, b1); cbae_cir_jump(&x.bld, b4, 0);
    fn_at(&x, b2);
    val_t n = un(&x.bld, CIR_OP_NOT, ci(&x.bld, T1, 0), T1);
    cbae_cir_branch(&x.bld, n, b3, b4, 0);
    fn_at(&x, b3); cbae_cir_jump(&x.bld, b4, 0);
    val_t ph = phi(&x, b4, T64);
    ret(&x, b4);
    incoming(&x, ph, ci(&x.bld, T64, 1), b1);
    incoming(&x, ph, ci(&x.bld, T64, 2), b2);
    incoming(&x, ph, ci(&x.bld, T64, 3), b3);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "k", k, 0);
    expect_const(&c, "n", n, 1);
    expect_block(&c, "b1", 1, false);
    expect_block(&c, "b2", 2, true);
    expect_block(&c, "b3", 3, true);
    expect_block(&c, "b4", 4, true);
    expect_edge(&c, "2->3", 2, 3, true);
    expect_edge(&c, "2->4 folded away", 2, 4, false);
    expect_edge(&c, "1->4 from a dead block", 1, 4, false);
    expect_edge(&c, "3->4", 3, 4, true);
    expect_const(&c, "phi sees only b3", ph, 3);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] folded branches chain: a block entered only through folded edges stays dead\n");
}

static void t_cond_from_identity(void) {
    /*   b0: p, q = params ; cmp = cmp p, q (unknown i1)
     *       d = cmp AND 0 = 0 ; branch d, b1, b2             -> only b2
     *       e = cmp OR 1 = 1 ; branch e, b3, b4  (in b2)     -> only b3
     *   The comparison itself is never folded, but an identity can make a condition constant.  */
    fn_t x; fn_init(&x, "cond_identity");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_block_t *b3 = fn_block(&x, 0x1030), *b4 = fn_block(&x, 0x1040);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX), q = cbae_cir_param(b, CBAE_REG_RCX);
    val_t cmp = bin(b, CIR_OP_CMP, p, q, T1);
    val_t d = bin(b, CIR_OP_AND, cmp, ci(b, T1, 0), T1);
    cbae_cir_branch(b, d, b1, b2, 0);
    ret(&x, b1);
    fn_at(&x, b2);
    val_t e = bin(&x.bld, CIR_OP_OR, cmp, ci(&x.bld, T1, 1), T1);
    cbae_cir_branch(&x.bld, e, b3, b4, 0);
    ret(&x, b3);
    ret(&x, b4);

    cpx_t c; cpx_build(&c, &x);
    expect_varying(&c, "the comparison", cmp);
    expect_const(&c, "cmp & 0", d, 0);
    expect_const(&c, "cmp | 1", e, 1);
    expect_block(&c, "b1", 1, false);
    expect_block(&c, "b2", 2, true);
    expect_block(&c, "b3", 3, true);
    expect_block(&c, "b4", 4, false);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] an identity can make a condition constant even though the comparison never is\n");
}

static void t_cond_not_folded(void) {
    /*   Both edges stay open when the condition is
     *     - an unknown i1 (a comparison),
     *     - a comparison of two constants (CIR records no predicate: 5 == 5 and 5 < 3 look alike),
     *     - a constant that is not an i1 (i64 1: how a wider condition is read is not said),
     *   and a branch whose two targets are one block keeps its single edge whatever the condition. */
    for (int kind = 0; kind < 4; kind++) {
        fn_t x; fn_init(&x, "cond_open");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        val_t cond;
        switch (kind) {
            case 0:  cond = bin(b, CIR_OP_CMP, p, ci(b, T64, 0), T1); break;
            case 1:  cond = bin(b, CIR_OP_CMP, ci(b, T64, 5), ci(b, T64, 5), T1); break;
            case 2:  cond = ci(b, T64, 1); break;
            default: cond = ci(b, T1, 0); break;
        }
        cbae_cir_branch(b, cond, b1, kind == 3 ? b1 : b2, 0);
        ret(&x, b1);
        if (kind != 3) ret(&x, b2);

        cpx_t c; cpx_build(&c, &x);
        expect_block(&c, "b1", 1, true);
        if (kind != 3) {
            expect_block(&c, "b2", 2, true);
            expect_edge(&c, "0->2", 0, 2, true);
        }
        expect_edge(&c, "0->1", 0, 1, true);
        cpx_free(&c); fn_done(&x);
    }
    printf("  [PASS] comparisons, non-i1 constants and one-target branches keep every edge open\n");
}

static void t_unreachable_blocks(void) {
    /*   b0: jump b1
     *   b1: ph = phi [5, b0] [v, b2] -> 5 ; r = ph + 1 -> 6 ; return
     *   b2 (nothing enters it): v = 1 + 2 ; jump b1          -> v is UNREACHED, its edge ignored
     *   b3 (nothing enters it, no edges): u = 4 + 4 ; return -> UNREACHED
     *   Executable: 0, 1. Edge 2->1 is not (its source is dead).                                  */
    fn_t x; fn_init(&x, "unreachable");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_jump(b, b1, 0);
    fn_at(&x, b2);
    val_t v = bin(&x.bld, CIR_OP_ADD, ci(&x.bld, T64, 1), ci(&x.bld, T64, 2), T64);
    cbae_cir_jump(&x.bld, b1, 0);
    fn_at(&x, b3);
    val_t u = bin(&x.bld, CIR_OP_ADD, ci(&x.bld, T64, 4), ci(&x.bld, T64, 4), T64);
    cbae_cir_return(&x.bld, u, 0);
    val_t ph = phi(&x, b1, T64);
    fn_at(&x, b1);
    val_t r = bin(&x.bld, CIR_OP_ADD, ph, ci(&x.bld, T64, 1), T64);
    cbae_cir_return(&x.bld, r, 0);
    incoming(&x, ph, ci(&x.bld, T64, 5), x.b0);
    incoming(&x, ph, v, b2);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "phi", ph, 5);
    expect_const(&c, "r", r, 6);
    expect_unreached(&c, "value in a block nothing enters", v);
    expect_unreached(&c, "value in an isolated block", u);
    expect_block(&c, "b0", 0, true);
    expect_block(&c, "b1", 1, true);
    expect_block(&c, "b2", 2, false);
    expect_block(&c, "b3", 3, false);
    expect_edge(&c, "0->1", 0, 1, true);
    expect_edge(&c, "2->1 from a dead block", 2, 1, false);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] blocks the entry cannot reach are not executable and feed nothing\n");
}

static void t_fallthrough(void) {
    /*   b0: a = 1 + 2 = 3 ; r = call f ; (no terminator: the call falls through, edge 0->1)
     *   b1: s = a + 1 = 4 ; t = r + 1 -> VARYING ; return
     *   The edge of a block without a terminator is executable.                               */
    fn_t x; fn_init(&x, "fallthrough");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010);
    cbae_cir_builder_t *b = &x.bld;
    val_t a = bin(b, CIR_OP_ADD, ci(b, T64, 1), ci(b, T64, 2), T64);
    val_t r = cbae_cir_call(b, "f", NULL, 0, T64, 0);
    assert(r);
    assert(cbae_cir_block_add_edge(x.b0, b1) == CBAE_OK);
    fn_at(&x, b1);
    val_t s = bin(&x.bld, CIR_OP_ADD, a, ci(&x.bld, T64, 1), T64);
    val_t t = bin(&x.bld, CIR_OP_ADD, r, ci(&x.bld, T64, 1), T64);
    cbae_cir_return(&x.bld, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "a", a, 3);
    expect_varying(&c, "call result", r);
    expect_const(&c, "s", s, 4);
    expect_varying(&c, "t", t);
    expect_block(&c, "b1", 1, true);
    expect_edge(&c, "fallthrough", 0, 1, true);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] a block with no terminator opens its fallthrough edge\n");
}

/* ── Malformed instructions ───────────────────────────────────────────── */

static void t_malformed(void) {
    /*   CIR may hold instructions the builder does not forbid but that mean nothing: the wrong
     *   number of operands, an operand slot left empty, a result of void type. The analysis must
     *   not read past what is there and must not invent a value for them: every result below is
     *   unknown (VARYING) -- the checks that make it so are the ones this test pins.
     *     add / shl with 1 operand, 3 operands, a NULL first or second operand
     *     not / copy with 2 operands, with a NULL operand
     *     add / copy / not / shl / phi whose result type was hand-edited to void: no width, so no value
     *     a void-typed constant has no value
     *   A void-typed instruction made through the builder has no result value at all (the builder
     *   returns NULL); it is still in the block, and the analysis must walk past it.
     *   One phi has a second incoming from a block that does not lead to it, and one from a block
     *   that does not exist: neither is an edge, so neither counts.                              */
    fn_t x; fn_init(&x, "malformed");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_builder_t *b = &x.bld;
    val_t c5 = ci(b, T64, 5), c7 = ci(b, T64, 7), c9 = ci(b, T64, 9);
    val_t one_op[1] = { c5 }, two_ops[2] = { c5, c7 }, three_ops[3] = { c5, c7, c5 };
    val_t add1  = cbae_cir_emit(b, CIR_OP_ADD, T64, 0, one_op, 1);
    val_t add1s = cbae_cir_emit(b, CIR_OP_ADD, T64, 0, one_op, 1);       /* a stale operand beyond the count */
    k_def(add1s)->operands[1] = c7;
    val_t add0  = cbae_cir_emit(b, CIR_OP_ADD, T64, 0, NULL, 0);
    val_t add3  = cbae_cir_emit(b, CIR_OP_ADD, T64, 0, three_ops, 3);
    val_t addna = cbae_cir_emit(b, CIR_OP_ADD, T64, 0, two_ops, 2);      /* the builder refuses a NULL operand: it is put in afterwards */
    k_def(addna)->operands[0] = NULL;
    val_t addnb = cbae_cir_emit(b, CIR_OP_ADD, T64, 0, two_ops, 2);
    k_def(addnb)->operands[1] = NULL;
    val_t shl1  = cbae_cir_emit(b, CIR_OP_SHL, T64, 0, one_op, 1);
    val_t shl3  = cbae_cir_emit(b, CIR_OP_SHL, T64, 0, three_ops, 3);
    val_t shlna = cbae_cir_emit(b, CIR_OP_SHL, T64, 0, two_ops, 2);
    k_def(shlna)->operands[0] = NULL;
    val_t shlnb = cbae_cir_emit(b, CIR_OP_SHL, T64, 0, two_ops, 2);
    k_def(shlnb)->operands[1] = NULL;
    val_t not2  = cbae_cir_emit(b, CIR_OP_NOT, T64, 0, two_ops, 2);
    val_t notn  = cbae_cir_emit(b, CIR_OP_NOT, T64, 0, one_op, 1);
    k_def(notn)->operands[0] = NULL;
    val_t cpy2  = cbae_cir_emit(b, CIR_OP_COPY, T64, 0, two_ops, 2);
    val_t cpyn  = cbae_cir_emit(b, CIR_OP_COPY, T64, 0, one_op, 1);
    k_def(cpyn)->operands[0] = NULL;

    /* results hand-edited to void after the fact */
    val_t vadd = bin(b, CIR_OP_ADD, c5, c7, T64);
    val_t vcpy = un(b, CIR_OP_COPY, c5, T64);
    val_t vnot = un(b, CIR_OP_NOT, c5, T64);
    val_t vshl = bin(b, CIR_OP_SHL, c5, c7, T64);
    vadd->type = vcpy->type = vnot->type = vshl->type = cir_type_void();

    /* void-typed instructions the builder gives no result to */
    const uint32_t before = x.b0->instruction_count;
    assert(cbae_cir_emit(b, CIR_OP_ADD, cir_type_void(), 0, two_ops, 2) == NULL);
    assert(cbae_cir_emit(b, CIR_OP_COPY, cir_type_void(), 0, one_op, 1) == NULL);
    assert(cbae_cir_emit(b, CIR_OP_NOT, cir_type_void(), 0, one_op, 1) == NULL);
    assert(cbae_cir_emit(b, CIR_OP_SHL, cir_type_void(), 0, two_ops, 2) == NULL);
    assert(x.b0->instruction_count == before + 4);          /* all four really are in the block */
    val_t vconst = ci(b, T64, 5);                            /* (the builder refuses a void constant) */
    vconst->type = cir_type_void();
    val_t after = bin(b, CIR_OP_ADD, c5, c7, T64);           /* evaluated after all of the above */

    cbae_cir_emit(b, CIR_OP_BRANCH, cir_type_void(), 0, NULL, 0);     /* no condition at all */
    k_last(b)->branch_true_block = b1->id;
    k_last(b)->branch_false_block = b2->id;
    k_last(b)->operands[0] = ci(b, T1, 0);                  /* ... whatever stale value sits in slot 0 */
    assert(cbae_cir_block_add_edge(x.b0, b1) == CBAE_OK && cbae_cir_block_add_edge(x.b0, b2) == CBAE_OK);

    /* b1: a phi from b0 (5), a phi from b0 plus a block that does not lead here (b2) and one that
     *     does not exist (99); a void-typed phi */
    val_t ph    = phi(&x, b1, T64);
    val_t phvd  = phi(&x, b1, T64);
    incoming(&x, ph, c5, x.b0);
    incoming(&x, ph, c9, b2);                                              /* b2 has no edge to b1 */
    assert(cbae_cir_phi_add_incoming(x.f, ph->u.def_insn, c9, x.b0->id) == CBAE_OK);
    ph->u.def_insn->phi_incoming_blocks[ph->u.def_insn->phi_incoming_count - 1] = 99;   /* no block 99 (the builder would not add it) */
    incoming(&x, phvd, c5, x.b0);
    phvd->type = cir_type_void();
    ret(&x, b1);
    ret(&x, b2);
    b1->successors[b1->successor_count++] = 99;               /* an edge to a block that does not exist */
    assert(add1 && add1s && add0 && add3 && addna && addnb && shl1 && shl3 && shlna && shlnb && not2 && notn &&
           cpy2 && cpyn && vadd && vcpy && vnot && vshl && vconst && after && ph && phvd);

    cpx_t c; cpx_build_unchecked(&c, x.f);
    expect_varying(&c, "add with one operand", add1);
    expect_varying(&c, "add with one operand and a stale second", add1s);
    expect_varying(&c, "add with none", add0);
    expect_varying(&c, "add with three operands", add3);
    expect_varying(&c, "add with a NULL first operand", addna);
    expect_varying(&c, "add with a NULL second operand", addnb);
    expect_varying(&c, "shl with one operand", shl1);
    expect_varying(&c, "shl with three operands", shl3);
    expect_varying(&c, "shl with a NULL first operand", shlna);
    expect_varying(&c, "shl with a NULL second operand", shlnb);
    expect_varying(&c, "not with two operands", not2);
    expect_varying(&c, "not with a NULL operand", notn);
    expect_varying(&c, "copy with two operands", cpy2);
    expect_varying(&c, "copy with a NULL operand", cpyn);
    expect_varying(&c, "add edited to void", vadd);
    expect_varying(&c, "copy edited to void", vcpy);
    expect_varying(&c, "not edited to void", vnot);
    expect_varying(&c, "shl edited to void", vshl);
    expect_varying(&c, "phi edited to void", phvd);
    expect_varying(&c, "void-typed constant", vconst);
    expect_const(&c, "an add after the malformed instructions", after, 12);
    expect_block(&c, "operand-less branch, true side", 1, true);
    expect_block(&c, "operand-less branch, false side", 2, true);
    expect_edge(&c, "operand-less branch, true edge", 0, 1, true);
    expect_edge(&c, "operand-less branch, false edge", 0, 2, true);
    expect_const(&c, "a phi ignores incomings from blocks that do not lead to it", ph, 5);
    expect_edge(&c, "no such edge", 2, 1, false);
    expect_edge(&c, "no such block", 99, 1, false);
    expect_block(&c, "no block 99", 99, false);               /* b1's edge to it opened nothing, harmlessly */
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] malformed instructions (operand counts, NULL operands, void types) are unknown, never invented\n");
}

static void t_branch_shapes(void) {
    /*   Only the LAST instruction of a block ends it, and a branch means what its condition says
     *   only when its target is one of the block's successors.
     *     b0: BRANCH(true -> b1 / false -> b2)       not last, so it decides nothing
     *         BRANCH(true -> b2 / false -> b1)       last: condition true selects b2 alone
     *         => b2 executable, b1 NOT
     *     b2: BRANCH(true -> b3 / false -> b4) with the true target edited to a block that is not
     *         a successor: the branch cannot be followed, so both edges stay open (b3, b4)
     *     b4: BRANCH on a void-typed constant 1 (-> b5 / b6): no i1, so both edges open
     *     b6: BRANCH on a value defined only in the dead block b9 (-> b7 / b8): the condition is
     *         UNREACHED, no execution has produced it, so no edge opens and b7, b8 stay dead   */
    fn_t x; fn_init(&x, "branch_shapes");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_block_t *b3 = fn_block(&x, 0x1030), *b4 = fn_block(&x, 0x1040);
    cbae_cir_block_t *b5 = fn_block(&x, 0x1050), *b6 = fn_block(&x, 0x1060);
    cbae_cir_block_t *b7 = fn_block(&x, 0x1070), *b8 = fn_block(&x, 0x1080), *b9 = fn_block(&x, 0x1090);
    cbae_cir_builder_t *b = &x.bld;
    val_t t = ci(b, T1, 1);
    cbae_cir_branch(b, t, b1, b2, 0);
    cbae_cir_branch(b, t, b2, b1, 0);                       /* same two edges (the builder dedups) */
    assert(x.b0->successor_count == 2 && x.b0->instruction_count == 2);
    fn_at(&x, b2);
    cbae_cir_branch(&x.bld, ci(&x.bld, T1, 1), b3, b4, 0);
    k_last(&x.bld)->branch_true_block = 77;                 /* not a successor of b2 */
    ret(&x, b1); ret(&x, b3);
    fn_at(&x, b4);
    val_t void_cond = ci(&x.bld, T1, 1);
    void_cond->type = cir_type_void();                      /* a condition with no width */
    cbae_cir_branch(&x.bld, void_cond, b5, b6, 0);
    ret(&x, b5);
    fn_at(&x, b9);                                          /* dead: nothing leads here */
    val_t dead = bin(&x.bld, CIR_OP_CMP, ci(&x.bld, T64, 1), ci(&x.bld, T64, 2), T1);
    cbae_cir_return(&x.bld, NULL, 0);
    fn_at(&x, b6);
    cbae_cir_branch(&x.bld, dead, b7, b8, 0);
    ret(&x, b7); ret(&x, b8);

    cpx_t c; cpx_build_unchecked(&c, x.f);
    expect_block(&c, "b0", 0, true);
    expect_block(&c, "selected by the last branch", 2, true);
    expect_block(&c, "selected only by a branch that is not last", 1, false);
    expect_edge(&c, "b0 -> b2", 0, 2, true);
    expect_edge(&c, "b0 -> b1", 0, 1, false);
    expect_block(&c, "b3, behind an inconsistent branch", 3, true);
    expect_block(&c, "b4, behind an inconsistent branch", 4, true);
    expect_edge(&c, "b2 -> b3", 2, 3, true);
    expect_edge(&c, "b2 -> b4", 2, 4, true);
    expect_block(&c, "b5, behind a void-typed constant condition", 5, true);
    expect_block(&c, "b6, behind a void-typed constant condition", 6, true);
    expect_block(&c, "b9, nothing leads here", 9, false);
    expect_unreached(&c, "a value defined in a dead block", dead);
    expect_block(&c, "b7, behind a condition no execution has produced", 7, false);
    expect_block(&c, "b8, behind a condition no execution has produced", 8, false);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] only a last instruction ends a block; odd branches keep every edge, an undefined condition none\n");
}

static void t_foreign_result(void) {
    /*   An instruction whose RESULT is a value of another function (use-def scans operands, not
     *   results, so it does not notice): the analysis must not write that value's id into its own
     *   tables. Function x has k = 2 + 3 = 5 with id R; function y has a value with the same id R
     *   (built in the same order), and another with an id past the end of x's tables. One of x's
     *   adds is given each of them as its result. k must still be 5 afterwards, and nothing may
     *   be written out of range (the Valgrind run of this test is what proves that half).       */
    fn_t x; fn_init(&x, "own");
    cbae_cir_builder_t *b = &x.bld;
    val_t k = bin(b, CIR_OP_ADD, ci(b, T64, 2), ci(b, T64, 3), T64);           /* two constants, then k: id 2 */
    val_t victim1 = bin(b, CIR_OP_ADD, ci(b, T64, 1), ci(b, T64, 1), T64);
    val_t victim2 = bin(b, CIR_OP_ADD, ci(b, T64, 4), ci(b, T64, 4), T64);
    cbae_cir_return(b, NULL, 0);

    fn_t y; fn_init(&y, "foreign");
    cbae_cir_builder_t *by = &y.bld;
    val_t yk = bin(by, CIR_OP_ADD, ci(by, T64, 20), ci(by, T64, 30), T64);     /* same shape, so also id 2 */
    assert(yk->id == k->id);
    val_t yfar = yk;
    for (int i = 0; i < 40; i++) yfar = bin(by, CIR_OP_ADD, yfar, ci(by, T64, 1), T64);
    assert(yfar->id >= x.f->next_value_id);
    cbae_cir_return(by, NULL, 0);

    victim1->u.def_insn->result = yk;                       /* the add of 1+1 now "defines" y's value  */
    victim2->u.def_insn->result = yfar;                     /* and the add of 4+4 one far out of range */

    cpx_t c; cpx_build_unchecked(&c, x.f);
    expect_const(&c, "k is untouched by a foreign result with its id", k, 5);
    expect_unreached(&c, "the orphaned result of victim 1 is never defined", victim1);
    expect_unreached(&c, "the orphaned result of victim 2 is never defined", victim2);
    expect_varying(&c, "the foreign value itself", yk);
    expect_varying(&c, "the far foreign value", yfar);
    cpx_free(&c);
    fn_done(&y); fn_done(&x);
    printf("  [PASS] an instruction whose result belongs to another function is skipped, nothing is written out of range\n");
}

/* ── What is never folded ─────────────────────────────────────────────── */

static void t_never_folded(void) {
    /*   Every one of these results is unknown, whatever the operands:
     *   load, call, api call, cmp of equal constants, test, div of constants, lea, an MMIO read,
     *   a parameter, and the conflated parameter.                                             */
    fn_t x; fn_init(&x, "varying");
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX), o = cbae_cir_param(b, CBAE_REG_OTHER);
    val_t c5 = ci(b, T64, 5), c2 = ci(b, T64, 2);
    val_t ld = k_load(b, ci(b, T64, 0x2000));
    val_t call = cbae_cir_call(b, "f", NULL, 0, T64, 0);
    val_t api = cbae_cir_emit(b, CIR_OP_API_CALL, T64, 0, NULL, 0);
    val_t cmp = bin(b, CIR_OP_CMP, c5, c5, T1), tst = bin(b, CIR_OP_TEST, c5, c5, T1);
    val_t div = bin(b, CIR_OP_DIV, ci(b, T64, 10), c2, T64);
    val_t lea = un(b, CIR_OP_LEA, c5, T64);
    val_t mmio = un(b, CIR_OP_MMIO_READ, c5, T64);
    val_t user = bin(b, CIR_OP_ADD, ld, c5, T64);
    assert(call && api);
    cbae_cir_return(b, NULL, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_varying(&c, "load", ld);
    expect_varying(&c, "call", call);
    expect_varying(&c, "api call", api);
    expect_varying(&c, "cmp of equal constants", cmp);
    expect_varying(&c, "test", tst);
    expect_varying(&c, "div of constants", div);
    expect_varying(&c, "lea", lea);
    expect_varying(&c, "mmio read", mmio);
    expect_varying(&c, "a parameter", p);
    expect_varying(&c, "the conflated parameter", o);
    expect_varying(&c, "an arithmetic user of a load", user);
    cpx_free(&c); fn_done(&x);
    printf("  [PASS] loads, calls, comparisons, division and the rest are never folded\n");
}

/* ── Lookups and errors ───────────────────────────────────────────────── */

static void t_lookups(void) {
    /*   A constant is answered directly whichever function it came from (it means the same
     *   everywhere); an instruction result of another function, a parameter, NULL: VARYING.
     *   Unknown block ids and non-edges are false, a null analysis answers false/VARYING.      */
    fn_t x; fn_init(&x, "lookups");
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    val_t a = bin(b, CIR_OP_ADD, ci(b, T64, 1), ci(b, T64, 2), T64);
    cbae_cir_return(b, a, 0);

    fn_t y; fn_init(&y, "other_fn");
    cbae_cir_builder_t *by = &y.bld;
    val_t ya = bin(by, CIR_OP_ADD, ci(by, T64, 7), ci(by, T64, 8), T64);   /* id may equal a's */
    val_t yk = ci(by, T32, -2);
    cbae_cir_return(by, ya, 0);

    cpx_t c; cpx_build(&c, &x);
    expect_const(&c, "own result", a, 3);
    expect_varying(&c, "parameter", p);
    expect_varying(&c, "another function's instruction result", ya);
    expect_const(&c, "another function's constant", yk, 0xFFFFFFFEu);
    assert(cbae_const_prop_value(&c.cp, NULL).kind == CBAE_CP_VARYING);
    assert(cbae_const_prop_value(NULL, a).kind == CBAE_CP_VARYING);
    assert(!cbae_const_prop_is_constant(NULL, a, NULL));
    assert(!cbae_const_prop_is_constant(&c.cp, NULL, NULL));
    assert(!cbae_const_prop_block_executable(&c.cp, 1));
    assert(!cbae_const_prop_block_executable(&c.cp, UINT32_MAX));
    assert(!cbae_const_prop_block_executable(NULL, 0));
    assert(cbae_const_prop_block_executable(&c.cp, 0));
    assert(!cbae_const_prop_edge_executable(&c.cp, 0, 1));
    assert(!cbae_const_prop_edge_executable(&c.cp, UINT32_MAX, 0));
    assert(!cbae_const_prop_edge_executable(NULL, 0, 0));
    cpx_free(&c);
    fn_done(&y); fn_done(&x);
    printf("  [PASS] lookups: foreign values, null arguments and unknown ids answer conservatively\n");
}

static void t_errors(void) {
    cbae_const_prop_t out;
    cbae_use_def_t ud;
    memset(&ud, 0, sizeof ud);

    /* null output, null index */
    assert(cbae_const_prop_run(&ud, NULL) == CBAE_ERR_INVALID);
    memset(&out, 0xAB, sizeof out);
    assert(cbae_const_prop_run(NULL, &out) == CBAE_ERR_INVALID);
    assert(out.impl == NULL && out.ud == NULL);                  /* nothing to destroy */
    memset(&out, 0xAB, sizeof out);
    assert(cbae_const_prop_run(&ud, &out) == CBAE_ERR_INVALID);  /* an index of nothing */
    assert(out.impl == NULL);

    /* a function with no blocks */
    cbae_arena_t arena;
    cbae_cir_function_t *f = NULL;
    assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);
    assert(cbae_cir_function_create(&arena, 0x1000, "empty", &f) == CBAE_OK);
    assert(cbae_use_def_build(f, &ud) == CBAE_OK);
    memset(&out, 0xAB, sizeof out);
    assert(cbae_const_prop_run(&ud, &out) == CBAE_ERR_INVALID);
    assert(out.impl == NULL);
    cbae_use_def_destroy(&ud);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);

    /* destroying nothing, or twice, is harmless */
    cbae_const_prop_destroy(NULL);
    memset(&out, 0, sizeof out);
    cbae_const_prop_destroy(&out);

    fn_t x; fn_init(&x, "twice");
    val_t k5 = ci(&x.bld, T64, 5);
    cbae_cir_return(&x.bld, NULL, 0);
    cpx_t c; cpx_build(&c, &x);
    assert(cbae_const_prop_value(&c.cp, k5).kind == CBAE_CP_CONSTANT);
    cbae_const_prop_destroy(&c.cp);
    cbae_const_prop_destroy(&c.cp);
    assert(c.cp.impl == NULL);
    assert(cbae_const_prop_value(&c.cp, NULL).kind == CBAE_CP_VARYING);
    assert(cbae_const_prop_value(&c.cp, k5).kind == CBAE_CP_VARYING);        /* nothing is known any more */
    assert(!cbae_const_prop_is_constant(&c.cp, k5, NULL));
    assert(!cbae_const_prop_block_executable(&c.cp, 0));
    assert(!cbae_const_prop_edge_executable(&c.cp, 0, 0));
    cbae_use_def_destroy(&c.ud);
    fn_done(&x);
    printf("  [PASS] bad arguments and double destroy are handled\n");
}

/* ── Size ─────────────────────────────────────────────────────────────── */

static void t_fanin_duplicates(void) {
    /*   One value used by 4 phis with 150 incomings each (600 uses of it). When it first gets a
     *   value every use is a candidate to re-evaluate, but each PHI must be queued once, not once
     *   per incoming: the instruction stack has room for one entry per instruction (156 here), and
     *   600 entries would run past its end. Memory safety is what the Valgrind run of this test
     *   proves; the values are checked here.
     *     l_0 .. l_149: l_i branches to J or to l_(i+1) on the same unknown condition (the last
     *     one jumps to J), so J has 150 predecessors.
     *     J: phi_k = phi [v from l_0] ... [v from l_149]      for k = 0..3, with v = 3 + 4      */
    enum { M = 150, K = 4 };
    fn_t x; fn_init_sized(&x, "fanin", 8u << 20);
    cbae_cir_block_t *l[M];
    l[0] = x.b0;
    for (int i = 1; i < M; i++) l[i] = fn_block(&x, 0x2000 + 0x10 * (uint32_t)i);
    cbae_cir_block_t *J = fn_block(&x, 0x9000);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    val_t v = bin(b, CIR_OP_ADD, ci(b, T64, 3), ci(b, T64, 4), T64);
    val_t cc = bin(b, CIR_OP_CMP, p, ci(b, T64, 0), T1);
    for (int i = 0; i < M; i++) {
        fn_at(&x, l[i]);
        if (i + 1 < M) cbae_cir_branch(&x.bld, cc, J, l[i + 1], 0);
        else           cbae_cir_jump(&x.bld, J, 0);
    }
    val_t ph[K];
    for (int k = 0; k < K; k++) {
        ph[k] = phi(&x, J, T64);
        for (int i = 0; i < M; i++) incoming(&x, ph[k], v, l[i]);
    }
    ret(&x, J);

    cpx_t cx; cpx_build(&cx, &x);
    expect_const(&cx, "v", v, 7);
    for (int k = 0; k < K; k++) expect_const(&cx, "a phi of 150 equal incomings", ph[k], 7);
    expect_block(&cx, "J", J->id, true);
    cpx_free(&cx); fn_done(&x);
    printf("  [PASS] a value with many uses queues each user once (no overrun of the instruction stack)\n");
}

static void t_long_chain(void) {
    /*   One block, 100,000 additions of 1 to a running total: value k is k.            */
    enum { N = 100000 };
    fn_t x; fn_init_sized(&x, "chain", 96u << 20);
    cbae_cir_builder_t *b = &x.bld;
    val_t one = ci(b, T64, 1);
    val_t *vals = malloc((N + 1) * sizeof *vals);
    assert(vals);
    vals[0] = ci(b, T64, 0);
    for (int i = 1; i <= N; i++) vals[i] = bin(b, CIR_OP_ADD, vals[i - 1], one, T64);
    cbae_cir_return(b, vals[N], 0);

    cpx_t c; cpx_build(&c, &x);
    for (int i = 0; i <= N; i += 997) expect_const(&c, "chain", vals[i], (uint64_t)i);
    expect_const(&c, "chain end", vals[N], N);
    cpx_free(&c);
    free(vals);
    fn_done(&x);
    printf("  [PASS] a chain of 100,000 dependent additions\n");
}

static void t_many_phis(void) {
    /*   One loop, 3,000 induction variables (VARYING) and 3,000 invariants (CONSTANT 7):
     *   each value falls at most twice, so this is linear, and the answers are exact.        */
    enum { K = 3000 };
    fn_t x; fn_init_sized(&x, "many_phis", 96u << 20);
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_jump(b, b1, 0);

    val_t *ind = malloc(K * sizeof *ind), *inv = malloc(K * sizeof *inv), *upd = malloc(K * sizeof *upd);
    assert(ind && inv && upd);
    for (int i = 0; i < K; i++) { ind[i] = phi(&x, b1, T64); inv[i] = phi(&x, b1, T64); }
    fn_at(&x, b1);
    val_t c = bin(&x.bld, CIR_OP_CMP, p, ci(&x.bld, T64, 0), T1);
    cbae_cir_branch(&x.bld, c, b2, b3, 0);
    fn_at(&x, b2);
    for (int i = 0; i < K; i++) upd[i] = bin(&x.bld, CIR_OP_ADD, ind[i], ci(&x.bld, T64, 1), T64);
    cbae_cir_jump(&x.bld, b1, 0);
    ret(&x, b3);
    for (int i = 0; i < K; i++) {
        incoming(&x, ind[i], ci(&x.bld, T64, i), x.b0);  incoming(&x, ind[i], upd[i], b2);
        incoming(&x, inv[i], ci(&x.bld, T64, 7), x.b0);  incoming(&x, inv[i], inv[i], b2);
    }

    cpx_t cx; cpx_build(&cx, &x);
    for (int i = 0; i < K; i++) {
        expect_varying(&cx, "induction", ind[i]);
        expect_varying(&cx, "update", upd[i]);
        expect_const(&cx, "invariant", inv[i], 7);
    }
    cpx_free(&cx);
    free(ind); free(inv); free(upd);
    fn_done(&x);
    printf("  [PASS] 3,000 induction variables and 3,000 invariant phis in one loop\n");
}

/* ── Lifted machine code ──────────────────────────────────────────────── */

static void t_lifted(void) {
    {   /*   0x7000: 48 C7 C0 10 00 00 00   mov rax, 0x10
         *   0x7007: 48 83 C0 20            add rax, 0x20      = 0x30
         *   0x700B: 48 C1 E0 04            shl rax, 4         = 0x300
         *   0x700F: C3                     ret                                                  */
        static const uint8_t code[] = { 0x48,0xC7,0xC0,0x10,0x00,0x00,0x00, 0x48,0x83,0xC0,0x20,
                                        0x48,0xC1,0xE0,0x04, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x7000, "consts");
        cpx_t c; cpx_build_unchecked(&c, L.func);
        const cbae_cir_instruction_t *add = lh_nth_insn(L.func, CIR_OP_ADD, 0);
        const cbae_cir_instruction_t *shl = lh_nth_insn(L.func, CIR_OP_SHL, 0);
        assert(add && shl);
        expect_const(&c, "lifted add", add->result, 0x30);
        expect_const(&c, "lifted shl", shl->result, 0x300);
        cpx_free(&c); lifted_destroy(&L);
    }
    {   /*   0x8000: 48 31 C0   xor rax, rax     -> lifted as xor of the SAME value: 0
         *   0x8003: C3         ret                                                              */
        static const uint8_t code[] = { 0x48,0x31,0xC0, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x8000, "xor64");
        cpx_t c; cpx_build_unchecked(&c, L.func);
        const cbae_cir_instruction_t *xr = lh_nth_insn(L.func, CIR_OP_XOR, 0);
        assert(xr);
        expect_const(&c, "xor rax, rax", xr->result, 0);
        cpx_free(&c); lifted_destroy(&L);
    }
    {   /*   0x8100: 31 C0      xor eax, eax     -> lifted as other ^ other (audit A-002): NOT zero
         *   The idiom is a zero on the machine, but the lifter conflates every narrow register,
         *   so the analysis must not call it one. When A-002 is fixed this becomes CONSTANT 0.  */
        static const uint8_t code[] = { 0x31,0xC0, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x8100, "xor32");
        cpx_t c; cpx_build_unchecked(&c, L.func);
        const cbae_cir_instruction_t *xr = lh_nth_insn(L.func, CIR_OP_XOR, 0);
        assert(xr);
        expect_varying(&c, "xor eax, eax (conflated register)", xr->result);
        cpx_free(&c); lifted_destroy(&L);
    }
    {   /*   0x9000: 48 C7 C0 05 00 00 00   mov rax, 5
         *   0x9007: 48 83 F8 05            cmp rax, 5
         *   0x900B: 74 07                  je 0x9014
         *   0x900D: 48 C7 C0 07 00 00 00   mov rax, 7
         *   0x9014: 48 83 C0 01            add rax, 1
         *   0x9018: C3                     ret
         *   The branch condition is a cmp (no predicate in CIR), so both edges stay open and
         *   rax at 0x9014 is phi(5, 7): unknown, and so is the add.                             */
        static const uint8_t code[] = { 0x48,0xC7,0xC0,0x05,0x00,0x00,0x00, 0x48,0x83,0xF8,0x05,
                                        0x74,0x07, 0x48,0xC7,0xC0,0x07,0x00,0x00,0x00,
                                        0x48,0x83,0xC0,0x01, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x9000, "jcc");
        cpx_t c; cpx_build_unchecked(&c, L.func);
        const cbae_cir_instruction_t *ph = lh_nth_insn(L.func, CIR_OP_PHI, 0);
        const cbae_cir_instruction_t *add = lh_nth_insn(L.func, CIR_OP_ADD, 0);
        assert(ph && add);
        expect_varying(&c, "phi(5, 7)", ph->result);
        expect_varying(&c, "add after the join", add->result);
        const uint32_t nb = (uint32_t)cbae_vector_count(&L.func->blocks);
        for (uint32_t i = 0; i < nb; i++) expect_block(&c, "lifted jcc", i, true);
        cpx_free(&c); lifted_destroy(&L);
    }
    printf("  [PASS] lifted code: constants fold, xor rax,rax is 0, xor eax,eax is not (A-002), a je on a cmp never folds\n");
}

int main(void) {
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);
    t_arith64();
    t_narrow_wrap();
    t_copy();
    t_mixed_width();
    t_shifts();
    t_identities();
    t_transient_unknown();
    t_phi_diamond();
    t_phi_last();
    t_phi_loop();
    t_order_independence();
    t_cond_branch();
    t_cond_const_width();
    t_cond_chain();
    t_cond_from_identity();
    t_cond_not_folded();
    t_unreachable_blocks();
    t_fallthrough();
    t_malformed();
    t_branch_shapes();
    t_foreign_result();
    t_never_folded();
    t_lookups();
    t_errors();
    t_fanin_duplicates();
    t_long_chain();
    t_many_phis();
    t_lifted();
    printf("All constant propagation tests passed.\n");
    return 0;
}
