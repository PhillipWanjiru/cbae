/**
 * @file test_ssa_verifier.c
 * @brief cbae_ssa_verify_function(): every rule is shown to fire on a function
 *        broken in exactly that one way, valid functions of every shape pass, and
 *        a differential fuzz checks the verdict AND the message against a
 *        dominance oracle that shares no code with the verifier.
 *
 * A verifier that accepted everything would pass every test that feeds it valid
 * functions, which is all the Phase 4 verifier was ever fed. So most of this file
 * is negative: each case builds a small function, corrupts one use through the data
 * structures directly (the builder will not let a test write most of these), and
 * compares the whole message, ids and positions included, with what the rule says.
 *
 *   - valid shapes: straight line, diamond, loop (a phi may take a value defined
 *     later in the loop), self-referential and swapping phis, far dominators;
 *   - one violation each: used before defined (earlier, and by itself), defined in a
 *     block that does not dominate (join, sibling, loop exit, loop-carried), phi
 *     incomings whose definition does not dominate the predecessor, a result nothing
 *     defines, a result named by an instruction that produces another, a result whose
 *     instruction was removed;
 *   - unreachable code: its own uses are exempt, a phi incoming from an unreachable
 *     predecessor is exempt, a value DEFINED there and used from reachable code is not;
 *   - which violation is reported first, and that a structural failure comes first;
 *   - machine code through the lifter and SSA construction: hand-assembled inputs, and
 *     what gcc emits for eight small functions at five optimisation levels
 *     (compiled_corpus.h);
 *   - random valid functions (must pass), then the same functions with uses rewired
 *     to random values and unreachable blocks grafted on, against the oracle.
 *
 * The oracle decides dominance by brute force -- a block A dominates B if B cannot be
 * reached from the entry once A is removed -- and finds each definition by scanning
 * the instructions' results. It uses neither the dominator tree, nor use-def, nor
 * the verifier's tables.
 */
#include "dataflow/ssa_verifier.h"
#include "cir_random.h"
#include "cir_test_util.h"
#include "compiled_corpus.h"
#include "lift_helpers.h"
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef cbae_cir_value_t *val_t;
typedef cbae_cir_instruction_t *ins_t;

/* ── Checks ───────────────────────────────────────────────────────────── */

static void expect_ok(const cbae_cir_function_t *f, const char *what) {
    const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(f);
    if (!vr.ok) fprintf(stderr, "FAIL [%s]: valid function rejected: %s\n", what, vr.message);
    assert(vr.ok);
    assert(vr.message[0] == '\0');
}

static void expect_exact(const cbae_cir_function_t *f, const char *what, const char *want) {
    const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(f);
    if (vr.ok || strcmp(vr.message, want) != 0)
        fprintf(stderr, "FAIL [%s]:\n  got  ok=%d '%s'\n  want ok=0 '%s'\n", what, (int)vr.ok, vr.message, want);
    assert(!vr.ok);
    assert(strcmp(vr.message, want) == 0);
}

static uint32_t pos_in(const cbae_cir_block_t *b, const cbae_cir_instruction_t *in) {
    for (uint32_t i = 0; i < b->instruction_count; i++)
        if (b->instructions[i] == in) return i;
    assert(!"instruction not in block");
    return 0;
}

/* The reasons, written out the way ssa_verifier.h states them. */
static const char *why_before(char *buf, uint32_t def_insn, uint32_t def_pos, uint32_t use_pos) {
    snprintf(buf, 160, "used before its definition: insn#%u defines it at position %u of this block, "
             "the use is at position %u", def_insn, def_pos, use_pos);
    return buf;
}
static const char *why_not_dom(char *buf, uint32_t def_insn, uint32_t def_blk, uint32_t use_blk) {
    snprintf(buf, 160, "defined by insn#%u in block%u, which does not dominate block%u", def_insn, def_blk, use_blk);
    return buf;
}
static const char *why_unreach(char *buf, uint32_t def_insn, uint32_t def_blk) {
    snprintf(buf, 160, "defined by insn#%u in block%u, which the entry cannot reach", def_insn, def_blk);
    return buf;
}

/* Operand `oi` of `use`, which sits in block `blk`, is the offender. */
static void expect_operand_bad(const cbae_cir_function_t *f, const char *what, uint32_t blk,
                               const cbae_cir_instruction_t *use, uint32_t oi, const cbae_cir_value_t *v,
                               const char *reason) {
    char want[CIR_VERIFY_MSG_MAX];
    snprintf(want, sizeof want, "block%u insn#%u: operand %u (%%v%u) is %s", blk, use->id, oi, v->id, reason);
    expect_exact(f, what, want);
}

/* Incoming `k` of phi `phi` (in block `blk`), which comes from block `from`, is the offender. */
static void expect_phi_bad(const cbae_cir_function_t *f, const char *what, uint32_t blk,
                           const cbae_cir_instruction_t *phi, uint32_t k, const cbae_cir_value_t *v,
                           uint32_t from, const char *reason) {
    char want[CIR_VERIFY_MSG_MAX];
    snprintf(want, sizeof want, "block%u insn#%u: phi incoming %u (%%v%u) from block%u is %s",
             blk, phi->id, k, v->id, from, reason);
    expect_exact(f, what, want);
}

/* ── The functions the cases start from ───────────────────────────────────
 *   base:   b0: p, q = params ; c = cmp p, 0 ; a = p + 1 ; branch c, b1, b2
 *           b1: x1 = a + 2 ; jump b3          b2: x2 = a * 3 ; jump b3
 *           b3: ph = phi [x1, b1] [x2, b2] ; r = ph + q ; ret r
 *           (positions: b0 = c 0, a 1, branch 2 | b1 = x1 0, jump 1 | b2 = x2 0, jump 1 |
 *            b3 = ph 0, r 1, ret 2)
 *   loop:   b0: p = param ; jump b1
 *           b1: iv = phi [0, b0] [next, b2] ; c = cmp iv, p ; branch c, b2, b3
 *           b2: next = iv + 1 ; jump b1
 *           b3: s = iv + p ; ret s                                                        */

typedef struct {
    fn_t x;
    cbae_cir_block_t *b1, *b2, *b3;
    val_t p, q, c, a, x1, x2, ph, r;
    ins_t br, ret;
} base_t;

static void base_build(base_t *B) {
    memset(B, 0, sizeof *B);
    fn_init(&B->x, "base");
    fn_t *x = &B->x;
    B->b1 = fn_block(x, 0x1010); B->b2 = fn_block(x, 0x1020); B->b3 = fn_block(x, 0x1030);
    cbae_cir_builder_t *b = &x->bld;
    B->p = cbae_cir_param(b, CBAE_REG_RBX);
    B->q = cbae_cir_param(b, CBAE_REG_RCX);
    B->c = cbae_cir_binop(b, CIR_OP_CMP, B->p, k_const(b, 0), cir_type_i1(), 0);
    B->a = k_add(b, B->p, k_const(b, 1));
    cbae_cir_branch(b, B->c, B->b1, B->b2, 0);
    B->br = k_last(b);

    fn_at(x, B->b1);
    B->x1 = k_add(&x->bld, B->a, k_const(&x->bld, 2));
    cbae_cir_jump(&x->bld, B->b3, 0);
    fn_at(x, B->b2);
    B->x2 = k_mul(&x->bld, B->a, k_const(&x->bld, 3));
    cbae_cir_jump(&x->bld, B->b3, 0);

    B->ph = cbae_cir_phi_create(x->f, B->b3, T64);
    assert(cbae_cir_phi_add_incoming(x->f, B->ph->u.def_insn, B->x1, B->b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, B->ph->u.def_insn, B->x2, B->b2->id) == CBAE_OK);
    fn_at(x, B->b3);
    B->r = k_add(&x->bld, B->ph, B->q);
    cbae_cir_return(&x->bld, B->r, 0);
    B->ret = k_last(&x->bld);
}

typedef struct {
    fn_t x;
    cbae_cir_block_t *b1, *b2, *b3;
    val_t p, iv, c, next, s;
    ins_t br;
} loop_t;

static void loop_build(loop_t *L) {
    memset(L, 0, sizeof *L);
    fn_init(&L->x, "loop");
    fn_t *x = &L->x;
    L->b1 = fn_block(x, 0x2010); L->b2 = fn_block(x, 0x2020); L->b3 = fn_block(x, 0x2030);
    cbae_cir_builder_t *b = &x->bld;
    L->p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_jump(b, L->b1, 0);

    L->iv = cbae_cir_phi_create(x->f, L->b1, T64);
    fn_at(x, L->b1);
    L->c = cbae_cir_binop(&x->bld, CIR_OP_CMP, L->iv, L->p, cir_type_i1(), 0);
    cbae_cir_branch(&x->bld, L->c, L->b2, L->b3, 0);
    L->br = k_last(&x->bld);
    fn_at(x, L->b2);
    L->next = k_add(&x->bld, L->iv, k_const(&x->bld, 1));
    cbae_cir_jump(&x->bld, L->b1, 0);
    fn_at(x, L->b3);
    L->s = k_add(&x->bld, L->iv, L->p);
    cbae_cir_return(&x->bld, L->s, 0);

    assert(cbae_cir_phi_add_incoming(x->f, L->iv->u.def_insn, k_const(&x->bld, 0), x->b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, L->iv->u.def_insn, L->next, L->b2->id) == CBAE_OK);
}

#define BASE_CASE(name) \
    base_t B; base_build(&B); \
    expect_ok(B.x.f, name " (before)");
#define LOOP_CASE(name) \
    loop_t L; loop_build(&L); \
    expect_ok(L.x.f, name " (before)");
#define DONE(msg) \
    fn_done(&B.x); \
    printf("  [PASS] %s\n", msg);
#define LOOP_DONE(msg) \
    fn_done(&L.x); \
    printf("  [PASS] %s\n", msg);

/* ── Valid functions ──────────────────────────────────────────────────── */

static void t_valid(void) {
    char buf[160]; (void)buf;
    {   base_t B; base_build(&B);
        expect_ok(B.x.f, "diamond with a phi");
        expect_ok(B.x.f, "diamond with a phi, asked again");               /* a pure check: the same answer twice */
        fn_done(&B.x);
    }
    {   /* a straight line: each value is used after its definition */
        fn_t x; fn_init(&x, "line");
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        val_t a = k_add(b, p, k_const(b, 1));
        val_t m = k_mul(b, a, a);
        val_t d = k_sub(b, m, p);
        cbae_cir_return(b, d, 0);
        expect_ok(x.f, "straight line");
        fn_done(&x);
    }
    {   loop_t L; loop_build(&L);
        expect_ok(L.x.f, "counted loop: the phi takes `next`, defined later in the loop body");
        fn_done(&L.x);
    }
    {   /* a self-referential phi (a loop-invariant in disguise) and a pair that swap every iteration */
        fn_t x; fn_init(&x, "phis");
        cbae_cir_block_t *b1 = fn_block(&x, 0x3010), *b2 = fn_block(&x, 0x3020), *b3 = fn_block(&x, 0x3030);
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_jump(b, b1, 0);
        val_t self = cbae_cir_phi_create(x.f, b1, T64);
        val_t pa = cbae_cir_phi_create(x.f, b1, T64);
        val_t pb = cbae_cir_phi_create(x.f, b1, T64);
        fn_at(&x, b1);
        val_t c = cbae_cir_binop(&x.bld, CIR_OP_CMP, pa, p, cir_type_i1(), 0);
        cbae_cir_branch(&x.bld, c, b2, b3, 0);
        fn_at(&x, b2);
        cbae_cir_jump(&x.bld, b1, 0);
        fn_at(&x, b3);
        val_t s = k_add(&x.bld, pa, pb);
        val_t t = k_add(&x.bld, s, self);
        cbae_cir_return(&x.bld, t, 0);
        assert(cbae_cir_phi_add_incoming(x.f, self->u.def_insn, k_const(&x.bld, 5), x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, self->u.def_insn, self, b2->id) == CBAE_OK);       /* its own value */
        assert(cbae_cir_phi_add_incoming(x.f, pa->u.def_insn, k_const(&x.bld, 1), x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, pa->u.def_insn, pb, b2->id) == CBAE_OK);           /* swap */
        assert(cbae_cir_phi_add_incoming(x.f, pb->u.def_insn, k_const(&x.bld, 2), x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, pb->u.def_insn, pa, b2->id) == CBAE_OK);
        expect_ok(x.f, "self-referential phi, and two phis that exchange their values on the back edge");
        fn_done(&x);
    }
    {   /* a chain b0 -> b1 -> b2 -> b3 -> b4: a definition reaches every use below it, however far */
        fn_t x; fn_init(&x, "chain");
        cbae_cir_block_t *bb[4];
        for (int i = 0; i < 4; i++) bb[i] = fn_block(&x, 0x4010 + 0x10 * i);
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        val_t v0 = k_add(b, p, p);
        cbae_cir_jump(b, bb[0], 0);
        fn_at(&x, bb[0]);
        val_t v1 = k_add(&x.bld, v0, p);
        cbae_cir_jump(&x.bld, bb[1], 0);
        fn_at(&x, bb[1]);
        val_t v2 = k_mul(&x.bld, v1, v0);
        cbae_cir_jump(&x.bld, bb[2], 0);
        fn_at(&x, bb[2]);
        val_t v3 = k_add(&x.bld, v2, k_add(&x.bld, v1, v0));
        cbae_cir_jump(&x.bld, bb[3], 0);
        fn_at(&x, bb[3]);
        cbae_cir_return(&x.bld, k_sub(&x.bld, v3, v0), 0);
        expect_ok(x.f, "values used several blocks below their definition");
        fn_done(&x);
    }
    {   /* a phi incoming defined by the LAST instruction of its predecessor, and by an earlier one */
        fn_t x; fn_init(&x, "pos");
        cbae_cir_block_t *b1 = fn_block(&x, 0x5010), *b2 = fn_block(&x, 0x5020), *b3 = fn_block(&x, 0x5030);
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        val_t c = cbae_cir_binop(b, CIR_OP_CMP, p, k_const(b, 0), cir_type_i1(), 0);
        cbae_cir_branch(b, c, b1, b2, 0);
        fn_at(&x, b1);
        val_t early = k_add(&x.bld, p, k_const(&x.bld, 1));
        (void)k_add(&x.bld, early, early);
        cbae_cir_jump(&x.bld, b3, 0);
        fn_at(&x, b2);
        (void)k_add(&x.bld, p, p);
        val_t last = k_mul(&x.bld, p, p);                                  /* just before the jump */
        cbae_cir_jump(&x.bld, b3, 0);
        val_t ph = cbae_cir_phi_create(x.f, b3, T64);
        assert(cbae_cir_phi_add_incoming(x.f, ph->u.def_insn, early, b1->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, ph->u.def_insn, last, b2->id) == CBAE_OK);
        fn_at(&x, b3);
        cbae_cir_return(&x.bld, ph, 0);
        expect_ok(x.f, "a phi incoming may be defined anywhere in its predecessor");
        fn_done(&x);
    }
    {   /* nothing to violate */
        cbae_arena_t arena; cbae_cir_function_t *f = NULL;
        assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);
        assert(cbae_cir_function_create(&arena, 0x1000, "empty", &f) == CBAE_OK);
        expect_ok(f, "a function with no blocks");
        cbae_cir_function_destroy(f);
        cbae_arena_destroy(&arena);

        fn_t x; fn_init(&x, "one");
        expect_ok(x.f, "one empty block");
        fn_done(&x);

        const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(NULL);
        assert(!vr.ok && strcmp(vr.message, "null function") == 0);
    }
    printf("  [PASS] valid functions of every shape pass; a null function is reported\n");
}

/* ── One violation each: operands ─────────────────────────────────────── */

static void t_before_definition(void) {
    char w[160];
    {   BASE_CASE("earlier in the block")
        k_def(B.c)->operands[0] = B.a;                                    /* the cmp (position 0) reads `a` (position 1) */
        expect_operand_bad(B.x.f, "use before def", 0, k_def(B.c), 0, B.a,
                           why_before(w, k_def(B.a)->id, pos_in(B.x.b0, k_def(B.a)), pos_in(B.x.b0, k_def(B.c))));
        DONE("an operand defined LATER in its own block is reported, with both positions") }
    {   BASE_CASE("its own result")
        k_def(B.a)->operands[0] = B.a;                                    /* a = a + 1 */
        expect_operand_bad(B.x.f, "self use", 0, k_def(B.a), 0, B.a,
                           why_before(w, k_def(B.a)->id, 1, 1));
        DONE("an instruction that uses its own result is reported") }
    {   BASE_CASE("second operand")
        k_def(B.a)->operands[1] = B.x1;                                   /* b0 reads a value from b1: not before, not dominating */
        expect_operand_bad(B.x.f, "operand index", 0, k_def(B.a), 1, B.x1,
                           why_not_dom(w, k_def(B.x1)->id, 1, 0));
        DONE("the operand index is the one that is wrong, not always the first") }
    {   BASE_CASE("branch condition")
        B.br->operands[0] = B.x1;                                         /* the terminator's operand is a use like any other */
        expect_operand_bad(B.x.f, "branch operand", 0, B.br, 0, B.x1, why_not_dom(w, k_def(B.x1)->id, 1, 0));
        DONE("a branch condition is checked") }
    {   BASE_CASE("return value")
        B.ret->operands[0] = B.x2;
        expect_operand_bad(B.x.f, "return operand", 3, B.ret, 0, B.x2, why_not_dom(w, k_def(B.x2)->id, 2, 3));
        DONE("a returned value is checked") }
}

static void t_not_dominated(void) {
    char w[160];
    {   BASE_CASE("join")
        k_def(B.r)->operands[1] = B.x1;                                   /* b1 is one of two ways into b3 */
        expect_operand_bad(B.x.f, "join", 3, k_def(B.r), 1, B.x1, why_not_dom(w, k_def(B.x1)->id, 1, 3));
        DONE("a value from one arm of a diamond, used at the join") }
    {   BASE_CASE("sibling")
        k_def(B.x2)->operands[0] = B.x1;                                  /* b2 is not below b1 */
        expect_operand_bad(B.x.f, "sibling", 2, k_def(B.x2), 0, B.x1, why_not_dom(w, k_def(B.x1)->id, 1, 2));
        DONE("a value from the other arm of a diamond") }
    {   BASE_CASE("dominator is fine")
        k_def(B.x2)->operands[0] = B.c;                                   /* c is in b0, which dominates b2 */
        expect_ok(B.x.f, "an operand from a dominating block");
        DONE("an operand from a dominating block is accepted") }
    {   LOOP_CASE("exit reads the body")
        k_def(L.s)->operands[0] = L.next;                                 /* b2 is inside the loop; b3 can be entered without it */
        expect_operand_bad(L.x.f, "loop exit", 3, k_def(L.s), 0, L.next, why_not_dom(w, k_def(L.next)->id, 2, 3));
        LOOP_DONE("a loop-body value used after the loop") }
    {   LOOP_CASE("loop carried, used directly")
        k_def(L.c)->operands[0] = L.next;                                 /* the header sees `next` only through its phi */
        expect_operand_bad(L.x.f, "loop carried", 1, k_def(L.c), 0, L.next, why_not_dom(w, k_def(L.next)->id, 2, 1));
        LOOP_DONE("a loop-carried value read in the header without going through its phi") }
    {   LOOP_CASE("header value below the loop")
        k_def(L.s)->operands[1] = L.iv;                                   /* the header dominates the exit */
        expect_ok(L.x.f, "iv, defined in the header, read in the exit");
        LOOP_DONE("a header value read in the loop exit is accepted") }
}

/* ── One violation each: phi incomings ────────────────────────────────── */

static void t_phi_incomings(void) {
    char w[160];
    {   BASE_CASE("incoming from the wrong arm")
        k_def(B.ph)->phi_incoming_values[1] = B.x1;                       /* from b2, a value that lives in b1 */
        expect_phi_bad(B.x.f, "phi incoming", 3, k_def(B.ph), 1, B.x1, 2, why_not_dom(w, k_def(B.x1)->id, 1, 2));
        DONE("a phi incoming defined in a block that does not dominate its predecessor") }
    {   BASE_CASE("incoming defined in the phi's own block")
        k_def(B.ph)->phi_incoming_values[0] = B.r;                        /* r is below the phi: not available at the end of b1 */
        expect_phi_bad(B.x.f, "phi own block", 3, k_def(B.ph), 0, B.r, 1, why_not_dom(w, k_def(B.r)->id, 3, 1));
        DONE("a phi incoming defined in the phi's own block, on a forward edge") }
    {   BASE_CASE("incoming is the phi itself")
        k_def(B.ph)->phi_incoming_values[0] = B.ph;
        expect_phi_bad(B.x.f, "phi self", 3, k_def(B.ph), 0, B.ph, 1, why_not_dom(w, k_def(B.ph)->id, 3, 1));
        DONE("a phi whose own value flows in along a forward edge") }
    {   BASE_CASE("incoming from a dominator")
        k_def(B.ph)->phi_incoming_values[0] = B.a;                        /* a is in b0, which dominates b1 */
        k_def(B.ph)->phi_incoming_values[1] = B.p;                        /* a parameter */
        expect_ok(B.x.f, "incomings from a dominator and a parameter");
        DONE("an incoming defined in a block that dominates its predecessor is accepted") }
    {   LOOP_CASE("entry incoming defined in the header")
        k_def(L.iv)->phi_incoming_values[0] = L.c;                        /* from b0, a value that lives in b1 */
        expect_phi_bad(L.x.f, "entry incoming", 1, k_def(L.iv), 0, L.c, 0, why_not_dom(w, k_def(L.c)->id, 1, 0));
        LOOP_DONE("a loop phi whose entry incoming is defined inside the loop") }
    {   LOOP_CASE("back incoming defined after the loop")
        k_def(L.iv)->phi_incoming_values[1] = L.s;                        /* from b2, a value that lives in b3 */
        expect_phi_bad(L.x.f, "back incoming", 1, k_def(L.iv), 1, L.s, 2, why_not_dom(w, k_def(L.s)->id, 3, 2));
        LOOP_DONE("a loop phi whose back-edge incoming is defined after the loop") }
    {   LOOP_CASE("back incoming is the header's own value")
        k_def(L.iv)->phi_incoming_values[1] = L.c;                        /* the header dominates the latch: fine */
        expect_ok(L.x.f, "a header value flowing round the back edge");
        LOOP_DONE("a header value flowing round the back edge is accepted") }
}

/* ── Results nothing defines ──────────────────────────────────────────── */

/* A value that looks like an instruction result, in the three ways it can be a lie. */
static void t_orphans(void) {
    char w[160]; (void)w;
    {   BASE_CASE("removed instruction")
        fn_at(&B.x, B.b2);
        val_t orphan = k_add(&B.x.bld, B.p, B.p);                        /* appended to b2 ... */
        ins_t oi = k_def(orphan);
        assert(B.b2->instructions[B.b2->instruction_count - 1] == oi);
        B.b2->instruction_count--;                                        /* ... and taken out again, its value left behind */
        k_def(B.r)->operands[1] = orphan;
        char reason[160];
        snprintf(reason, sizeof reason, "defined by insn#%u, which is in no block", oi->id);
        expect_operand_bad(B.x.f, "removed instruction", 3, k_def(B.r), 1, orphan, reason);

        k_def(B.r)->operands[1] = B.q;
        k_def(B.ph)->phi_incoming_values[0] = orphan;                     /* the same value as a phi incoming */
        expect_phi_bad(B.x.f, "removed instruction, as a phi incoming", 3, k_def(B.ph), 0, orphan, 1, reason);
        DONE("a value whose defining instruction is in no block (operand and phi incoming)") }
    {   BASE_CASE("no definition")
        val_t ghost = k_const(&B.x.bld, 7);
        ghost->kind = CIR_VAL_INSN_RESULT;                                /* an instruction result that names no instruction */
        ghost->u.def_insn = NULL;
        k_def(B.r)->operands[1] = ghost;
        expect_operand_bad(B.x.f, "no definition", 3, k_def(B.r), 1, ghost, "not defined by any instruction");
        DONE("an instruction result with no defining instruction") }
    {   BASE_CASE("definition that produces another value")
        val_t liar = k_const(&B.x.bld, 7);
        liar->kind = CIR_VAL_INSN_RESULT;                                 /* names x1's instruction, which produces x1 */
        liar->u.def_insn = k_def(B.x1);
        k_def(B.r)->operands[1] = liar;
        char reason[160];
        snprintf(reason, sizeof reason, "claimed by insn#%u, which produces a different value", k_def(B.x1)->id);
        expect_operand_bad(B.x.f, "definition mismatch", 3, k_def(B.r), 1, liar, reason);
        DONE("an instruction result named by an instruction that produces another value") }
}

/* ── Unreachable code ─────────────────────────────────────────────────────
 *   b0: p = param ; a = p + 1 ; jump b1
 *   b1: ph = phi [a, b0] [r, b2] ; r = ph + 1 ; ret r        (b2 can reach b1; nothing reaches b2)
 *   b2: w = p + 2 ; jump b1                                   (unreachable, defines w)
 *   b3: y2 = w + y ; y = a + r ; z = w + 1 ; ret z            (unreachable, uses everything wrongly)  */

typedef struct {
    fn_t x;
    cbae_cir_block_t *b1, *u1, *u2;
    val_t p, a, ph, r, w, y, y2, z;
} dead_t;

static void dead_build(dead_t *D) {
    memset(D, 0, sizeof *D);
    fn_init(&D->x, "dead");
    fn_t *x = &D->x;
    D->b1 = fn_block(x, 0x6010); D->u1 = fn_block(x, 0x6020); D->u2 = fn_block(x, 0x6030);
    cbae_cir_builder_t *b = &x->bld;
    D->p = cbae_cir_param(b, CBAE_REG_RBX);
    D->a = k_add(b, D->p, k_const(b, 1));
    cbae_cir_jump(b, D->b1, 0);

    D->ph = cbae_cir_phi_create(x->f, D->b1, T64);
    fn_at(x, D->b1);
    D->r = k_add(&x->bld, D->ph, k_const(&x->bld, 1));
    cbae_cir_return(&x->bld, D->r, 0);

    fn_at(x, D->u1);
    D->w = k_add(&x->bld, D->p, k_const(&x->bld, 2));
    cbae_cir_jump(&x->bld, D->b1, 0);                                     /* an unreachable predecessor of b1 */

    fn_at(x, D->u2);
    D->y = k_add(&x->bld, D->a, D->r);                                    /* from reachable blocks that do not dominate it */
    /* y2 reads y, which is defined after it, and w, which is defined in another unreachable block */
    D->y2 = k_add(&x->bld, D->w, D->w);
    k_def(D->y2)->operands[1] = D->y;                                     /* (rewired below, once y exists) */
    D->z = k_add(&x->bld, D->w, k_const(&x->bld, 1));
    cbae_cir_return(&x->bld, D->z, 0);

    /* the order inside u2 is [y, y2, z, ret]; make y2 come BEFORE y so that it reads a later definition */
    ins_t *ins = D->u2->instructions;
    ins_t t = ins[0]; ins[0] = ins[1]; ins[1] = t;                        /* [y2, y, z, ret] */

    assert(cbae_cir_phi_add_incoming(x->f, D->ph->u.def_insn, D->a, x->b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, D->ph->u.def_insn, D->r, D->u1->id) == CBAE_OK);   /* nonsense: from a block that never runs */
}

static void t_unreachable(void) {
    char w[160];
    {   dead_t D; dead_build(&D);
        assert(D.x.b0->id == 0 && D.b1->id == 1 && D.u1->id == 2 && D.u2->id == 3);
        expect_ok(D.x.f, "a function whose unreachable blocks misuse values in every way");
        fn_done(&D.x);
        printf("  [PASS] unreachable code is exempt: misordered uses, uses of values that dominate nothing, "
               "an unreachable phi incoming\n");
    }
    {   dead_t D; dead_build(&D);
        val_t ghost = k_const(&D.x.bld, 9);
        ghost->kind = CIR_VAL_INSN_RESULT; ghost->u.def_insn = NULL;
        k_def(D.ph)->phi_incoming_values[1] = ghost;                      /* from the unreachable predecessor: still exempt */
        expect_ok(D.x.f, "garbage incoming from an unreachable predecessor");
        k_def(D.ph)->phi_incoming_values[0] = ghost;                      /* but not from the reachable one */
        expect_phi_bad(D.x.f, "garbage incoming from a reachable predecessor", 1, k_def(D.ph), 0, ghost, 0,
                       "not defined by any instruction");
        fn_done(&D.x);
        printf("  [PASS] a phi incoming from an unreachable predecessor is exempt, even if it names nothing\n");
    }
    {   dead_t D; dead_build(&D);
        k_def(D.r)->operands[1] = D.w;                                    /* reachable code reads a value from code that never runs */
        expect_operand_bad(D.x.f, "defined in unreachable code", 1, k_def(D.r), 1, D.w,
                           why_unreach(w, k_def(D.w)->id, 2));
        fn_done(&D.x);
        printf("  [PASS] a value DEFINED in unreachable code and used by reachable code is reported\n");
    }
    {   dead_t D; dead_build(&D);
        k_def(D.ph)->phi_incoming_values[0] = D.w;                        /* the same, through a phi from a reachable predecessor */
        expect_phi_bad(D.x.f, "phi from unreachable definition", 1, k_def(D.ph), 0, D.w, 0,
                       why_unreach(w, k_def(D.w)->id, 2));
        fn_done(&D.x);
        printf("  [PASS] ... also as the incoming of a phi along a reachable edge\n");
    }
    {   dead_t D; dead_build(&D);
        k_def(D.y)->operands[0] = NULL;                                   /* rules 3 and 4 of the STRUCTURE hold everywhere */
        const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(D.x.f);
        assert(!vr.ok && strstr(vr.message, "block3") && strstr(vr.message, "operand 0 is NULL"));
        fn_done(&D.x);
        printf("  [PASS] the structural rules still apply inside unreachable blocks\n");
    }
    {   /* reachability follows the recorded edges, not the terminators: a block entered only from
         * an unreachable block is unreachable too, and so are its uses */
        fn_t x; fn_init(&x, "island");
        cbae_cir_block_t *u1 = fn_block(&x, 0x7010), *u2 = fn_block(&x, 0x7020);
        cbae_cir_builder_t *b = &x.bld;
        val_t p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_return(b, p, 0);
        fn_at(&x, u1);
        val_t v = k_add(&x.bld, p, p);
        cbae_cir_jump(&x.bld, u2, 0);
        fn_at(&x, u2);
        val_t bad = k_add(&x.bld, v, v);                                  /* in u2, entered only from u1: both unreachable */
        k_def(bad)->operands[0] = bad;                                    /* even a self use */
        cbae_cir_return(&x.bld, bad, 0);
        expect_ok(x.f, "an unreachable island");
        fn_done(&x);
        printf("  [PASS] a block reachable only from unreachable blocks is unreachable\n");
    }
}

/* ── Which violation is reported ──────────────────────────────────────── */

static void t_report_order(void) {
    char w[160];
    {   BASE_CASE("two operands")
        k_def(B.r)->operands[0] = B.x1;
        k_def(B.r)->operands[1] = B.x2;
        expect_operand_bad(B.x.f, "operand 0 first", 3, k_def(B.r), 0, B.x1, why_not_dom(w, k_def(B.x1)->id, 1, 3));
        DONE("within an instruction, the first operand is reported") }
    {   BASE_CASE("two instructions")
        B.ret->operands[0] = B.x2;                                        /* position 2 of b3 */
        k_def(B.r)->operands[1] = B.x1;                                   /* position 1 of b3 */
        expect_operand_bad(B.x.f, "earlier instruction first", 3, k_def(B.r), 1, B.x1,
                           why_not_dom(w, k_def(B.x1)->id, 1, 3));
        DONE("within a block, the earlier instruction is reported") }
    {   BASE_CASE("two blocks")
        k_def(B.r)->operands[1] = B.x1;                                   /* block 3 */
        k_def(B.x2)->operands[0] = B.x1;                                  /* block 2 */
        expect_operand_bad(B.x.f, "lower block first", 2, k_def(B.x2), 0, B.x1, why_not_dom(w, k_def(B.x1)->id, 1, 2));
        DONE("the lower block id is reported first") }
    {   BASE_CASE("phi before add")
        k_def(B.r)->operands[1] = B.x1;                                   /* position 1 of b3 */
        k_def(B.ph)->phi_incoming_values[1] = B.x1;                       /* position 0 of b3, the phi */
        expect_phi_bad(B.x.f, "phi first", 3, k_def(B.ph), 1, B.x1, 2, why_not_dom(w, k_def(B.x1)->id, 1, 2));
        DONE("a phi (which leads its block) is reported before the instructions below it") }
    {   BASE_CASE("two incomings")
        k_def(B.ph)->phi_incoming_values[0] = B.x2;                       /* from b1, a value of b2 */
        k_def(B.ph)->phi_incoming_values[1] = B.x1;                       /* from b2, a value of b1 */
        expect_phi_bad(B.x.f, "incoming 0 first", 3, k_def(B.ph), 0, B.x2, 1, why_not_dom(w, k_def(B.x2)->id, 2, 1));
        DONE("within a phi, the first incoming is reported") }
}

static void t_structure_first(void) {
    {   BASE_CASE("placeholder")
        B.q->kind = CIR_VAL_REG_ENTRY;                                    /* r reads q */
        const cbae_cir_verify_result_t st = cbae_cir_verify_function(B.x.f);
        const cbae_cir_verify_result_t ss = cbae_ssa_verify_function(B.x.f);
        assert(!st.ok && !ss.ok && strcmp(st.message, ss.message) == 0);
        assert(strstr(ss.message, "unresolved CIR_VAL_REG_ENTRY"));
        B.q->kind = CIR_VAL_PARAM;
        DONE("a structural failure is returned as it is") }
    {   BASE_CASE("both kinds")
        k_def(B.c)->operands[0] = B.a;                                    /* an SSA violation in block 0 ... */
        k_def(B.r)->operands[1] = NULL;                                   /* ... and a structural one in block 3 */
        const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(B.x.f);
        assert(!vr.ok && strstr(vr.message, "block3 insn#") && strstr(vr.message, "operand 1 is NULL"));
        DONE("the structural check runs first, whichever block each failure is in") }
}

/* ── Machine code through the lifter and SSA construction ─────────────── */

static uint32_t block_of_insn(const cbae_cir_function_t *f, const cbae_cir_instruction_t *in) {
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    for (uint32_t b = 0; b < nb; b++)
        for (uint32_t i = 0; i < lh_block(f, b)->instruction_count; i++)
            if (lh_block(f, b)->instructions[i] == in) return b;
    assert(!"instruction not placed");
    return 0;
}

static void t_lifted(void) {
    /* The three inputs the Phase 4 SSA tests use: a diamond that merges two constants, a counted
     * loop, and a loop whose header is the function's first instruction (it gets a synthetic entry). */
    static const uint8_t diamond[] = {
        0x0F,0x84,0x0F,0x00,0x00,0x00,
        0x48,0xB8,0x0A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xE9,0x0A,0x00,0x00,0x00,
        0x48,0xB8,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xC3 };
    static const uint8_t loop[] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x48,0x83,0xC0,0x01,
        0x48,0x83,0xF8,0x0A,
        0x0F,0x8C,0xF2,0xFF,0xFF,0xFF,
        0xC3 };
    static const uint8_t entry_loop[] = { 0x48,0xFF,0xC9, 0x75,0xFB, 0xC3 };
    static const uint8_t consts[]  = { 0x48,0xC7,0xC0,0x10,0x00,0x00,0x00, 0x48,0x83,0xC0,0x20,
                                       0x48,0xC1,0xE0,0x04, 0xC3 };
    static const uint8_t jcc[]     = { 0x48,0xC7,0xC0,0x05,0x00,0x00,0x00, 0x48,0x83,0xF8,0x05,
                                       0x74,0x07, 0x48,0xC7,0xC0,0x07,0x00,0x00,0x00,
                                       0x48,0x83,0xC0,0x01, 0xC3 };
    static const uint8_t frame[]   = { 0x48,0x83,0xEC,0x28, 0x48,0x89,0x4C,0x24,0x20, 0xE8,0xF2,0x00,0x00,0x00,
                                       0x48,0x8B,0x44,0x24,0x20, 0x48,0x89,0x54,0x24,0x18, 0x48,0x8B,0x74,0x24,0x18,
                                       0x48,0x83,0xC4,0x28, 0xC3 };
    static const uint8_t pushpop[] = { 0x53, 0xE8,0xFA,0x00,0x00,0x00, 0x59, 0xC3 };

    struct { const uint8_t *code; size_t len; cbae_addr_t base; const char *name; } cases[] = {
        { diamond,    sizeof diamond,    0x1000, "diamond"    },
        { loop,       sizeof loop,       0x2000, "loop"       },
        { entry_loop, sizeof entry_loop, 0x2000, "entry_loop" },
        { consts,     sizeof consts,     0x7000, "consts"     },
        { jcc,        sizeof jcc,        0x9000, "jcc"        },
        { frame,      sizeof frame,      0x5000, "frame"      },
        { pushpop,    sizeof pushpop,    0x6000, "pushpop"    },
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        lifted_t L;
        lift_x86(&L, cases[c].code, cases[c].len, cases[c].base, cases[c].name);
        expect_ok(L.func, cases[c].name);
        lifted_destroy(&L);
    }

    /* The same counted loop, broken. head: phi = [const 0 from the entry, add from head] ; add = phi + 1.
     * The entry-side incoming is rewired to `add`, which lives in the head: the head does not dominate
     * the entry. */
    lifted_t L;
    lift_x86(&L, loop, sizeof loop, 0x2000, "loop");
    ins_t phi = lh_nth_insn(L.func, CIR_OP_PHI, 0);
    ins_t add = lh_nth_insn(L.func, CIR_OP_ADD, 0);
    assert(phi && add && add->result);
    const uint32_t head = block_of_insn(L.func, phi);
    assert(block_of_insn(L.func, add) == head && phi->phi_incoming_count == 2);
    uint32_t k = 0;
    while (phi->phi_incoming_blocks[k] == head) k++;                      /* the incoming that is NOT the back edge */
    assert(k < 2);
    const uint32_t entry = phi->phi_incoming_blocks[k];
    phi->phi_incoming_values[k] = add->result;
    char w[160];
    expect_phi_bad(L.func, "lifted loop, rewired", head, phi, k, add->result, entry,
                   why_not_dom(w, add->id, head, entry));
    lifted_destroy(&L);
    printf("  [PASS] lifted code (%zu functions) verifies, and a rewired lifted loop is caught\n",
           sizeof cases / sizeof cases[0]);
}

/* What gcc emitted for the functions in compiled_corpus.h, lifted and put into SSA form: every one
 * must pass. Hand-assembled inputs show the verifier accepts what their author had in mind; this is
 * code nobody arranged. Before the SSA constructor was fixed to resolve register reads that come
 * after the phis it inserts into its own block, 13 of the 40 functions (before removing duplicates)
 * failed here with "unresolved CIR_VAL_REG_ENTRY operand". */
static void t_compiled(void) {
    uint64_t blocks = 0, phis = 0, joins = 0;
    for (size_t c = 0; c < COMPILED_CORPUS_COUNT; c++) {
        const corpus_fn_t *fn = &compiled_corpus[c];
        lifted_t L;
        lift_x86(&L, fn->code, fn->len, 0x401000, fn->name);
        expect_ok(L.func, fn->name);

        const uint32_t nb = (uint32_t)cbae_vector_count(&L.func->blocks);
        blocks += nb;
        for (uint32_t b = 0; b < nb; b++) {
            const cbae_cir_block_t *blk = lh_block(L.func, b);
            if (cbae_vector_count(&blk->predecessors) >= 2) joins++;
            for (uint32_t i = 0; i < blk->instruction_count; i++)
                if (blk->instructions[i]->opcode == CIR_OP_PHI) phis++;
        }
        lifted_destroy(&L);
    }
    /* The inputs must be rich enough to mean something: loops (blocks with two predecessors) and
     * phis are what dominance is about. */
    assert(COMPILED_CORPUS_COUNT >= 30);
    assert(blocks >= 150 && joins >= 40 && phis >= 80);
    printf("  [PASS] gcc output (%zu functions, %llu blocks, %llu joins, %llu phis) lifts to SSA the verifier accepts\n",
           (size_t)COMPILED_CORPUS_COUNT, (unsigned long long)blocks, (unsigned long long)joins,
           (unsigned long long)phis);
}

/* ── Random valid functions ───────────────────────────────────────────── */

static void t_random_valid(void) {
    uint64_t blocks = 0, phis = 0, loops = 0;
    for (uint64_t seed = 0; seed < 4000; seed++) {
        cirg_params_t p = cirg_params_for_seed(seed);
        if (seed % 2) { p.barrier_pct = 25; p.reload_pct = 25; p.const_pct = 35; p.const_cond_pct = 35; }
        cirg_t *g = NULL;
        assert(cirg_build(&g, seed, &p));
        expect_ok(g->f, "random function");
        blocks += g->nblocks;
        for (uint32_t b = 0; b < g->nblocks; b++) {
            phis += g->nphi[b];
            if (cirg_has_back_pred(g, b)) loops++;
        }
        cirg_free(g);
    }
    assert(blocks > 20000 && phis > 2000 && loops > 1000);               /* the functions have joins and loops */
    printf("  [PASS] 4000 random valid functions pass (%llu blocks, %llu phis, %llu loop headers)\n",
           (unsigned long long)blocks, (unsigned long long)phis, (unsigned long long)loops);
}

/* ── The oracle ───────────────────────────────────────────────────────── */

#define OMAXB 48                  /* the generator makes at most 32 blocks; the fuzz grafts a few more */

typedef struct {
    bool ok;
    int  reason;                  /* 0 none, 1 same block, 2 not dominated, 3 definition unreachable */
    char message[CIR_VERIFY_MSG_MAX];
} oracle_t;

/* Blocks reachable from the entry along the recorded successor lists, never entering `avoid`. */
static void o_reach(const cbae_cir_function_t *f, int avoid, bool seen[OMAXB]) {
    uint32_t stack[OMAXB], sp = 0;
    memset(seen, 0, OMAXB);
    if (avoid == 0) return;
    seen[0] = true;
    stack[sp++] = 0;
    while (sp) {
        const cbae_cir_block_t *b = lh_block(f, stack[--sp]);
        for (uint32_t k = 0; k < b->successor_count; k++) {
            const uint32_t s = b->successors[k];
            if ((int)s == avoid || seen[s]) continue;
            seen[s] = true;
            stack[sp++] = s;
        }
    }
}

typedef struct {
    bool                         reach[OMAXB];
    bool                         without[OMAXB][OMAXB];   /* without[a][b]: b is reachable avoiding a */
    int32_t                     *def_blk, *def_pos;       /* [value id] where the value's instruction is */
    const cbae_cir_instruction_t **def_insn;
} octx_t;

/* 0 if `v` is available at position `upos` of reachable block `ub` (UINT32_MAX: at its end); else
 * the reason, with the text of it in `why`. */
static int o_avail(const octx_t *c, const cbae_cir_value_t *v, uint32_t ub, uint32_t upos, char *why) {
    if (v->kind == CIR_VAL_CONST || v->kind == CIR_VAL_PARAM) return 0;
    assert(v->kind == CIR_VAL_INSN_RESULT && c->def_blk[v->id] >= 0);
    const uint32_t db = (uint32_t)c->def_blk[v->id], dp = (uint32_t)c->def_pos[v->id];
    const uint32_t di = c->def_insn[v->id]->id;
    if (!c->reach[db]) {
        snprintf(why, 160, "defined by insn#%u in block%u, which the entry cannot reach", di, db);
        return 3;
    }
    if (db == ub) {
        if (upos == UINT32_MAX || dp < upos) return 0;
        snprintf(why, 160, "used before its definition: insn#%u defines it at position %u of this block, "
                 "the use is at position %u", di, dp, upos);
        return 1;
    }
    if (!c->without[db][ub]) return 0;                                    /* every path to ub passes through db */
    snprintf(why, 160, "defined by insn#%u in block%u, which does not dominate block%u", di, db, ub);
    return 2;
}

static oracle_t oracle(const cbae_cir_function_t *f) {
    oracle_t o;
    memset(&o, 0, sizeof o);
    o.ok = true;
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    assert(nb <= OMAXB);

    octx_t *c = calloc(1, sizeof *c);
    const uint32_t nv = f->next_value_id;
    c->def_blk  = malloc(sizeof(int32_t) * nv);
    c->def_pos  = malloc(sizeof(int32_t) * nv);
    c->def_insn = calloc(nv, sizeof *c->def_insn);
    assert(c->def_blk && c->def_pos && c->def_insn);
    for (uint32_t i = 0; i < nv; i++) c->def_blk[i] = c->def_pos[i] = -1;

    o_reach(f, -1, c->reach);
    for (uint32_t a = 0; a < nb; a++) o_reach(f, (int)a, c->without[a]);
    for (uint32_t b = 0; b < nb; b++)
        for (uint32_t i = 0; i < lh_block(f, b)->instruction_count; i++) {
            const cbae_cir_instruction_t *in = lh_block(f, b)->instructions[i];
            if (!in->result) continue;
            c->def_blk[in->result->id]  = (int32_t)b;
            c->def_pos[in->result->id]  = (int32_t)i;
            c->def_insn[in->result->id] = in;
        }

    char why[160];
    for (uint32_t b = 0; b < nb && o.ok; b++) {
        if (!c->reach[b]) continue;
        const cbae_cir_block_t *blk = lh_block(f, b);
        for (uint32_t i = 0; i < blk->instruction_count && o.ok; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (in->opcode == CIR_OP_PHI) {
                for (uint32_t k = 0; k < in->phi_incoming_count && o.ok; k++) {
                    const uint32_t pb = in->phi_incoming_blocks[k];
                    if (!c->reach[pb]) continue;
                    const cbae_cir_value_t *v = in->phi_incoming_values[k];
                    const int why_code = o_avail(c, v, pb, UINT32_MAX, why);
                    if (why_code) {
                        o.ok = false; o.reason = why_code;
                        snprintf(o.message, sizeof o.message, "block%u insn#%u: phi incoming %u (%%v%u) from block%u is %s",
                                 b, in->id, k, v->id, pb, why);
                    }
                }
            } else {
                for (uint32_t oi = 0; oi < in->operand_count && o.ok; oi++) {
                    const cbae_cir_value_t *v = in->operands[oi];
                    const int why_code = o_avail(c, v, b, i, why);
                    if (why_code) {
                        o.ok = false; o.reason = why_code;
                        snprintf(o.message, sizeof o.message, "block%u insn#%u: operand %u (%%v%u) is %s",
                                 b, in->id, oi, v->id, why);
                    }
                }
            }
        }
    }
    free(c->def_blk); free(c->def_pos); free(c->def_insn); free(c);
    return o;
}

/* ── Differential fuzz ──────────────────────────────────────────────────
 * A random valid function, optionally with unreachable blocks grafted on (they use random values in
 * every wrong way, and some feed reachable phis), then rounds of: rewire one to three uses to random
 * values, ask the verifier and the oracle, compare verdict and message, and put the uses back. */

static val_t any_value(const cbae_cir_function_t *f, cirr_rng_t *rng) {
    return *(val_t *)cbae_vector_at(&f->values, cirr_below(rng, (uint32_t)cbae_vector_count(&f->values)));
}

static bool lists_succ(const cbae_cir_block_t *b, uint32_t s) {
    for (uint32_t k = 0; k < b->successor_count; k++)
        if (b->successors[k] == s) return true;
    return false;
}

static void graft_unreachable(cbae_cir_function_t *f, cirr_rng_t *rng) {
    const uint32_t nb0 = (uint32_t)cbae_vector_count(&f->blocks);
    const uint32_t nu = 1 + cirr_below(rng, 3);
    cbae_cir_block_t *u[3];
    for (uint32_t i = 0; i < nu; i++)
        assert(cbae_cir_block_create(f, 0x7000000 + 0x10 * i, &u[i]) == CBAE_OK);
    for (uint32_t i = 0; i < nu; i++) {
        cbae_cir_builder_t b;
        cbae_cir_builder_init(&b, f, u[i]);
        for (uint32_t m = cirr_below(rng, 4); m > 0; m--) {
            val_t x = any_value(f, rng), y = any_value(f, rng);
            assert(cbae_cir_binop(&b, CIR_OP_ADD, x, y, T64, 0));
        }
        for (uint32_t e = cirr_below(rng, 3); e > 0; e--) {
            const uint32_t pick = cirr_below(rng, (nb0 - 1) + nu);        /* a reachable block but the entry, or an unreachable one */
            cbae_cir_block_t *t = pick < nb0 - 1 ? lh_block(f, 1 + pick) : u[pick - (nb0 - 1)];
            if (lists_succ(u[i], t->id)) continue;
            assert(cbae_cir_block_add_edge(u[i], t) == CBAE_OK);
            for (uint32_t k = 0; k < t->instruction_count && t->instructions[k]->opcode == CIR_OP_PHI; k++) {
                val_t v = any_value(f, rng);
                assert(cbae_cir_phi_add_incoming(f, t->instructions[k], v, u[i]->id) == CBAE_OK);
            }
        }
    }
}

typedef struct { val_t *slot; val_t old; } undo_t;

/* `dead` are the values defined in the grafted (unreachable) blocks, if any. */
static val_t pick_replacement(const cbae_cir_function_t *f, cirr_rng_t *rng, val_t *dead, uint32_t ndead) {
    if (ndead && cirr_pct(rng, 15)) return dead[cirr_below(rng, ndead)];  /* now and then one from code that never runs */
    if (cirr_pct(rng, 25))                                                /* often one that is available everywhere */
        for (int tries = 0; tries < 64; tries++) {
            val_t v = any_value(f, rng);
            if (v->kind == CIR_VAL_CONST || v->kind == CIR_VAL_PARAM) return v;
        }
    return any_value(f, rng);
}

static void t_differential(void) {
    uint64_t functions = 0, grafted = 0, rounds = 0, verdict_ok = 0, verdict_bad = 0, reason[4] = {0, 0, 0, 0};
    for (uint64_t seed = 0; seed < 5000; seed++) {
        cirg_params_t p = cirg_params_for_seed(seed);
        if (seed % 2) { p.const_pct = 30; p.const_cond_pct = 30; }
        cirg_t *g = NULL;
        assert(cirg_build(&g, seed, &p));
        cbae_cir_function_t *f = g->f;
        cirr_rng_t rng; rng.s = seed * 0x9E3779B97F4A7C15ull + 0xC0FFEEull;

        const uint32_t nreach = (uint32_t)cbae_vector_count(&f->blocks);
        if (seed % 3 != 0) { graft_unreachable(f, &rng); grafted++; }
        val_t dead[32]; uint32_t ndead = 0;                              /* what the grafted blocks define */
        for (uint32_t b = nreach; b < (uint32_t)cbae_vector_count(&f->blocks); b++)
            for (uint32_t i = 0; i < lh_block(f, b)->instruction_count && ndead < 32; i++)
                if (lh_block(f, b)->instructions[i]->result) dead[ndead++] = lh_block(f, b)->instructions[i]->result;
        expect_ok(f, "before any rewiring");
        { const oracle_t o = oracle(f); assert(o.ok); }                   /* the oracle agrees the function is valid */

        /* every use slot of the function */
        uint32_t nslots = 0;
        const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
        for (uint32_t b = 0; b < nb; b++)
            for (uint32_t i = 0; i < lh_block(f, b)->instruction_count; i++) {
                const ins_t in = lh_block(f, b)->instructions[i];
                nslots += in->opcode == CIR_OP_PHI ? in->phi_incoming_count : in->operand_count;
            }
        val_t **slots = malloc(sizeof(val_t *) * (nslots ? nslots : 1));
        assert(slots);
        uint32_t n = 0;
        for (uint32_t b = 0; b < nb; b++)
            for (uint32_t i = 0; i < lh_block(f, b)->instruction_count; i++) {
                const ins_t in = lh_block(f, b)->instructions[i];
                if (in->opcode == CIR_OP_PHI) for (uint32_t k = 0; k < in->phi_incoming_count; k++) slots[n++] = &in->phi_incoming_values[k];
                else                          for (uint32_t k = 0; k < in->operand_count; k++)       slots[n++] = &in->operands[k];
            }
        assert(n == nslots);

        for (int round = 0; round < 6 && nslots; round++) {
            undo_t undo[3];
            const uint32_t ncor = 1 + cirr_below(&rng, 3);
            for (uint32_t k = 0; k < ncor; k++) {
                undo[k].slot = slots[cirr_below(&rng, nslots)];
                undo[k].old  = *undo[k].slot;
                *undo[k].slot = pick_replacement(f, &rng, dead, ndead);
            }
            const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(f);
            const oracle_t o = oracle(f);
            if (vr.ok != o.ok || (!o.ok && strcmp(vr.message, o.message) != 0))
                fprintf(stderr, "FAIL [seed %llu round %d]:\n  verifier ok=%d '%s'\n  oracle   ok=%d '%s'\n",
                        (unsigned long long)seed, round, (int)vr.ok, vr.message, (int)o.ok, o.message);
            assert(vr.ok == o.ok);
            if (!o.ok) assert(strcmp(vr.message, o.message) == 0);
            rounds++;
            if (o.ok) verdict_ok++; else { verdict_bad++; reason[o.reason]++; }
            for (uint32_t k = ncor; k-- > 0;) *undo[k].slot = undo[k].old;  /* newest first: a slot picked twice returns to its original */
        }
        expect_ok(f, "after putting every use back");
        free(slots);
        functions++;
        cirg_free(g);
    }
    assert(verdict_ok > 3000 && reason[1] > 500 && reason[2] > 5000 && reason[3] > 500);
    printf("  [PASS] verdict and message agree with the dominance oracle on %llu rewirings of %llu random functions "
           "(%llu with unreachable blocks; %llu valid, %llu invalid: %llu used before defined, %llu not dominated, "
           "%llu defined in unreachable code)\n",
           (unsigned long long)rounds, (unsigned long long)functions, (unsigned long long)grafted,
           (unsigned long long)verdict_ok, (unsigned long long)verdict_bad, (unsigned long long)reason[1],
           (unsigned long long)reason[2], (unsigned long long)reason[3]);
}

int main(void) {
    t_valid();
    t_before_definition();
    t_not_dominated();
    t_phi_incomings();
    t_orphans();
    t_unreachable();
    t_report_order();
    t_structure_first();
    t_lifted();
    t_compiled();
    t_random_valid();
    t_differential();
    printf("All SSA verifier tests passed.\n");
    return 0;
}
