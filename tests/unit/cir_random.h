/**
 * @file cir_random.h
 * @brief Test support: random VALID-SSA CIR functions, and a concrete
 *        interpreter that actually runs them.
 *
 * WHY
 *   A static analysis claims things about EVERY execution. Hand-built cases
 *   show the claims are right where we thought to look; this lets a test
 *   check them against real executions of thousands of functions nobody
 *   thought about. Used by the alias, reaching-store and constant-propagation
 *   soundness tests, and it exercises the SSA verifier (every generated
 *   function must pass it).
 *
 * THE GENERATOR  (cirg_build)
 *   - CFG first: a random spanning tree rooted at block 0 (every block
 *     reachable, block 0 has no predecessors, every block has at most two
 *     successors) plus extra edges, which create loops and join points.
 *     A tree parent always has a lower index than its child, so every
 *     block's immediate dominator has a lower index than the block.
 *   - Dominators by the plain bit-set fixed point (independent of the
 *     dominator code under test).
 *   - Blocks are filled in index order. An operand is chosen only among
 *     values whose definition dominates the use (earlier in the same block,
 *     or in a strictly dominating block, or a parameter / constant), so the
 *     function is dominance-correct SSA by construction.
 *   - Phis are created empty and filled last, from values available at the
 *     end of each predecessor. The fill is biased toward the shapes that
 *     matter: redundant phis (one value on every edge, or the phi itself on
 *     a back edge) and induction variables (phi + stride on a back edge).
 *   - Addresses are built the way the lifter builds them: [base],
 *     [base+disp], [base + idx*scale + disp] with a fresh MUL each time, in
 *     PTR or i64 arithmetic. Address "recipes" are reused, with the same or
 *     a different displacement, so that distinct SSA values with identical
 *     decompositions occur (the case alias analysis exists for).
 *   - Sums of up to eleven operands (more atoms than the analysis keeps) and
 *     loop-header phis carrying every kind of recurrence (x+c, x*k, x<<c, -x,
 *     x+y, x+x, copies), so that both the term caps and the redundant-phi
 *     guards are exercised on code nobody wrote by hand.
 *   - Widths are deliberately mixed. i32/i16/i8 values are produced by
 *     arithmetic, loads and constants (including constants that do not fit
 *     their type) and flow into 64-bit arithmetic, addresses and phis; phis
 *     themselves are sometimes narrow. CIR does not forbid any of this and
 *     the lifter produces some of it (its phis are i64 over incoming values
 *     of any width), so analyses must be sound for all of it.
 *
 * THE INTERPRETER  (cirx_run)
 *   Semantics, chosen to be the most hostile reading of the CIR:
 *   - Every value is held zero-extended at its own type's width; a result is
 *     truncated to its type. ADD SUB MUL AND OR XOR NOT NEG SHL SHR SAR
 *     compute on those 64-bit patterns and truncate. Shift counts are taken
 *     modulo 64 (as x86 does). A constant is its int64 field truncated to its
 *     type's width.
 *   - The parameter for the lifter's conflated "other" register reads as an
 *     unrelated value every time it is read.
 *   - CMP and TEST have no defined predicate in CIR (the condition code is
 *     not recorded), so each execution of one yields an arbitrary bit.
 *   - Phis are a parallel copy on the incoming edge.
 *   - LOAD/STORE touch `size` bytes, size from the accessed type. Memory is
 *     sparse; a byte never written reads as a value derived from its
 *     address, and most initial quad-words look like pointers into the same
 *     small address pool the parameters use, so loaded pointers collide with
 *     other addresses.
 *   - CALL returns an arbitrary value and overwrites a few quad-words,
 *     preferring addresses the function touched recently.
 *   - Execution stops at RETURN or after a step budget; every claim a
 *     static analysis makes must also hold for such a prefix.
 *   - Using a value before its definition aborts: the generator is
 *     supposed to make that impossible.
 *   Hooks report each definition, each memory access, each load's
 *   per-byte last writer, and each byte a call clobbers.
 */
#ifndef CBAE_TEST_CIR_RANDOM_H
#define CBAE_TEST_CIR_RANDOM_H

#include "cir/cir_builder.h"
#include "cir/cir_verifier.h"
#include "platform/memory.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Small PRNG ──────────────────────────────────────────────────────── */

typedef struct { uint64_t s; } cirr_rng_t;

static inline uint64_t cirr_mix(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}
static inline uint64_t cirr_next(cirr_rng_t *r) {
    r->s += 0x9E3779B97F4A7C15ull;
    return cirr_mix(r->s);
}
static inline uint32_t cirr_below(cirr_rng_t *r, uint32_t n) { return (uint32_t)(cirr_next(r) % n); }
static inline bool     cirr_pct(cirr_rng_t *r, uint32_t p)   { return cirr_below(r, 100) < p; }

/* Values parameters, constants and initial memory are drawn from, so that
 * independent pointers land close to each other and collide. */
static const uint64_t CIRR_POOL[] = {
    0x1000, 0x1008, 0x1010, 0x1018, 0x1020, 0x1004, 0x100C, 0x1100, 0x1108, 0x2000, 0x2008,
    0, 1, 2, 4, 8, 16, 24, 0xFFFFFFFFFFFFFFF8ull, 0xFFFFFFFFFFFFFFF0ull };
#define CIRR_POOL_N ((uint32_t)(sizeof CIRR_POOL / sizeof CIRR_POOL[0]))

/* Constants every function gets (as i64), and the shift counts it uses. */
static const int64_t CIRG_KCONST[] = {
    0, 1, 2, 3, 4, 8, 12, 16, 24, 32, -1, -4, -8, -16, 0x7FFFFFFFFFFFFFF8ll };
#define CIRG_KCONST_N ((uint32_t)(sizeof CIRG_KCONST / sizeof CIRG_KCONST[0]))
static const int64_t CIRG_KSHIFT[] = { 0, 1, 2, 3, 4, 5, 63, 64 };
#define CIRG_KSHIFT_N ((uint32_t)(sizeof CIRG_KSHIFT / sizeof CIRG_KSHIFT[0]))

/* ── Generator ───────────────────────────────────────────────────────── */

#define CIRG_MAX_BLOCKS  32
#define CIRG_MAX_DEFS    512
#define CIRG_MAX_PHIS    4
#define CIRG_MAX_RECIPES 96

typedef enum { CIRG_I64 = 0, CIRG_I32, CIRG_I16, CIRG_I8, CIRG_I1, CIRG_NCLASS } cirg_class_t;

typedef struct {
    cbae_cir_value_t *v[CIRG_MAX_DEFS];
    uint8_t           cls[CIRG_MAX_DEFS];
    uint32_t          n;
} cirg_defs_t;

typedef struct cirg_params {
    uint32_t min_blocks, max_blocks;   /* function size, at least 2                  */
    uint32_t max_body;                  /* random instructions per block, 1..max_body */
    uint32_t extra_edge_pct;            /* chance of keeping each extra edge attempt  */
} cirg_params_t;

/* One address expression, remembered so it can be built again. */
typedef struct {
    cbae_cir_value_t *base;     /* may be NULL                                      */
    cbae_cir_value_t *idx;      /* may be NULL                                      */
    int64_t           scale;    /* 1, 2, 4 or 8                                     */
    int64_t           disp;
    uint8_t           shape;
    bool              use_shl;  /* scale the index with SHL instead of MUL          */
    bool              ptr_ty;   /* PTR arithmetic, like the lifter, or plain i64    */
    uint32_t          blk;      /* block that first built it                        */
    uint8_t           nsum;     /* shape 7: a sum of nsum operands, +/- each        */
    cbae_cir_value_t *sum_v[12];
    uint8_t           sum_neg[12];
} cirg_recipe_t;

typedef struct cirg {
    cbae_arena_t          arena;
    cbae_cir_function_t  *f;
    uint32_t              nblocks;

    cbae_cir_block_t     *blk[CIRG_MAX_BLOCKS];
    uint32_t              succ[CIRG_MAX_BLOCKS][2];
    uint32_t              nsucc[CIRG_MAX_BLOCKS];
    uint32_t              pred[CIRG_MAX_BLOCKS][CIRG_MAX_BLOCKS];
    uint32_t              npred[CIRG_MAX_BLOCKS];
    uint32_t              dom[CIRG_MAX_BLOCKS];       /* bit d set: block d dominates this block */

    cirg_defs_t           defs[CIRG_MAX_BLOCKS];
    cirg_defs_t           globals;                    /* parameters and constants               */
    cbae_cir_value_t     *params[8];
    cbae_cir_value_t     *other;                      /* the lifter's conflated narrow register  */
    cbae_cir_value_t     *anchors[8];                 /* loads and calls in block 0: distinct stable atoms */
    uint32_t              nanchors;
    cbae_cir_value_t     *conflated[16];              /* phis fed (mostly) by the "other" register */
    uint32_t              conflated_blk[16];
    uint32_t              nconflated;
    cbae_cir_value_t     *consts[CIRG_KCONST_N];
    cbae_cir_value_t     *shift_counts[CIRG_KSHIFT_N];

    cirg_recipe_t         recipes[CIRG_MAX_RECIPES];
    uint32_t              nrecipes;

    cbae_cir_value_t     *phi[CIRG_MAX_BLOCKS][CIRG_MAX_PHIS];
    cbae_cir_value_t     *phi_main[CIRG_MAX_BLOCKS][CIRG_MAX_PHIS];
    uint8_t               phi_rec[CIRG_MAX_BLOCKS][CIRG_MAX_PHIS];   /* 0 none, else recurrence kind */
    cbae_cir_value_t     *induct_in[CIRG_MAX_BLOCKS][CIRG_MAX_PHIS][CIRG_MAX_BLOCKS];
    uint32_t              nphi[CIRG_MAX_BLOCKS];

    cirr_rng_t            rng;
    cbae_cir_builder_t    bld;
} cirg_t;

static inline void cirg_add_def(cirg_defs_t *d, cbae_cir_value_t *v, cirg_class_t c) {
    assert(v && d->n < CIRG_MAX_DEFS);
    d->v[d->n] = v;
    d->cls[d->n] = (uint8_t)c;
    d->n++;
}

/* Uniform choice among the values of class `c` in `d` (reservoir sampling,
 * so no candidate array is needed). `seen` carries the running count. */
static inline void cirg_reservoir(cirg_t *g, const cirg_defs_t *d, cirg_class_t c,
                                  cbae_cir_value_t **chosen, uint32_t *seen) {
    for (uint32_t i = 0; i < d->n; i++) {
        if (d->cls[i] != c) continue;
        *seen += 1;
        if (cirr_below(&g->rng, *seen) == 0) *chosen = d->v[i];
    }
}

/* A random available value of class `c` at block `b` (b's own definitions
 * so far included, which for a phi incoming means "at the end of b").
 * NULL if there is none. Recent definitions are favoured: real code mostly
 * uses what it just computed. */
static cbae_cir_value_t *cirg_pick(cirg_t *g, uint32_t b, cirg_class_t c) {
    cbae_cir_value_t *chosen = NULL;
    uint32_t seen = 0;
    if (cirr_pct(&g->rng, 40)) {
        cirg_reservoir(g, &g->defs[b], c, &chosen, &seen);
        if (chosen) return chosen;
    }
    seen = 0;
    cirg_reservoir(g, &g->globals, c, &chosen, &seen);
    for (uint32_t d = 0; d < g->nblocks; d++)
        if ((g->dom[b] >> d) & 1u) cirg_reservoir(g, &g->defs[d], c, &chosen, &seen);
    return chosen;
}

/* A 64-bit value (parameters guarantee one exists). */
static cbae_cir_value_t *cirg_i64(cirg_t *g, uint32_t b) {
    cbae_cir_value_t *v = cirg_pick(g, b, CIRG_I64);
    assert(v);
    return v;
}

/* An operand for a wide operation: usually a 64-bit value, sometimes a
 * narrower one (which an interpreter holds zero-extended). */
static cbae_cir_value_t *cirg_opnd(cirg_t *g, uint32_t b) {
    if (cirr_pct(&g->rng, 12)) {
        cbae_cir_value_t *v = cirg_pick(g, b, (cirg_class_t)(CIRG_I32 + cirr_below(&g->rng, 3)));
        if (v) return v;
    }
    return cirg_i64(g, b);
}

/* A base register: a parameter about half the time (frame / object
 * pointers), otherwise anything. */
static cbae_cir_value_t *cirg_base(cirg_t *g, uint32_t b) {
    if (cirr_pct(&g->rng, 6)) return g->other;
    if (g->nanchors && cirr_pct(&g->rng, 12)) return g->anchors[cirr_below(&g->rng, g->nanchors)];
    if (cirr_pct(&g->rng, 45)) return g->params[cirr_below(&g->rng, 8)];
    return cirg_opnd(g, b);
}

/* An operand for a long sum: a non-constant value not already in it, so
 * that the sum really has many distinct atoms (and runs into the caps). */
static cbae_cir_value_t *cirg_sum_operand(cirg_t *g, uint32_t b, cbae_cir_value_t *const *used,
                                          uint32_t nused) {
    for (int tries = 0; tries < 10; tries++) {
        cbae_cir_value_t *v;
        const uint32_t r = cirr_below(&g->rng, 100);
        if (r < 35)                            v = g->params[cirr_below(&g->rng, 8)];
        else if (r < 60 && g->nanchors)        v = g->anchors[cirr_below(&g->rng, g->nanchors)];
        else                                   v = cirg_opnd(g, b);
        if (v->kind == CIR_VAL_CONST) continue;
        bool dup = false;
        for (uint32_t i = 0; i < nused; i++) if (used[i] == v) dup = true;
        if (!dup) return v;
    }
    return cirg_opnd(g, b);
}

static cbae_cir_value_t *cirg_const(cirg_t *g) { return g->consts[cirr_below(&g->rng, CIRG_KCONST_N)]; }

static cbae_cir_type_t cirg_type_of(cirg_class_t c) {
    switch (c) {
        case CIRG_I32: return cir_type_i(32);
        case CIRG_I16: return cir_type_i(16);
        case CIRG_I8:  return cir_type_i(8);
        case CIRG_I1:  return cir_type_i1();
        default:       return cir_type_i(64);
    }
}

static cirg_class_t cirg_class_of_type(cbae_cir_type_t t) {
    switch (cir_type_bits(t)) {
        case 32: return CIRG_I32;
        case 16: return CIRG_I16;
        case 8:  return CIRG_I8;
        case 1:  return CIRG_I1;
        default: return CIRG_I64;
    }
}

static cbae_cir_value_t *cirg_def_binop(cirg_t *g, uint32_t b, cbae_cir_opcode_t op,
                                        cbae_cir_value_t *x, cbae_cir_value_t *y,
                                        cbae_cir_type_t ty) {
    cbae_cir_value_t *r = cbae_cir_binop(&g->bld, op, x, y, ty, 0);
    assert(r);
    cirg_add_def(&g->defs[b], r, cirg_class_of_type(ty));
    return r;
}

static cbae_cir_value_t *cirg_def_unop(cirg_t *g, uint32_t b, cbae_cir_opcode_t op,
                                       cbae_cir_value_t *x, cbae_cir_type_t ty) {
    cbae_cir_value_t *ops[1] = { x };
    cbae_cir_value_t *r = cbae_cir_emit(&g->bld, op, ty, 0, ops, 1);
    assert(r);
    cirg_add_def(&g->defs[b], r, cirg_class_of_type(ty));
    return r;
}

static int64_t cirg_disp(cirg_t *g) {
    static const int64_t small[] = { 0, 4, 8, 8, 12, 16, 24, 32, -4, -8, -8, -16, -24, 1, 2, 3, 5, 7 };
    const uint32_t r = cirr_below(&g->rng, 100);
    if (r < 70) return small[cirr_below(&g->rng, (uint32_t)(sizeof small / sizeof small[0]))];
    if (r < 85) return (int64_t)cirr_below(&g->rng, 129) - 64;
    return CIRG_KCONST[cirr_below(&g->rng, CIRG_KCONST_N)];
}

/* Emit an address expression in the shapes the lifter produces. A fresh MUL
 * (or SHL) and fresh ADDs every time, so two uses of one recipe are
 * different SSA values. */
static cbae_cir_value_t *cirg_emit_address(cirg_t *g, uint32_t b, const cirg_recipe_t *r) {
    const cbae_cir_type_t ty = r->ptr_ty ? cir_type_ptr() : cir_type_i(64);
    if (r->shape == 6) return cbae_cir_const(&g->bld, cir_type_ptr(), r->disp);

    if (r->shape == 7) {                       /* many operands: exercises the term caps */
        cbae_cir_value_t *a = r->sum_v[0];
        for (uint32_t i = 1; i < r->nsum; i++)
            a = cirg_def_binop(g, b, r->sum_neg[i] ? CIR_OP_SUB : CIR_OP_ADD, a, r->sum_v[i], ty);
        if (r->disp != 0)
            a = cirg_def_binop(g, b, CIR_OP_ADD, a, cbae_cir_const(&g->bld, cir_type_ptr(), r->disp), ty);
        return a;
    }

    cbae_cir_value_t *a = r->base;
    if (r->idx) {
        cbae_cir_value_t *scaled;
        if (r->use_shl) {
            const int64_t log2 = r->scale == 1 ? 0 : r->scale == 2 ? 1 : r->scale == 4 ? 2 : 3;
            scaled = cirg_def_binop(g, b, CIR_OP_SHL, r->idx,
                                    cbae_cir_const(&g->bld, cir_type_i(64), log2), ty);
        } else {
            scaled = cirg_def_binop(g, b, CIR_OP_MUL, r->idx,
                                    cbae_cir_const(&g->bld, cir_type_i(64), r->scale), ty);
        }
        a = a ? cirg_def_binop(g, b, CIR_OP_ADD, a, scaled, ty) : scaled;
    }
    if (r->shape == 1 || r->shape == 2) {
        cbae_cir_value_t *d = cbae_cir_const(&g->bld, cir_type_ptr(), r->disp);
        a = a ? cirg_def_binop(g, b, CIR_OP_ADD, a, d, ty) : d;
    } else if (r->shape == 3) {
        cbae_cir_value_t *d = cbae_cir_const(&g->bld, cir_type_ptr(), r->disp);
        a = cirg_def_binop(g, b, CIR_OP_SUB, a, d, ty);
    }
    return a;
}

/* An address for a memory access (or an address value to leave lying
 * around): a reused recipe about 40% of the time. */
static cbae_cir_value_t *cirg_address(cirg_t *g, uint32_t b) {
    cirr_rng_t *rng = &g->rng;
    cirg_recipe_t rc;
    bool reuse = false;

    if (g->nrecipes && cirr_pct(rng, 40)) {
        for (int tries = 0; tries < 8 && !reuse; tries++) {
            const cirg_recipe_t *c = &g->recipes[cirr_below(rng, g->nrecipes)];
            if (!((g->dom[b] >> c->blk) & 1u)) continue;     /* its operands might not be available here */
            rc = *c;
            if (cirr_pct(rng, 50)) rc.disp = cirg_disp(g);
            reuse = true;
        }
    }
    if (!reuse) {
        memset(&rc, 0, sizeof rc);
        const uint32_t r = cirr_below(rng, 100);
        rc.shape = r < 12 ? 0 : r < 38 ? 1 : r < 56 ? 2 : r < 63 ? 3 : r < 67 ? 4 : r < 79 ? 5 : r < 84 ? 6 : 7;
        rc.base  = rc.shape == 4 || rc.shape == 6 || rc.shape == 7 ? NULL : cirg_base(g, b);
        rc.idx   = rc.shape == 2 || rc.shape == 4 || rc.shape == 5 ? cirg_opnd(g, b) : NULL;
        if (rc.shape == 7) {
            const uint32_t q = cirr_below(rng, 100);
            rc.nsum = (uint8_t)(q < 40 ? 3 + cirr_below(rng, 2) : q < 80 ? 5 + cirr_below(rng, 4)
                                                                         : 9 + cirr_below(rng, 3));
            for (uint32_t i = 0; i < rc.nsum; i++) {
                rc.sum_v[i]   = cirg_sum_operand(g, b, rc.sum_v, i);
                rc.sum_neg[i] = cirr_pct(rng, 25);
            }
        }
        rc.scale = (int64_t)1 << cirr_below(rng, 4);
        rc.disp  = rc.shape == 6 ? (int64_t)CIRR_POOL[cirr_below(rng, 11)] : cirg_disp(g);
        rc.use_shl = cirr_pct(rng, 30);
        rc.ptr_ty  = cirr_pct(rng, 50);
        rc.blk   = b;
        if (g->nrecipes < CIRG_MAX_RECIPES) g->recipes[g->nrecipes++] = rc;
    }
    return cirg_emit_address(g, b, &rc);
}

static cirg_class_t cirg_data_class(cirg_t *g) {
    const uint32_t r = cirr_below(&g->rng, 100);
    return r < 55 ? CIRG_I64 : r < 75 ? CIRG_I32 : r < 90 ? CIRG_I16 : CIRG_I8;
}

/* Narrow arithmetic: a result that wraps at 8, 16 or 32 bits, fed by wide or
 * narrow operands. */
static void cirg_emit_narrow(cirg_t *g, uint32_t b) {
    cirr_rng_t *rng = &g->rng;
    const cirg_class_t c = (cirg_class_t)(CIRG_I32 + cirr_below(rng, 3));
    const cbae_cir_type_t ty = cirg_type_of(c);
    cbae_cir_value_t *x = cirr_pct(rng, 60) ? cirg_pick(g, b, c) : NULL;
    if (!x) x = cirg_opnd(g, b);
    const uint32_t r = cirr_below(rng, 100);
    if (r < 12) {
        cirg_def_unop(g, b, CIR_OP_NEG, x, ty);
    } else if (r < 22) {
        cirg_def_unop(g, b, CIR_OP_COPY, x, ty);
    } else if (r < 28) {
        cirg_def_unop(g, b, CIR_OP_NOT, x, ty);
    } else {
        static const cbae_cir_opcode_t ops[7] = { CIR_OP_ADD, CIR_OP_SUB, CIR_OP_MUL, CIR_OP_AND,
                                                  CIR_OP_OR, CIR_OP_XOR, CIR_OP_SHL };
        const cbae_cir_opcode_t op = ops[cirr_below(rng, 7)];
        cbae_cir_value_t *y;
        if (op == CIR_OP_SHL)       y = g->shift_counts[cirr_below(rng, CIRG_KSHIFT_N)];
        else if (cirr_pct(rng, 40)) y = cirg_const(g);
        else if (cirr_pct(rng, 50)) { y = cirg_pick(g, b, c); if (!y) y = cirg_opnd(g, b); }
        else                        y = cirg_opnd(g, b);
        cirg_def_binop(g, b, op, x, y, ty);
    }
}

/* ecx - edx with both lifted to "other": a difference of two conflated
 * values, added to a base and loaded from. The two are NOT equal at run time,
 * so the load must not be treated as an access to the base itself. */
static bool cirg_emit_cancel_pair(cirg_t *g, uint32_t b) {
    cbae_cir_value_t *cand[16];
    uint32_t nc = 0;
    for (uint32_t i = 0; i < g->nconflated; i++)
        if ((g->dom[b] >> g->conflated_blk[i]) & 1u) cand[nc++] = g->conflated[i];
    if (nc == 0) return false;
    cbae_cir_value_t *x = cand[cirr_below(&g->rng, nc)], *y = cand[cirr_below(&g->rng, nc)];
    cbae_cir_value_t *d = cirg_def_binop(g, b, CIR_OP_SUB, x, y, cir_type_i(64));
    cbae_cir_value_t *a = cirg_def_binop(g, b, CIR_OP_ADD, cirg_base(g, b), d, cir_type_ptr());
    cbae_cir_value_t *v = cbae_cir_load(&g->bld, a, cir_type_i(64), 0);
    assert(v);
    cirg_add_def(&g->defs[b], v, CIRG_I64);
    return true;
}

static void cirg_emit_random(cirg_t *g, uint32_t b) {
    cirr_rng_t *rng = &g->rng;
    const uint32_t r = cirr_below(rng, 100);
    const cbae_cir_type_t t64 = cir_type_i(64);

    if (r < 14) {
        cirg_def_binop(g, b, CIR_OP_ADD, cirg_opnd(g, b),
                       cirr_pct(rng, 70) ? cirg_const(g) : cirg_opnd(g, b), t64);
    } else if (r < 22) {
        cirg_def_binop(g, b, CIR_OP_SUB, cirg_opnd(g, b),
                       cirr_pct(rng, 70) ? cirg_const(g) : cirg_opnd(g, b), t64);
    } else if (r < 27) {
        cirg_def_binop(g, b, CIR_OP_MUL, cirg_opnd(g, b), cirg_const(g), t64);
    } else if (r < 30) {
        cirg_def_binop(g, b, CIR_OP_MUL, cirg_opnd(g, b), cirg_opnd(g, b), t64);
    } else if (r < 34) {
        cirg_def_binop(g, b, CIR_OP_SHL, cirg_opnd(g, b),
                       g->shift_counts[cirr_below(rng, CIRG_KSHIFT_N)], t64);
    } else if (r < 35) {
        cirg_def_binop(g, b, CIR_OP_SHL, cirg_opnd(g, b), cirg_opnd(g, b), t64);
    } else if (r < 37) {
        cirg_def_unop(g, b, CIR_OP_NEG, cirg_opnd(g, b), t64);
    } else if (r < 39) {
        cirg_def_unop(g, b, CIR_OP_COPY, cirg_opnd(g, b), t64);
    } else if (r < 43) {
        static const cbae_cir_opcode_t ops[3] = { CIR_OP_AND, CIR_OP_OR, CIR_OP_XOR };
        cirg_def_binop(g, b, ops[cirr_below(rng, 3)], cirg_opnd(g, b), cirg_opnd(g, b), t64);
    } else if (r < 45) {
        static const cbae_cir_opcode_t ops[2] = { CIR_OP_SHR, CIR_OP_SAR };
        if (cirr_pct(rng, 70))
            cirg_def_binop(g, b, ops[cirr_below(rng, 2)], cirg_opnd(g, b),
                           g->shift_counts[cirr_below(rng, CIRG_KSHIFT_N)], t64);
        else
            cirg_def_unop(g, b, CIR_OP_NOT, cirg_opnd(g, b), t64);
    } else if (r < 51) {
        cirg_emit_narrow(g, b);
    } else if (r < 64) {
        const cirg_class_t c = cirg_data_class(g);
        cbae_cir_value_t *v = cbae_cir_load(&g->bld, cirg_address(g, b), cirg_type_of(c), 0);
        assert(v);
        cirg_add_def(&g->defs[b], v, c);
    } else if (r < 77) {
        const cirg_class_t c = cirg_data_class(g);
        cbae_cir_value_t *data = c == CIRG_I64 ? cirg_i64(g, b) : cirg_pick(g, b, c);
        if (!data) data = cbae_cir_const(&g->bld, cirg_type_of(c),
                                         (int64_t)CIRR_POOL[cirr_below(rng, CIRR_POOL_N)]);
        cbae_cir_store(&g->bld, cirg_address(g, b), data, 0);
    } else if (r < 80) {
        cbae_cir_value_t *args[2];
        const uint8_t argc = (uint8_t)cirr_below(rng, 3);
        for (uint8_t i = 0; i < argc; i++) args[i] = cirg_opnd(g, b);
        cbae_cir_value_t *v = cbae_cir_call(&g->bld, "ext_fn", args, argc, t64, 0);
        assert(v);
        cirg_add_def(&g->defs[b], v, CIRG_I64);
    } else if (r < 87) {
        cirg_class_t c = CIRG_I64;
        if (cirr_pct(rng, 30)) c = (cirg_class_t)(CIRG_I32 + cirr_below(rng, 3));
        cbae_cir_value_t *x = cirg_pick(g, b, c), *y = cirg_pick(g, b, c);
        if (!x || !y) { x = cirg_i64(g, b); y = cirg_i64(g, b); }
        cirg_def_binop(g, b, cirr_pct(rng, 80) ? CIR_OP_CMP : CIR_OP_TEST, x, y, cir_type_i1());
    } else if (r < 91 && cirg_emit_cancel_pair(g, b)) {
        /* emitted */
    } else {
        (void)cirg_address(g, b);       /* an address value other instructions may pick up */
    }
}

/* The value a back edge feeds into a phi. Kind 1 is an induction variable;
 * the rest are the other recurrences a loop-header phi can carry. Some are
 * identities (x*1, x<<0, a copy), which make the phi redundant; the others
 * change the value every iteration and must never be treated as copies. */
static cbae_cir_value_t *cirg_recurrence(cirg_t *g, uint32_t b, cbae_cir_value_t *phi, uint8_t kind) {
    cirr_rng_t *rng = &g->rng;
    const cbae_cir_type_t t64 = cir_type_i(64);
    switch (kind) {
        case 1: {
            static const int64_t st[] = { 1, 4, 8, 8, 16, -8 };
            return cirg_def_binop(g, b, CIR_OP_ADD, phi,
                                  cbae_cir_const(&g->bld, t64, st[cirr_below(rng, 6)]), t64);
        }
        case 2: {
            static const int64_t k[] = { 2, 3, -1, 1 };
            return cirg_def_binop(g, b, CIR_OP_MUL, phi,
                                  cbae_cir_const(&g->bld, t64, k[cirr_below(rng, 4)]), t64);
        }
        case 3: {
            static const int64_t c[] = { 1, 2, 0 };
            return cirg_def_binop(g, b, CIR_OP_SHL, phi,
                                  cbae_cir_const(&g->bld, t64, c[cirr_below(rng, 3)]), t64);
        }
        case 4: return cirg_def_unop(g, b, CIR_OP_NEG, phi, t64);
        case 5: return cirg_def_binop(g, b, CIR_OP_ADD, phi, cirg_opnd(g, b), t64);
        case 6: return cirg_def_binop(g, b, CIR_OP_SUB, phi,
                                      cbae_cir_const(&g->bld, t64, cirr_pct(rng, 50) ? 8 : -4), t64);
        case 7: return cirg_def_binop(g, b, CIR_OP_ADD, phi, phi, t64);
        default: return cirg_def_unop(g, b, CIR_OP_COPY, phi, t64);
    }
}

/* Make the CFG skeleton: tree + extra edges + predecessor lists + dominators. */
static void cirg_skeleton(cirg_t *g, const cirg_params_t *p) {
    cirr_rng_t *rng = &g->rng;
    const uint32_t n = p->min_blocks + cirr_below(rng, p->max_blocks - p->min_blocks + 1);
    assert(n >= 2 && n <= CIRG_MAX_BLOCKS);
    g->nblocks = n;

    for (uint32_t i = 1; i < n; i++) {
        uint32_t cand[CIRG_MAX_BLOCKS], nc = 0;
        for (uint32_t j = 0; j < i; j++) if (g->nsucc[j] < 2) cand[nc++] = j;
        assert(nc > 0);
        const uint32_t par = cand[cirr_below(rng, nc)];
        g->succ[par][g->nsucc[par]++] = i;
    }
    for (uint32_t a = 0; a < 2 * n; a++) {
        const uint32_t u = cirr_below(rng, n), v = 1 + cirr_below(rng, n - 1);
        if (g->nsucc[u] >= 2 || !cirr_pct(rng, p->extra_edge_pct)) continue;
        if (g->nsucc[u] == 1 && g->succ[u][0] == v) continue;
        g->succ[u][g->nsucc[u]++] = v;
    }
    for (uint32_t u = 0; u < n; u++)
        for (uint32_t k = 0; k < g->nsucc[u]; k++) {
            const uint32_t v = g->succ[u][k];
            g->pred[v][g->npred[v]++] = u;
        }

    const uint32_t all = n == 32 ? 0xFFFFFFFFu : ((1u << n) - 1u);
    for (uint32_t b = 0; b < n; b++) g->dom[b] = b == 0 ? 1u : all;
    for (bool changed = true; changed; ) {
        changed = false;
        for (uint32_t b = 1; b < n; b++) {
            uint32_t d = all;
            for (uint32_t k = 0; k < g->npred[b]; k++) d &= g->dom[g->pred[b][k]];
            d |= 1u << b;
            if (d != g->dom[b]) { g->dom[b] = d; changed = true; }
        }
    }
}

static bool cirg_has_back_pred(const cirg_t *g, uint32_t b) {
    for (uint32_t k = 0; k < g->npred[b]; k++)
        if ((g->dom[g->pred[b][k]] >> b) & 1u) return true;     /* b dominates its predecessor */
    return false;
}

/** Three sizes, chosen by seed so a run of consecutive seeds covers them all. */
static cirg_params_t cirg_params_for_seed(uint64_t seed) {
    static const cirg_params_t P[3] = {
        { 2,  6,  6, 35 },
        { 5, 14,  8, 30 },
        { 12, 32, 10, 22 },
    };
    return P[seed % 3];
}

/** Build one random valid-SSA function from `seed`. Returns false only if
 *  the arena or builder failed (never expected). On success the function
 *  has passed the structural verifier. Release with cirg_free(). */
static bool cirg_build(cirg_t **out, uint64_t seed, const cirg_params_t *p) {
    cirg_t *g = calloc(1, sizeof *g);
    if (!g) return false;
    g->rng.s = seed * 0x2545F4914F6CDD1Dull + 0x1234567ull;
    cirr_rng_t *rng = &g->rng;

    if (cbae_arena_init(&g->arena, 8u * 1024 * 1024) != CBAE_OK) { free(g); return false; }
    if (cbae_cir_function_create(&g->arena, 0x1000, "random", &g->f) != CBAE_OK) {
        cbae_arena_destroy(&g->arena); free(g); return false;
    }
    cirg_skeleton(g, p);
    for (uint32_t i = 0; i < g->nblocks; i++)
        if (cbae_cir_block_create(g->f, 0x1000 + 0x10 * (cbae_addr_t)i, &g->blk[i]) != CBAE_OK)
            return false;
    cbae_cir_builder_init(&g->bld, g->f, g->blk[0]);

    /* Globals: eight parameters, a fixed set of i64 constants, and a few
     * narrow constants, some too wide for their own type. */
    static const cbae_reg_t regs[8] = { CBAE_REG_RAX, CBAE_REG_RBX, CBAE_REG_RCX, CBAE_REG_RDX,
                                        CBAE_REG_RSI, CBAE_REG_RDI, CBAE_REG_R8,  CBAE_REG_R9 };
    for (int i = 0; i < 8; i++) {
        g->params[i] = cbae_cir_param(&g->bld, regs[i]);
        cirg_add_def(&g->globals, g->params[i], CIRG_I64);
    }
    g->other = cbae_cir_param(&g->bld, CBAE_REG_OTHER);
    cirg_add_def(&g->globals, g->other, CIRG_I64);
    for (uint32_t i = 0; i < CIRG_KCONST_N; i++) {
        g->consts[i] = cbae_cir_const(&g->bld, cir_type_i(64), CIRG_KCONST[i]);
        cirg_add_def(&g->globals, g->consts[i], CIRG_I64);
    }
    static const struct { cirg_class_t c; int64_t v; } narrow[] = {
        { CIRG_I32, -1 }, { CIRG_I32, 0x7FFFFFFF }, { CIRG_I32, 0x80000000ll }, { CIRG_I32, 0x100000008ll },
        { CIRG_I16, -1 }, { CIRG_I16, 0x1234 },     { CIRG_I16, 70000 },
        { CIRG_I8, -1 },  { CIRG_I8, 0x7F },        { CIRG_I8, 200 },
    };
    for (size_t i = 0; i < sizeof narrow / sizeof narrow[0]; i++)
        cirg_add_def(&g->globals,
                     cbae_cir_const(&g->bld, cirg_type_of(narrow[i].c), narrow[i].v), narrow[i].c);
    for (uint32_t i = 0; i < CIRG_KSHIFT_N; i++)
        g->shift_counts[i] = cbae_cir_const(&g->bld, cir_type_i(64), CIRG_KSHIFT[i]);

    for (uint32_t b = 0; b < g->nblocks; b++) {
        cbae_cir_builder_init(&g->bld, g->f, g->blk[b]);

        /* Phis, empty for now; about one in six is narrow. */
        uint32_t nphi = 0;
        if (b > 0 && g->npred[b] >= 2) nphi = 1 + cirr_below(rng, 3);
        else if (b > 0 && cirr_pct(rng, 25)) nphi = 1;
        for (uint32_t k = 0; k < nphi; k++) {
            const cirg_class_t pc = cirr_pct(rng, 84) ? CIRG_I64
                                                      : (cirg_class_t)(CIRG_I32 + cirr_below(rng, 3));
            cbae_cir_value_t *ph = cbae_cir_phi_create(g->f, g->blk[b], cirg_type_of(pc));
            assert(ph);
            g->phi[b][k]      = ph;
            g->phi_main[b][k] = cirr_pct(rng, 15) ? g->other
                              : cirr_pct(rng, 60) ? g->params[cirr_below(rng, 8)] : cirg_const(g);
            if (cirg_has_back_pred(g, b) && cirr_pct(rng, 55)) {
                const uint32_t q = cirr_below(rng, 100);
                g->phi_rec[b][k] = (uint8_t)(q < 40 ? 1 : q < 50 ? 2 : q < 58 ? 3 : q < 64 ? 4 :
                                             q < 78 ? 5 : q < 86 ? 6 : q < 92 ? 7 : 8);
            }
            cirg_add_def(&g->defs[b], ph, pc);
            if (g->phi_main[b][k] == g->other && g->nconflated < 16) {
                g->conflated[g->nconflated]     = ph;
                g->conflated_blk[g->nconflated] = b;
                g->nconflated++;
            }
        }
        g->nphi[b] = nphi;

        if (b == 0) {                     /* distinct stable atoms for every later block */
            for (int i = 0; i < 6; i++) {
                cbae_cir_value_t *a;
                if (i < 3) {
                    a = cbae_cir_load(&g->bld, cirg_address(g, 0), cir_type_i(64), 0);
                } else {
                    cbae_cir_value_t *arg = g->params[cirr_below(rng, 8)];
                    a = cbae_cir_call(&g->bld, "ext_fn", &arg, (uint8_t)(i & 1), cir_type_i(64), 0);
                }
                assert(a);
                cirg_add_def(&g->defs[0], a, CIRG_I64);
                g->anchors[g->nanchors++] = a;
            }
        }

        const uint32_t body = 1 + cirr_below(rng, p->max_body);
        for (uint32_t i = 0; i < body; i++) cirg_emit_random(g, b);

        /* Induction steps for the back edges leaving this block. */
        for (uint32_t k = 0; k < g->nsucc[b]; k++) {
            const uint32_t v = g->succ[b][k];
            if (!((g->dom[b] >> v) & 1u)) continue;               /* not a back edge */
            for (uint32_t j = 0; j < g->nphi[v]; j++) {
                if (!g->phi_rec[v][j]) continue;
                g->induct_in[v][j][b] = cirg_recurrence(g, b, g->phi[v][j], g->phi_rec[v][j]);
            }
        }

        /* Terminator. */
        if (g->nsucc[b] == 0) {
            cbae_cir_return(&g->bld, cirr_pct(rng, 70) ? cirg_opnd(g, b) : NULL, 0);
        } else if (g->nsucc[b] == 1) {
            cbae_cir_jump(&g->bld, g->blk[g->succ[b][0]], 0);
        } else {
            cbae_cir_value_t *cond = cirr_pct(rng, 50) ? cirg_pick(g, b, CIRG_I1) : NULL;
            if (!cond)
                cond = cirg_def_binop(g, b, CIR_OP_CMP, cirg_i64(g, b), cirg_i64(g, b), cir_type_i1());
            cbae_cir_branch(&g->bld, cond, g->blk[g->succ[b][0]], g->blk[g->succ[b][1]], 0);
        }
    }

    /* Fill the phis: values available at the end of each predecessor. */
    for (uint32_t b = 0; b < g->nblocks; b++)
        for (uint32_t k = 0; k < g->nphi[b]; k++)
            for (uint32_t q = 0; q < g->npred[b]; q++) {
                const uint32_t P = g->pred[b][q];
                cbae_cir_value_t *val;
                const uint32_t r = cirr_below(rng, 100);
                if (g->induct_in[b][k][P])                              val = g->induct_in[b][k][P];
                else if (g->phi_main[b][k] == g->other && r < 90)       val = g->other;
                else if (r < 35)                                        val = g->phi_main[b][k];
                else if (r < 55 && ((g->dom[P] >> b) & 1u))             val = g->phi[b][k];
                else                                                    val = cirg_opnd(g, P);
                assert(val);
                const cbae_err_t rc = cbae_cir_phi_add_incoming(g->f, g->phi[b][k]->u.def_insn, val, P);
                assert(rc == CBAE_OK);
                (void)rc;
            }

    const cbae_cir_verify_result_t vr = cbae_cir_verify_function(g->f);
    if (!vr.ok) {
        fprintf(stderr, "cirg_build: seed %llu produced invalid CIR: %s\n",
                (unsigned long long)seed, vr.message);
        abort();
    }
    *out = g;
    return true;
}

static void cirg_free(cirg_t *g) {
    if (!g) return;
    cbae_cir_function_destroy(g->f);
    cbae_arena_destroy(&g->arena);
    free(g);
}

/* ── Interpreter ─────────────────────────────────────────────────────── */

typedef struct {
    uint64_t key;       /* byte address                                  */
    int32_t  writer;    /* id of the instruction that wrote it last       */
    uint8_t  val;
    uint8_t  used;
} cirx_slot_t;

typedef struct {
    cirx_slot_t *slots;
    size_t       cap, count;
    uint64_t     seed;
} cirx_mem_t;

typedef struct cirx_hooks {
    void *user;
    /** `insn` defined a value (phis included). */
    void (*on_def)(void *user, const cbae_cir_instruction_t *insn, uint64_t value, uint64_t step);
    /** A LOAD or STORE touched [addr, addr+size). */
    void (*on_access)(void *user, const cbae_cir_instruction_t *insn, uint64_t addr,
                      uint32_t size, bool is_store, uint64_t step);
    /** A LOAD read [addr, addr+size); writers[i] is the id of the instruction
     *  that last wrote byte i, or -1 if it still holds its initial content. */
    void (*on_load)(void *user, const cbae_cir_instruction_t *insn, uint64_t addr,
                    uint32_t size, const int32_t *writers);
    /** A CALL overwrote [addr, addr+size). */
    void (*on_call_write)(void *user, const cbae_cir_instruction_t *insn, uint64_t addr, uint32_t size);
} cirx_hooks_t;

typedef struct { uint64_t steps; bool returned; } cirx_result_t;

static inline uint64_t cirx_mask(cbae_cir_type_t t) {
    const unsigned bits = cir_type_bits(t);
    return bits >= 64 ? ~0ull : bits == 0 ? 0ull : ((1ull << bits) - 1ull);
}

static void cirx_mem_init(cirx_mem_t *m, uint64_t seed) {
    m->cap = 1u << 10;
    m->count = 0;
    m->seed = seed;
    m->slots = calloc(m->cap, sizeof *m->slots);
    assert(m->slots);
}
static void cirx_mem_destroy(cirx_mem_t *m) { free(m->slots); m->slots = NULL; }

static cirx_slot_t *cirx_mem_find(const cirx_mem_t *m, uint64_t addr) {
    size_t i = (size_t)(cirr_mix(addr) & (m->cap - 1));
    while (m->slots[i].used) {
        if (m->slots[i].key == addr) return &m->slots[i];
        i = (i + 1) & (m->cap - 1);
    }
    return NULL;
}

static void cirx_mem_put(cirx_mem_t *m, uint64_t addr, uint8_t val, int32_t writer) {
    cirx_slot_t *s = cirx_mem_find(m, addr);
    if (!s) {
        if ((m->count + 1) * 2 > m->cap) {
            cirx_slot_t *old = m->slots;
            const size_t oldcap = m->cap;
            m->cap *= 2;
            m->slots = calloc(m->cap, sizeof *m->slots);
            assert(m->slots);
            for (size_t i = 0; i < oldcap; i++) {
                if (!old[i].used) continue;
                size_t j = (size_t)(cirr_mix(old[i].key) & (m->cap - 1));
                while (m->slots[j].used) j = (j + 1) & (m->cap - 1);
                m->slots[j] = old[i];
            }
            free(old);
        }
        size_t i = (size_t)(cirr_mix(addr) & (m->cap - 1));
        while (m->slots[i].used) i = (i + 1) & (m->cap - 1);
        s = &m->slots[i];
        s->used = 1;
        s->key = addr;
        m->count++;
    }
    s->val = val;
    s->writer = writer;
}

/* The content of a byte nobody has written yet: derived from its address;
 * most quad-words look like pointers into the shared pool. */
static uint8_t cirx_initial_byte(uint64_t seed, uint64_t addr) {
    const uint64_t h = cirr_mix(seed ^ cirr_mix(addr & ~7ull));
    const uint64_t q = (h & 3u) ? CIRR_POOL[(h >> 2) % CIRR_POOL_N] : h;
    return (uint8_t)(q >> (8 * (addr & 7u)));
}

static uint64_t cirx_read(const cirx_mem_t *m, uint64_t addr, uint32_t size, int32_t *writers) {
    uint64_t v = 0;
    for (uint32_t i = 0; i < size; i++) {
        const cirx_slot_t *s = cirx_mem_find(m, addr + i);
        const uint8_t b = s ? s->val : cirx_initial_byte(m->seed, addr + i);
        if (writers) writers[i] = s ? s->writer : -1;
        if (i < 8) v |= (uint64_t)b << (8 * i);
    }
    return v;
}

static void cirx_write(cirx_mem_t *m, uint64_t addr, uint32_t size, uint64_t v, int32_t writer) {
    for (uint32_t i = 0; i < size; i++)
        cirx_mem_put(m, addr + i, (uint8_t)(i < 8 ? v >> (8 * i) : 0), writer);
}

static uint64_t cirx_param_init(uint64_t seed, cbae_reg_t reg) {
    return CIRR_POOL[cirr_mix(seed * 31 + (uint64_t)reg) % CIRR_POOL_N];
}

/** The value of a parameter or constant in the run seeded by `seed`. */
static inline uint64_t cirx_leaf_value(uint64_t seed, const cbae_cir_value_t *v) {
    if (v->kind == CIR_VAL_CONST) return (uint64_t)v->u.const_val & cirx_mask(v->type);
    assert(v->kind == CIR_VAL_PARAM);
    return cirx_param_init(seed, v->u.param_reg);
}

/* Interpreter state shared by every read. */
typedef struct {
    uint64_t   *val;
    uint8_t    *def;
    uint8_t    *vol;      /* the "other" register: every READ may see a different value */
    cirr_rng_t *rng;
} cirx_state_t;

/* The lifter maps every narrow register to the one parameter "other", so a
 * single SSA value stands for many different run-time values. The most
 * hostile reading is that each read of it is an unrelated number. */
static inline uint64_t cirx_get(const cirx_state_t *s, const cbae_cir_value_t *v) {
    if (v->kind == CIR_VAL_CONST) return (uint64_t)v->u.const_val & cirx_mask(v->type);
    assert(s->def[v->id] && "use of a value before its definition");
    if (s->vol[v->id]) return CIRR_POOL[cirr_below(s->rng, CIRR_POOL_N)];
    return s->val[v->id];
}

/** Run `f` from its entry block. `seed` fixes the initial registers, the
 *  initial memory and every arbitrary choice. */
static void cirx_run(const cbae_cir_function_t *f, uint64_t seed, uint64_t max_steps,
                     const cirx_hooks_t *hk, cirx_result_t *res) {
    const uint32_t nvals = f->next_value_id;
    uint64_t *val = calloc(nvals ? nvals : 1, sizeof *val);
    uint8_t  *def = calloc(nvals ? nvals : 1, 1);
    uint8_t  *vol = calloc(nvals ? nvals : 1, 1);
    assert(val && def && vol);
    cirr_rng_t rng = { .s = seed ^ 0xC0FFEEull };
    const cirx_state_t state = { val, def, vol, &rng };
    cirx_mem_t mem;
    cirx_mem_init(&mem, seed);

    const uint32_t nv = (uint32_t)cbae_vector_count(&f->values);
    for (uint32_t i = 0; i < nv; i++) {
        const cbae_cir_value_t *v = *(cbae_cir_value_t **)cbae_vector_at(&f->values, i);
        if (v->kind == CIR_VAL_PARAM) {
            val[v->id] = cirx_leaf_value(seed, v);
            def[v->id] = 1;
            vol[v->id] = v->u.param_reg == CBAE_REG_OTHER;
        }
    }

#define GET(v_) cirx_get(&state, (v_))

    uint64_t recent[16] = { 0 };
    uint32_t nrecent = 0;
    uint64_t steps = 0;
    uint32_t cur = 0, prev = UINT32_MAX;
    bool returned = false;

    while (!returned && steps < max_steps) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, cur);

        /* Phis: a parallel copy from the edge just taken. */
        uint32_t ip = 0;
        uint64_t newv[16];
        uint32_t nphi = 0;
        while (ip < blk->instruction_count && blk->instructions[ip]->opcode == CIR_OP_PHI) {
            const cbae_cir_instruction_t *ph = blk->instructions[ip];
            assert(nphi < 16 && prev != UINT32_MAX);
            bool found = false;
            for (uint32_t k = 0; k < ph->phi_incoming_count; k++) {
                if (ph->phi_incoming_blocks[k] != prev) continue;
                newv[nphi] = GET(ph->phi_incoming_values[k]);
                found = true;
                break;
            }
            assert(found);
            nphi++;
            ip++;
        }
        for (uint32_t k = 0; k < nphi; k++) {            /* all phis become defined together... */
            const cbae_cir_instruction_t *ph = blk->instructions[k];
            val[ph->result->id] = newv[k] & cirx_mask(ph->result->type);
            def[ph->result->id] = 1;
        }
        if (hk && hk->on_def)                            /* ...then they are reported */
            for (uint32_t k = 0; k < nphi; k++) {
                const cbae_cir_instruction_t *ph = blk->instructions[k];
                hk->on_def(hk->user, ph, val[ph->result->id], steps);
            }
        steps++;

        uint32_t next = UINT32_MAX;
        for (; ip < blk->instruction_count && !returned && next == UINT32_MAX; ip++) {
            const cbae_cir_instruction_t *in = blk->instructions[ip];
            steps++;
            uint64_t r = 0;
            bool has_result = in->result != NULL;
            const uint64_t m = in->result ? cirx_mask(in->result->type) : ~0ull;

            switch (in->opcode) {
                case CIR_OP_ADD: r = GET(in->operands[0]) + GET(in->operands[1]); break;
                case CIR_OP_SUB: r = GET(in->operands[0]) - GET(in->operands[1]); break;
                case CIR_OP_MUL: r = GET(in->operands[0]) * GET(in->operands[1]); break;
                case CIR_OP_AND: r = GET(in->operands[0]) & GET(in->operands[1]); break;
                case CIR_OP_OR:  r = GET(in->operands[0]) | GET(in->operands[1]); break;
                case CIR_OP_XOR: r = GET(in->operands[0]) ^ GET(in->operands[1]); break;
                case CIR_OP_NOT: r = ~GET(in->operands[0]); break;
                case CIR_OP_NEG: r = (uint64_t)0 - GET(in->operands[0]); break;
                case CIR_OP_COPY: r = GET(in->operands[0]); break;
                case CIR_OP_SHL: r = GET(in->operands[0]) << (GET(in->operands[1]) & 63u); break;
                case CIR_OP_SHR: r = GET(in->operands[0]) >> (GET(in->operands[1]) & 63u); break;
                case CIR_OP_SAR: r = (uint64_t)((int64_t)GET(in->operands[0]) >>
                                                (GET(in->operands[1]) & 63u)); break;
                case CIR_OP_CMP:
                case CIR_OP_TEST:
                    (void)GET(in->operands[0]);
                    (void)GET(in->operands[1]);
                    r = cirr_next(&rng) & 1u;
                    break;
                case CIR_OP_LOAD: {
                    const uint64_t addr = GET(in->operands[0]);
                    const uint32_t size = cir_type_bytes(in->result->type);
                    int32_t writers[8];
                    r = cirx_read(&mem, addr, size, writers);
                    if (hk && hk->on_access) hk->on_access(hk->user, in, addr, size, false, steps);
                    if (hk && hk->on_load)   hk->on_load(hk->user, in, addr, size, writers);
                    recent[nrecent++ & 15u] = addr;
                    break;
                }
                case CIR_OP_STORE: {
                    const uint64_t addr = GET(in->operands[0]);
                    const uint64_t data = GET(in->operands[1]);
                    const uint32_t size = cir_type_bytes(in->operands[1]->type);
                    cirx_write(&mem, addr, size, data, (int32_t)in->id);
                    if (hk && hk->on_access) hk->on_access(hk->user, in, addr, size, true, steps);
                    recent[nrecent++ & 15u] = addr;
                    has_result = false;
                    break;
                }
                case CIR_OP_CALL: {
                    for (uint8_t k = 0; k < in->operand_count; k++) (void)GET(in->operands[k]);
                    r = cirr_pct(&rng, 60) ? CIRR_POOL[cirr_below(&rng, CIRR_POOL_N)] : cirr_next(&rng);
                    const uint32_t nw = 1 + cirr_below(&rng, 3);
                    for (uint32_t k = 0; k < nw; k++) {
                        uint64_t a;
                        if (nrecent && cirr_pct(&rng, 70))
                            a = recent[cirr_below(&rng, nrecent < 16 ? nrecent : 16)] +
                                8 * (uint64_t)cirr_below(&rng, 2);
                        else
                            a = CIRR_POOL[cirr_below(&rng, CIRR_POOL_N)];
                        cirx_write(&mem, a, 8, cirr_next(&rng), (int32_t)in->id);
                        if (hk && hk->on_call_write) hk->on_call_write(hk->user, in, a, 8);
                    }
                    break;
                }
                case CIR_OP_BRANCH:
                    next = (GET(in->operands[0]) & 1u) ? in->branch_true_block : in->branch_false_block;
                    has_result = false;
                    break;
                case CIR_OP_JUMP:
                    next = in->branch_true_block;
                    has_result = false;
                    break;
                case CIR_OP_RETURN:
                    if (in->operand_count) (void)GET(in->operands[0]);
                    returned = true;
                    has_result = false;
                    break;
                default:
                    assert(!"cirx_run: opcode not supported by the test interpreter");
            }
            if (has_result) {
                val[in->result->id] = r & m;
                def[in->result->id] = 1;
                if (hk && hk->on_def) hk->on_def(hk->user, in, val[in->result->id], steps);
            }
        }
        if (!returned) {
            if (next == UINT32_MAX) break;           /* a block without a terminator: stop */
            prev = cur;
            cur = next;
        }
    }
#undef GET

    if (res) { res->steps = steps; res->returned = returned; }
    cirx_mem_destroy(&mem);
    free(val);
    free(def);
    free(vol);
}

#endif /* CBAE_TEST_CIR_RANDOM_H */
