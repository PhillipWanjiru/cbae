/**
 * @file test_const_prop_soundness.c
 * @brief Constant propagation checked against real executions of random
 *        functions, and against an independent reference solver.
 *
 * test_const_prop.c holds the cases somebody worked out on paper. This test
 * asks the question the analysis exists to answer on functions nobody designed:
 * build a random valid-SSA function (cir_random.h, with its constant-flavoured
 * knobs on: chains of constant arithmetic, wrap-around at every width, shifts
 * by 0 / 63 / 64, the identities x&0 x*0 x|-1 x^x x-x 0<<x, constant branch
 * conditions), run it for real several times with different initial registers
 * and memory, and compare what happened with what was claimed. Half of the runs
 * read narrow values zero-extended, half sign-extended (CIR does not say which
 * is right when a narrow value feeds a wider operation; the claims must hold
 * under both).
 *
 * WHAT IS CHECKED (const_prop.h, SOUNDNESS CLAIM)
 *   1. Every execution of an instruction whose result the analysis calls
 *      CONSTANT c produces exactly c.
 *   2. No instruction ever produces a value the analysis calls UNREACHED.
 *   3. Control only enters blocks, and only takes edges, called executable.
 *   Statically, for every function: the entry is executable; an executable edge
 *   joins executable blocks and is a CFG edge; every executable block except the
 *   entry has an executable incoming edge; a branch on a constant i1 opens exactly
 *   the edge that constant selects, any other branch opens both, any other
 *   terminator opens all; results in dead blocks are UNREACHED and results in
 *   executable blocks are not; constants fit their width.
 *
 * EXACTNESS (what the runs cannot show)
 *   A run can refute a constant, never prove one, so imprecision and lost work
 *   (a user not re-evaluated after an input fell) would pass the checks above.
 *   Every function is therefore also solved by a deliberately naive reference
 *   (whole-function passes until nothing changes, no work lists) written from the
 *   header's rules, and the two must agree on every value, block and edge.
 *
 * THE TEST CHECKS ITSELF
 *   After the real runs the same runs are checked against false claims (every
 *   constant off by one, every unknown value "the constant 0", every value
 *   unreachable, no edge executable, no block executable, folded branches taking
 *   the other edge) and each forgery must be caught in every function where the
 *   real runs exercised what it forges. Statistics at the end show the claims were
 *   exercised in volume.
 *
 * Environment (for longer runs): CBAE_SOUNDNESS_FUNCS, CBAE_SOUNDNESS_SEED0,
 * CBAE_SOUNDNESS_RUNS, CBAE_SOUNDNESS_STEPS.
 */
#include "cir_random.h"
#include "cir/cir_printer.h"
#include "dataflow/const_prop.h"
#include "dataflow/use_def.h"
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t env_u64(const char *name, uint64_t dflt) {
    const char *s = getenv(name);
    if (!s || !*s) return dflt;
    char *end = NULL;
    const unsigned long long v = strtoull(s, &end, 10);
    return (end && !*end) ? (uint64_t)v : dflt;
}

/* ── Statistics (all uint64_t: stats_add relies on it) ───────────────── */

typedef struct {
    uint64_t funcs, blocks, loop_funcs;
    uint64_t results, st_const, st_varying, st_unreached, st_const_narrow, st_const_phi;
    uint64_t dead_blocks, branch_blocks, folded_branches;
    uint64_t ref_values, ref_blocks, ref_edges;
    uint64_t runs, sx_runs, steps;
    uint64_t def_execs, const_execs, phi_const_execs, varying_execs, varying_nonzero_execs;
    uint64_t block_execs, edge_execs, folded_branch_execs;
    uint64_t dyn_const, dyn_const_claimed;
} stats_t;

static void stats_add(stats_t *d, const stats_t *s) {
    uint64_t *a = (uint64_t *)d;
    const uint64_t *b = (const uint64_t *)s;
    for (size_t i = 0; i < sizeof *d / sizeof(uint64_t); i++) a[i] += b[i];
}

/* ── Per-function facts ──────────────────────────────────────────────── */

typedef struct {
    const cbae_cir_function_t *f;
    uint64_t                   seed;
    cbae_use_def_t             ud;
    cbae_const_prop_t          cp;
    uint32_t                   nblocks;
    uint8_t                   *folded;     /* [nblocks] executable BRANCH block with exactly one open edge */
    uint32_t                  *cnt;        /* [value id] executions over all real runs   */
    uint64_t                  *first;      /* [value id] the first value it took         */
    uint8_t                   *differs;    /* [value id] it took a second value          */
    int32_t                   *last_run;   /* [value id] the last run that defined it    */
    uint8_t                   *runs_seen;  /* [value id] how many different runs did     */
    int                        reported;
} fctx_t;

static const cbae_cir_block_t *blk_at(const cbae_cir_function_t *f, uint32_t b) {
    return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
}

static bool is_successor(const cbae_cir_function_t *f, uint32_t from, uint32_t to) {
    const cbae_cir_block_t *blk = blk_at(f, from);
    for (uint32_t k = 0; k < blk->successor_count; k++)
        if (blk->successors[k] == to) return true;
    return false;
}

static uint64_t width_mask(const cbae_cir_value_t *v) {
    const unsigned bits = cir_type_bits(v->type);
    return bits >= 64 ? UINT64_MAX : bits == 0 ? 0 : ((1ull << bits) - 1ull);
}

static void die(const fctx_t *fx, const char *fmt, ...) {
    fprintf(stderr, "\n=== STATIC VIOLATION: function seed %" PRIu64 " ===\n", fx->seed);
    cbae_cir_print_function(fx->f, stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* ── Reference solver ────────────────────────────────────────────────────
 * Whole-function passes until nothing changes. Written from the rules in
 * const_prop.h, in a different shape from const_prop.c: no work lists, no use
 * lists, no incremental edge opening. Lattice: 0 = unreached, 1 = constant,
 * 2 = varying. */

typedef struct { uint8_t k; uint64_t v; } rl_t;

typedef struct {
    uint8_t  *kind;      /* [value id] */
    uint64_t *val;
    uint8_t  *bexec;     /* [block]    */
    uint8_t  *eexec;     /* [block * 2 + successor slot] */
} ref_t;

static unsigned rbits(const cbae_cir_value_t *v) { return cir_type_bits(v->type); }

static rl_t rl_get(const ref_t *s, const cbae_cir_value_t *v) {
    rl_t r = { 2, 0 };
    if (v->kind == CIR_VAL_CONST) {
        if (rbits(v) != 0) { r.k = 1; r.v = (uint64_t)v->u.const_val & width_mask(v); }
    } else if (v->kind == CIR_VAL_INSN_RESULT) {
        r.k = s->kind[v->id];
        r.v = s->val[v->id];
    }
    return r;
}

static bool rl_is(rl_t x, uint64_t value, uint64_t mask) { return x.k == 1 && (x.v & mask) == value; }

static rl_t rl_meet(rl_t a, rl_t b) {
    if (a.k == 0) return b;
    if (b.k == 0) return a;
    if (a.k == 2 || b.k == 2) { rl_t r = { 2, 0 }; return r; }
    if (a.v == b.v) return a;
    rl_t r = { 2, 0 };
    return r;
}

static bool ref_edge_open(const ref_t *s, const cbae_cir_function_t *f, uint32_t from, uint32_t to) {
    if (!s->bexec[from]) return false;
    const cbae_cir_block_t *blk = blk_at(f, from);
    for (uint32_t k = 0; k < blk->successor_count; k++)
        if (blk->successors[k] == to) return s->eexec[(size_t)from * 2 + k] != 0;
    return false;
}

static rl_t ref_transfer(const ref_t *s, const cbae_cir_function_t *f, const cbae_cir_instruction_t *in,
                         uint32_t b) {
    const rl_t varying = { 2, 0 }, top = { 0, 0 };
    const unsigned rw = rbits(in->result);
    const uint64_t m = rw >= 64 ? UINT64_MAX : ((1ull << rw) - 1ull);
    rl_t out;

    switch (in->opcode) {
    case CIR_OP_ADD: case CIR_OP_SUB: case CIR_OP_MUL: case CIR_OP_AND: case CIR_OP_OR: case CIR_OP_XOR: {
        if (in->operand_count != 2 || rw == 0) return varying;
        const cbae_cir_value_t *x = in->operands[0], *y = in->operands[1];
        if (rbits(x) < rw || rbits(y) < rw) return varying;
        const rl_t a = rl_get(s, x), c = rl_get(s, y);
        const bool other = x->kind == CIR_VAL_PARAM && x->u.param_reg == CBAE_REG_OTHER;
        out.k = 1;
        if (x == y && !other && (in->opcode == CIR_OP_XOR || in->opcode == CIR_OP_SUB)) { out.v = 0; return out; }
        if ((in->opcode == CIR_OP_AND || in->opcode == CIR_OP_MUL) && (rl_is(a, 0, m) || rl_is(c, 0, m))) {
            out.v = 0; return out;
        }
        if (in->opcode == CIR_OP_OR && (rl_is(a, m, m) || rl_is(c, m, m))) { out.v = m; return out; }
        if (a.k == 0 || c.k == 0) return top;          /* not known yet: wait (it may still become an annihilator) */
        if (a.k == 2 || c.k == 2) return varying;
        switch (in->opcode) {
            case CIR_OP_ADD: out.v = a.v + c.v; break;
            case CIR_OP_SUB: out.v = a.v - c.v; break;
            case CIR_OP_MUL: out.v = a.v * c.v; break;
            case CIR_OP_AND: out.v = a.v & c.v; break;
            case CIR_OP_OR:  out.v = a.v | c.v; break;
            default:         out.v = a.v ^ c.v; break;
        }
        out.v &= m;
        return out;
    }
    case CIR_OP_NOT: case CIR_OP_NEG: case CIR_OP_COPY: {
        if (in->operand_count != 1 || rw == 0) return varying;
        if (rbits(in->operands[0]) < rw) return varying;
        const rl_t a = rl_get(s, in->operands[0]);
        if (a.k != 1) return a;
        out.k = 1;
        out.v = in->opcode == CIR_OP_NOT ? ~a.v : in->opcode == CIR_OP_NEG ? (0 - a.v) : a.v;
        out.v &= m;
        return out;
    }
    case CIR_OP_SHL: case CIR_OP_SHR: case CIR_OP_SAR: {
        if (in->operand_count != 2) return varying;
        if (rw != 64 || rbits(in->operands[0]) != 64 || rbits(in->operands[1]) < 8) return varying;
        const rl_t a = rl_get(s, in->operands[0]), n = rl_get(s, in->operands[1]);
        out.k = 1;
        if (rl_is(a, 0, UINT64_MAX)) { out.v = 0; return out; }
        if (a.k == 0 || n.k == 0) return top;
        if (a.k == 2 || n.k == 2) return varying;
        const unsigned cnt = (unsigned)(n.v % 64u);
        if (in->opcode == CIR_OP_SHL) out.v = a.v << cnt;
        else if (in->opcode == CIR_OP_SHR) out.v = a.v >> cnt;
        else {
            const int64_t sv = (int64_t)a.v;
            out.v = (uint64_t)(sv < 0 ? ~((~(uint64_t)sv) >> cnt) : (uint64_t)sv >> cnt);   /* arithmetic shift, spelled out */
        }
        return out;
    }
    case CIR_OP_PHI: {
        rl_t acc = top;
        for (uint32_t k = 0; k < in->phi_incoming_count; k++) {
            if (!ref_edge_open(s, f, in->phi_incoming_blocks[k], b)) continue;
            const cbae_cir_value_t *v = in->phi_incoming_values[k];
            if (rw == 0 || rbits(v) < rw) return varying;
            rl_t l = rl_get(s, v);
            if (l.k == 1) l.v &= m;
            acc = rl_meet(acc, l);
        }
        return acc;
    }
    default:
        return varying;
    }
}

static void ref_solve(const fctx_t *fx, ref_t *s) {
    const cbae_cir_function_t *f = fx->f;
    const uint32_t nb = fx->nblocks, nv = fx->ud.value_count;
    s->kind  = calloc(nv ? nv : 1, 1);
    s->val   = calloc(nv ? nv : 1, sizeof(uint64_t));
    s->bexec = calloc(nb, 1);
    s->eexec = calloc((size_t)nb * 2, 1);
    assert(s->kind && s->val && s->bexec && s->eexec);
    s->bexec[0] = 1;

    for (bool changed = true; changed; ) {
        changed = false;
        for (uint32_t b = 0; b < nb; b++) {
            if (!s->bexec[b]) continue;
            const cbae_cir_block_t *blk = blk_at(f, b);
            for (uint32_t i = 0; i < blk->instruction_count; i++) {
                const cbae_cir_instruction_t *in = blk->instructions[i];
                if (!in->result) continue;
                const rl_t old = { s->kind[in->result->id], s->val[in->result->id] };
                const rl_t nw = rl_meet(old, ref_transfer(s, f, in, b));
                if (nw.k != old.k || nw.v != old.v) {
                    s->kind[in->result->id] = nw.k;
                    s->val[in->result->id] = nw.v;
                    changed = true;
                }
            }
            /* which successor slots does this block open? */
            bool open[2] = { true, true };
            const cbae_cir_instruction_t *last =
                blk->instruction_count ? blk->instructions[blk->instruction_count - 1] : NULL;
            if (last && last->opcode == CIR_OP_BRANCH) {
                const cbae_cir_value_t *c = last->operands[0];
                rl_t l = rl_get(s, c);
                if (l.k == 1 && rbits(c) != 1) l.k = 2;
                if (l.k == 0) { open[0] = open[1] = false; }
                else if (l.k == 1) {
                    const uint32_t target = (l.v & 1u) ? last->branch_true_block : last->branch_false_block;
                    bool hit = false;
                    for (uint32_t k = 0; k < blk->successor_count; k++) hit |= blk->successors[k] == target;
                    if (hit)
                        for (uint32_t k = 0; k < 2; k++) open[k] = k < blk->successor_count && blk->successors[k] == target;
                }
            }
            for (uint32_t k = 0; k < blk->successor_count; k++) {
                if (!open[k] || s->eexec[(size_t)b * 2 + k]) continue;
                s->eexec[(size_t)b * 2 + k] = 1;
                if (blk->successors[k] < nb) s->bexec[blk->successors[k]] = 1;
                changed = true;
            }
        }
    }
}

static void ref_free(ref_t *s) { free(s->kind); free(s->val); free(s->bexec); free(s->eexec); }

/* ── Static checks ───────────────────────────────────────────────────── */

static void static_checks(fctx_t *fx, stats_t *st) {
    const cbae_cir_function_t *f = fx->f;
    const uint32_t nb = fx->nblocks;

    if (!cbae_const_prop_block_executable(&fx->cp, 0)) die(fx, "the entry block is not executable");

    uint32_t *in_open = calloc(nb, sizeof *in_open);     /* executable edges entering each block */
    assert(in_open);

    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = blk_at(f, b);
        const bool exec = cbae_const_prop_block_executable(&fx->cp, b);
        if (!exec) st->dead_blocks++;

        /* Edges: executable only between executable blocks, only along CFG edges. */
        for (uint32_t t = 0; t < nb; t++) {
            const bool e = cbae_const_prop_edge_executable(&fx->cp, b, t);
            if (e && !is_successor(f, b, t)) die(fx, "edge %u->%u is executable but is not a CFG edge", b, t);
            if (e && !exec) die(fx, "edge %u->%u is executable out of a dead block", b, t);
            if (e && !cbae_const_prop_block_executable(&fx->cp, t))
                die(fx, "edge %u->%u is executable into a dead block", b, t);
            if (e) in_open[t]++;
        }

        /* Results: unreached exactly in dead blocks; constants fit their width. */
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (!in->result) continue;
            const cbae_cp_value_t r = cbae_const_prop_value(&fx->cp, in->result);
            st->results++;
            if (exec && r.kind == CBAE_CP_UNREACHED) die(fx, "%%v%u in executable block %u is UNREACHED", in->result->id, b);
            if (!exec && r.kind != CBAE_CP_UNREACHED) die(fx, "%%v%u in dead block %u is not UNREACHED", in->result->id, b);
            if (r.kind == CBAE_CP_CONSTANT && (r.value & ~width_mask(in->result)) != 0)
                die(fx, "%%v%u is CONSTANT %#" PRIx64 ", wider than its type", in->result->id, r.value);
            if (r.kind == CBAE_CP_VARYING && r.value != 0) die(fx, "%%v%u is VARYING with a value", in->result->id);
            if (r.kind == CBAE_CP_UNREACHED && r.value != 0) die(fx, "%%v%u is UNREACHED with a value", in->result->id);
            st->st_const     += r.kind == CBAE_CP_CONSTANT;
            st->st_varying   += r.kind == CBAE_CP_VARYING;
            st->st_unreached += r.kind == CBAE_CP_UNREACHED;
            if (r.kind == CBAE_CP_CONSTANT) {
                st->st_const_narrow += cir_type_bits(in->result->type) < 64;
                st->st_const_phi    += in->opcode == CIR_OP_PHI;
            }
        }

        /* The terminator decides which edges open. */
        if (!exec) continue;
        const cbae_cir_instruction_t *last = blk->instruction_count ? blk->instructions[blk->instruction_count - 1] : NULL;
        uint32_t open_edges = 0;
        for (uint32_t k = 0; k < blk->successor_count; k++)
            open_edges += cbae_const_prop_edge_executable(&fx->cp, b, blk->successors[k]);

        if (last && last->opcode == CIR_OP_BRANCH) {
            st->branch_blocks++;
            const cbae_cir_value_t *c = last->operands[0];
            const cbae_cp_value_t l = cbae_const_prop_value(&fx->cp, c);
            if (l.kind == CBAE_CP_UNREACHED) die(fx, "block %u: branch condition is UNREACHED in an executable block", b);
            if (l.kind == CBAE_CP_CONSTANT && cir_type_bits(c->type) == 1) {
                const uint32_t target = (l.value & 1u) ? last->branch_true_block : last->branch_false_block;
                for (uint32_t k = 0; k < blk->successor_count; k++) {
                    const uint32_t s = blk->successors[k];
                    if (cbae_const_prop_edge_executable(&fx->cp, b, s) != (s == target))
                        die(fx, "block %u: constant condition %" PRIu64 " selects block %u, edge to %u is %s", b,
                            l.value & 1u, target, s, s == target ? "closed" : "open");
                }
                if (blk->successor_count == 2 && open_edges == 1) { fx->folded[b] = 1; st->folded_branches++; }
            } else if (open_edges != blk->successor_count) {
                die(fx, "block %u: branch on an unknown condition leaves %u of %u edges open", b, open_edges,
                    blk->successor_count);
            }
        } else if (open_edges != blk->successor_count) {
            die(fx, "block %u: no branch, yet %u of %u edges are open", b, open_edges, blk->successor_count);
        }
    }

    for (uint32_t b = 1; b < nb; b++) {
        const bool exec = cbae_const_prop_block_executable(&fx->cp, b);
        if (exec && in_open[b] == 0) die(fx, "block %u is executable but no edge into it is", b);
        if (!exec && in_open[b] != 0) die(fx, "block %u is dead but an edge into it is executable", b);
    }
    free(in_open);

    /* The reference solver must agree on everything. */
    ref_t ref;
    ref_solve(fx, &ref);
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = blk_at(f, b);
        if ((ref.bexec[b] != 0) != cbae_const_prop_block_executable(&fx->cp, b))
            die(fx, "reference says block %u is %s, the analysis says the opposite", b,
                ref.bexec[b] ? "executable" : "dead");
        st->ref_blocks++;
        for (uint32_t k = 0; k < blk->successor_count; k++) {
            const bool re = ref.eexec[(size_t)b * 2 + k] != 0;
            if (re != cbae_const_prop_edge_executable(&fx->cp, b, blk->successors[k]))
                die(fx, "reference says edge %u->%u is %s, the analysis says the opposite", b,
                    blk->successors[k], re ? "executable" : "closed");
            st->ref_edges++;
        }
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (!in->result) continue;
            const cbae_cp_value_t a = cbae_const_prop_value(&fx->cp, in->result);
            const uint8_t rk = ref.kind[in->result->id];
            const uint64_t rv = ref.val[in->result->id];
            const uint8_t ak = a.kind == CBAE_CP_UNREACHED ? 0 : a.kind == CBAE_CP_CONSTANT ? 1 : 2;
            if (ak != rk || (rk == 1 && rv != a.value))
                die(fx, "%%v%u: reference says kind %u value %#" PRIx64 ", the analysis kind %u value %#" PRIx64,
                    in->result->id, rk, rv, ak, a.value);
            st->ref_values++;
        }
    }
    ref_free(&ref);
}

/* ── Views: what a run is checked against ────────────────────────────── */

enum { FORGE_NONE = -1, FORGE_NUDGE = 0, FORGE_VARYING_ZERO, FORGE_ALL_UNREACHED, FORGE_EDGES_CLOSED,
       FORGE_BLOCKS_CLOSED, FORGE_FOLD_SWAPPED, FORGE_N };
static const char *const FORGE_NAME[FORGE_N] = {
    "every constant off by one", "every unknown value called the constant 0",
    "every value called unreachable", "no edge executable", "no block executable",
    "folded branches take the other edge" };

static cbae_cp_value_t view_value(const fctx_t *fx, int forge, const cbae_cir_value_t *v) {
    cbae_cp_value_t r = cbae_const_prop_value(&fx->cp, v);
    switch (forge) {
        case FORGE_NUDGE:         if (r.kind == CBAE_CP_CONSTANT) r.value += 1; break;
        case FORGE_VARYING_ZERO:  if (r.kind == CBAE_CP_VARYING) { r.kind = CBAE_CP_CONSTANT; r.value = 0; } break;
        case FORGE_ALL_UNREACHED: r.kind = CBAE_CP_UNREACHED; r.value = 0; break;
        default: break;
    }
    return r;
}

static bool view_block(const fctx_t *fx, int forge, uint32_t b) {
    return forge == FORGE_BLOCKS_CLOSED ? false : cbae_const_prop_block_executable(&fx->cp, b);
}

static bool view_edge(const fctx_t *fx, int forge, uint32_t from, uint32_t to) {
    if (forge == FORGE_EDGES_CLOSED) return false;
    const bool real = cbae_const_prop_edge_executable(&fx->cp, from, to);
    if (forge == FORGE_FOLD_SWAPPED && from < fx->nblocks && fx->folded[from])
        return !real && is_successor(fx->f, from, to);
    return real;
}

/* ── One run ─────────────────────────────────────────────────────────── */

typedef struct {
    fctx_t   *fx;
    int       forge;
    stats_t  *st;
    bool      quiet;
    uint64_t  seed;
    bool      sx;
    int32_t   run_id;
    int       violations;
} run_t;

static void report(run_t *r, const char *fmt, ...) {
    r->violations++;
    if (r->quiet) return;
    fctx_t *fx = r->fx;
    if (fx->reported == 0) {
        fprintf(stderr, "\n=== SOUNDNESS VIOLATION: function seed %" PRIu64 ", run seed %" PRIu64 " (%s extension) ===\n",
                fx->seed, r->seed, r->sx ? "sign" : "zero");
        cbae_cir_print_function(fx->f, stderr);
    }
    if (fx->reported++ < 8) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
    }
}

static void on_def(void *u, const cbae_cir_instruction_t *insn, uint64_t value, uint64_t step) {
    (void)step;
    run_t *r = u;
    fctx_t *fx = r->fx;
    stats_t *st = r->st;
    const cbae_cir_value_t *res = insn->result;
    const cbae_cp_value_t c = view_value(fx, r->forge, res);
    st->def_execs++;

    switch (c.kind) {
        case CBAE_CP_CONSTANT:
            st->const_execs++;
            st->phi_const_execs += insn->opcode == CIR_OP_PHI;
            if (value != c.value)
                report(r, "%%v%u (%s) defined %#" PRIx64 ", called CONSTANT %#" PRIx64, res->id,
                       insn->opcode == CIR_OP_PHI ? "phi" : "insn", value, c.value);
            break;
        case CBAE_CP_UNREACHED:
            report(r, "%%v%u was defined (as %#" PRIx64 ") but is called UNREACHED", res->id, value);
            break;
        default:
            st->varying_execs++;
            st->varying_nonzero_execs += value != 0;
            break;
    }

    if (r->forge == FORGE_NONE) {                      /* what the runs saw, for the tightness figures */
        if (fx->cnt[res->id]++ == 0) fx->first[res->id] = value;
        else if (value != fx->first[res->id]) fx->differs[res->id] = 1;
        if (fx->last_run[res->id] != r->run_id) { fx->last_run[res->id] = r->run_id; fx->runs_seen[res->id]++; }
    }
}

static void on_block(void *u, uint32_t b, uint32_t from, uint64_t step) {
    (void)step;
    run_t *r = u;
    fctx_t *fx = r->fx;
    stats_t *st = r->st;
    st->block_execs++;
    if (!view_block(fx, r->forge, b)) report(r, "control entered block %u, called not executable", b);
    if (from != UINT32_MAX) {
        st->edge_execs++;
        if (!view_edge(fx, r->forge, from, b)) report(r, "control took edge %u->%u, called not executable", from, b);
        if (fx->folded[from]) st->folded_branch_execs++;
    }
}

static int run_one(fctx_t *fx, int forge, stats_t *st, bool quiet, uint64_t run_seed, uint64_t max_steps,
                   bool sx, int32_t run_id) {
    run_t r;
    memset(&r, 0, sizeof r);
    r.fx = fx; r.forge = forge; r.st = st; r.quiet = quiet; r.seed = run_seed; r.sx = sx; r.run_id = run_id;

    cirx_hooks_t hk;
    memset(&hk, 0, sizeof hk);
    hk.user = &r;
    hk.on_def = on_def;
    hk.on_block = on_block;
    hk.sign_ext = sx;
    cirx_result_t res;
    cirx_run(fx->f, run_seed, max_steps, &hk, &res);
    st->runs++;
    st->sx_runs += sx;
    st->steps += res.steps;
    return r.violations;
}

/* ── Per function ────────────────────────────────────────────────────── */

static void fctx_init(fctx_t *fx, cirg_t *g, uint64_t seed, stats_t *st) {
    memset(fx, 0, sizeof *fx);
    fx->f = g->f;
    fx->seed = seed;
    assert(cbae_use_def_build(g->f, &fx->ud) == CBAE_OK);
    assert(cbae_const_prop_run(&fx->ud, &fx->cp) == CBAE_OK);
    fx->nblocks = (uint32_t)cbae_vector_count(&g->f->blocks);
    assert(fx->nblocks == g->nblocks);
    const size_t nv = fx->ud.value_count ? fx->ud.value_count : 1;
    fx->folded  = calloc(fx->nblocks, 1);
    fx->cnt     = calloc(nv, sizeof *fx->cnt);
    fx->first   = calloc(nv, sizeof *fx->first);
    fx->differs = calloc(nv, 1);
    fx->last_run = malloc(nv * sizeof *fx->last_run);
    fx->runs_seen = calloc(nv, 1);
    assert(fx->folded && fx->cnt && fx->first && fx->differs && fx->last_run && fx->runs_seen);
    memset(fx->last_run, 0xFF, nv * sizeof *fx->last_run);

    st->funcs++;
    st->blocks += fx->nblocks;
    for (uint32_t b = 0; b < fx->nblocks; b++)
        if (cirg_has_back_pred(g, b)) { st->loop_funcs++; break; }
    static_checks(fx, st);
}

static void tally_tightness(const fctx_t *fx, stats_t *st) {
    for (uint32_t id = 0; id < fx->ud.value_count; id++) {
        const cbae_cir_value_t *v = fx->ud.value_by_id[id];
        if (!v || v->kind != CIR_VAL_INSN_RESULT || fx->cnt[id] < 8 || fx->runs_seen[id] < 3 || fx->differs[id])
            continue;
        st->dyn_const++;
        st->dyn_const_claimed += cbae_const_prop_value(&fx->cp, v).kind == CBAE_CP_CONSTANT;
    }
}

static void fctx_free(fctx_t *fx) {
    cbae_const_prop_destroy(&fx->cp);
    cbae_use_def_destroy(&fx->ud);
    free(fx->folded); free(fx->cnt); free(fx->first); free(fx->differs);
    free(fx->last_run); free(fx->runs_seen);
}

/* Constant-flavoured code and constant branch conditions vary with the seed,
 * independently of the size class cirg_params_for_seed picks and of each other.
 * Every combination recurs every 36 seeds. */
static cirg_params_t params_for_seed(uint64_t seed) {
    static const uint32_t CONST_PCT[3] = { 18, 35, 55 };
    static const uint32_t COND_PCT[4]  = { 0, 25, 50, 85 };
    cirg_params_t p = cirg_params_for_seed(seed);
    p.const_pct      = CONST_PCT[(seed / 3) % 3];
    p.const_cond_pct = COND_PCT[(seed / 9) % 4];
    return p;
}

int main(void) {
    const uint64_t nfuncs = env_u64("CBAE_SOUNDNESS_FUNCS", 1500);
    const uint64_t seed0  = env_u64("CBAE_SOUNDNESS_SEED0", 1);
    const uint64_t nruns  = env_u64("CBAE_SOUNDNESS_RUNS", 4);
    const uint64_t steps  = env_u64("CBAE_SOUNDNESS_STEPS", 600);
    const uint64_t teeth_funcs = nfuncs < 150 ? nfuncs : 150;

    stats_t st;
    memset(&st, 0, sizeof st);
    uint64_t caught[FORGE_N] = { 0 }, exercised[FORGE_N] = { 0 };

    for (uint64_t fi = 0; fi < nfuncs; fi++) {
        const uint64_t seed = seed0 + fi;
        const cirg_params_t p = params_for_seed(seed);
        cirg_t *g = NULL;
        const bool built = cirg_build(&g, seed, &p);
        assert(built);
        (void)built;

        fctx_t fx;
        fctx_init(&fx, g, seed, &st);

        stats_t fst;                                   /* this function's own tally */
        memset(&fst, 0, sizeof fst);
        for (uint64_t run = 0; run < nruns; run++) {
            const int viol = run_one(&fx, FORGE_NONE, &fst, false, seed * 7919 + run, steps, (run & 1) != 0,
                                     (int32_t)run);
            if (viol) {
                fprintf(stderr, "FAILED: %d violation(s), function seed %" PRIu64 "\n", viol, seed);
                return 1;
            }
        }
        tally_tightness(&fx, &st);

        if (fi < teeth_funcs) {
            /* Which forgeries does this function give a chance to be caught? */
            const bool can[FORGE_N] = {
                [FORGE_NUDGE]         = fst.const_execs > 0,
                [FORGE_VARYING_ZERO]  = fst.varying_nonzero_execs > 0,
                [FORGE_ALL_UNREACHED] = fst.def_execs > 0,
                [FORGE_EDGES_CLOSED]  = fst.edge_execs > 0,
                [FORGE_BLOCKS_CLOSED] = fst.block_execs > 0,
                [FORGE_FOLD_SWAPPED]  = fst.folded_branch_execs > 0,
            };
            for (int kind = 0; kind < FORGE_N; kind++) {
                uint64_t found = 0;
                stats_t scratch;
                for (uint64_t run = 0; run < nruns; run++) {
                    memset(&scratch, 0, sizeof scratch);
                    found += (uint64_t)run_one(&fx, kind, &scratch, true, seed * 7919 + run, steps, (run & 1) != 0,
                                               (int32_t)run);
                }
                caught[kind] += found;
                exercised[kind] += can[kind];
                if (can[kind] && found == 0) {
                    fprintf(stderr, "SELF-CHECK FAILED: function seed %" PRIu64 " exercised '%s' but the forgery was not caught\n",
                            seed, FORGE_NAME[kind]);
                    return 1;
                }
            }
        }
        stats_add(&st, &fst);

        fctx_free(&fx);
        cirg_free(g);
    }

    printf("constant propagation soundness: %" PRIu64 " random functions (%" PRIu64 " blocks, %" PRIu64
           " with loops), %" PRIu64 " runs (%" PRIu64 " sign-extended), %" PRIu64 " steps\n",
           st.funcs, st.blocks, st.loop_funcs, st.runs, st.sx_runs, st.steps);
    printf("  static: %" PRIu64 " results: %" PRIu64 " constant (%" PRIu64 " narrower than 64 bits, %" PRIu64
           " phis), %" PRIu64 " varying, %" PRIu64 " unreached\n",
           st.results, st.st_const, st.st_const_narrow, st.st_const_phi, st.st_varying, st.st_unreached);
    printf("  static: %" PRIu64 " dead blocks; %" PRIu64 " executable blocks end in a branch, %" PRIu64 " of them folded\n",
           st.dead_blocks, st.branch_blocks, st.folded_branches);
    printf("  reference solver agreed on %" PRIu64 " values, %" PRIu64 " blocks, %" PRIu64 " edges\n",
           st.ref_values, st.ref_blocks, st.ref_edges);
    printf("  dynamic: %" PRIu64 " definitions: %" PRIu64 " of constants (%" PRIu64 " phis), %" PRIu64
           " of unknown values (%" PRIu64 " non-zero)\n",
           st.def_execs, st.const_execs, st.phi_const_execs, st.varying_execs, st.varying_nonzero_execs);
    printf("  dynamic: %" PRIu64 " block entries, %" PRIu64 " edges taken, %" PRIu64 " out of folded branches\n",
           st.block_execs, st.edge_execs, st.folded_branch_execs);
    printf("  tightness: %" PRIu64 " of %" PRIu64 " values that took a single value in 8+ executions over 3+ runs "
           "were proven constant\n    (the rest are the same only on the paths the runs took, through memory, or through mixed widths)\n",
           st.dyn_const_claimed, st.dyn_const);
    for (int kind = 0; kind < FORGE_N; kind++)
        printf("  self-check '%s': %" PRIu64 " violations caught (in all %" PRIu64 " functions that exercised it)\n",
               FORGE_NAME[kind], caught[kind], exercised[kind]);

    /* Every forgery must have been exercised and caught, or the checks above prove nothing. */
    for (int kind = 0; kind < FORGE_N; kind++) assert(caught[kind] > 0 && exercised[kind] > 0);

    /* The claims must have been exercised in volume, not trivially true. */
    if (nfuncs >= 1000) {
        assert(st.loop_funcs         >= 300);
        assert(st.results            >= 50000);
        assert(st.ref_values         == st.results);
        assert(st.st_const           >= 10000);
        assert(st.st_const_narrow    >= 3000);
        assert(st.st_const_phi       >= 1000);
        assert(st.st_varying         >= 30000);
        assert(st.dead_blocks        >= 2000);
        assert(st.folded_branches    >= 800);
        assert(st.const_execs        >= 100000);
        assert(st.phi_const_execs    >= 15000);
        assert(st.varying_execs      >= 200000);
        assert(st.edge_execs         >= 50000);
        assert(st.folded_branch_execs >= 10000);
        assert(st.sx_runs > 0 && st.sx_runs < st.runs);        /* both readings of narrow operands were run */
    }

    printf("test_const_prop_soundness: OK\n");
    return 0;
}
