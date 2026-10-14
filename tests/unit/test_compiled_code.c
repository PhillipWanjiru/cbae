/**
 * @file test_compiled_code.c
 * @brief The Phase 5 analyses on what gcc emits (compiled_corpus.h), lifted and put into SSA form.
 *
 * Every other Phase 5 test feeds its analysis a function somebody chose: built by hand, so the
 * answer can be derived on paper, or generated at random, so an oracle can check it. This feeds
 * them the real thing -- and checks what can be checked WITHOUT knowing what the code computes,
 * because the lifter models it only in part (see compiled_corpus.h):
 *
 *   - dominator tree, dominance frontier and post-dominator tree, against brute-force
 *     definitions that use no dominator code: A dominates B if B cannot be reached from the
 *     entry once A is removed; A post-dominates B if B cannot reach an exit once A is removed;
 *   - SSA: every use is dominated by its definition, judged with the production dominator tree
 *     (the SSA verifier reaches the same verdict with a computation of its own);
 *   - use-def: every use list entry names the slot it came from, and the lists together hold
 *     exactly as many uses as there are operand slots and phi incomings;
 *   - alias analysis: a query gives the same answer whichever access is asked about first;
 *   - reaching stores: the stores that reach a load are among those that reach its point, and a
 *     forwardable load has exactly one;
 *   - constant propagation: a block is executable exactly when an executable edge enters it (the
 *     entry aside); an instruction in an executable block does not define an UNREACHED value, and
 *     one in a block that cannot be reached defines nothing else; every constant fits its type.
 *
 * Each of these was first tested on hand-built and random inputs. This is the check that they hold
 * on code nobody arranged, and what ties the lifter, the SSA constructor and the analyses together.
 */
#include "dataflow/alias_analysis.h"
#include "dataflow/const_prop.h"
#include "dataflow/dominator_tree.h"
#include "dataflow/post_dominator_tree.h"
#include "dataflow/reaching_stores.h"
#include "dataflow/ssa_verifier.h"
#include "dataflow/use_def.h"
#include "compiled_corpus.h"
#include "lift_helpers.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NONE UINT32_MAX
#define MAXB 64          /* the largest function in the corpus has far fewer blocks */

/* `cond` is evaluated ONCE: most calls below are builds of an analysis, wrapped in EXPECT to check
 * their status, and a second evaluation would build it again and lose the first result. */
#define EXPECT(cond, ...) do { const bool expect_ok_ = (cond); \
                                if (!expect_ok_) { fprintf(stderr, "FAIL: "); \
                                fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
                                assert(expect_ok_); } while (0)

/* ── The control-flow graph, as the successor lists record it ─────────── */

typedef struct {
    uint32_t n;
    uint32_t nsucc[MAXB];
    uint32_t succ[MAXB][2];
} graph_t;

static graph_t graph_of(const cbae_cir_function_t *f) {
    graph_t g;
    memset(&g, 0, sizeof g);
    g.n = (uint32_t)cbae_vector_count(&f->blocks);
    assert(g.n > 0 && g.n <= MAXB);
    for (uint32_t b = 0; b < g.n; b++) {
        const cbae_cir_block_t *blk = lh_block(f, b);
        g.nsucc[b] = blk->successor_count;
        for (uint32_t k = 0; k < blk->successor_count; k++) g.succ[b][k] = blk->successors[k];
    }
    return g;
}

/* The blocks reachable from `from` without entering `avoid` (NONE: no restriction). Starting AT
 * `avoid` reaches nothing. */
static void reach(const graph_t *g, uint32_t from, uint32_t avoid, bool seen[MAXB]) {
    memset(seen, 0, sizeof(bool) * MAXB);
    if (from == avoid) return;
    uint32_t stack[MAXB], sp = 0;
    seen[from] = true;
    stack[sp++] = from;
    while (sp) {
        const uint32_t u = stack[--sp];
        for (uint32_t k = 0; k < g->nsucc[u]; k++) {
            const uint32_t v = g->succ[u][k];
            if (v == avoid || seen[v]) continue;
            seen[v] = true;
            stack[sp++] = v;
        }
    }
}

/* Every path from the entry to `b` passes through `a` (a block dominates itself). */
static bool oracle_dom(const graph_t *g, uint32_t a, uint32_t b) {
    if (a == b) return true;
    bool seen[MAXB];
    reach(g, 0, a, seen);
    return !seen[b];
}

/* Every path from `b` to an exit (a block with no successors) passes through `a`. Only meaningful
 * when `b` reaches an exit at all. */
static bool oracle_pdom(const graph_t *g, uint32_t a, uint32_t b) {
    if (a == b) return true;
    bool seen[MAXB];
    reach(g, b, a, seen);
    for (uint32_t e = 0; e < g->n; e++)
        if (g->nsucc[e] == 0 && seen[e]) return false;
    return true;
}

static bool every_block_reached(const graph_t *g) {
    bool seen[MAXB];
    reach(g, 0, NONE, seen);
    for (uint32_t b = 0; b < g->n; b++) if (!seen[b]) return false;
    return true;
}

static bool every_block_reaches_an_exit(const graph_t *g) {
    for (uint32_t b = 0; b < g->n; b++) {
        bool seen[MAXB], found = false;
        reach(g, b, NONE, seen);
        for (uint32_t e = 0; e < g->n; e++) if (g->nsucc[e] == 0 && seen[e]) found = true;
        if (!found) return false;
    }
    return true;
}

/* ── What was checked, for the report ─────────────────────────────────── */

typedef struct {
    uint64_t functions, blocks, dom_pairs, frontier_sets, pdom_pairs, uses, access_pairs,
             loads, loads_with_stores, forwardable, constants, folded_blocks;
} totals_t;

/* ── Dominance ────────────────────────────────────────────────────────── */

static void check_dominance(const char *name, const graph_t *g, const cbae_dom_tree_t *dt,
                            totals_t *t) {
    for (uint32_t a = 0; a < g->n; a++)
        for (uint32_t b = 0; b < g->n; b++) {
            const bool want = oracle_dom(g, a, b), got = cbae_dom_tree_dominates(dt, a, b);
            EXPECT(want == got, "[%s] dominates(block%u, block%u): the tree says %d, brute force %d",
                   name, a, b, (int)got, (int)want);
            t->dom_pairs++;
        }

    /* The immediate dominator is the closest strict dominator: the one every other strict
     * dominator of b also dominates. */
    EXPECT(cbae_dom_tree_idom(dt, 0) == 0, "[%s] the entry's idom is not itself", name);
    for (uint32_t b = 1; b < g->n; b++) {
        uint32_t want = NONE;
        for (uint32_t d = 0; d < g->n; d++) {
            if (d == b || !oracle_dom(g, d, b)) continue;
            bool closest = true;
            for (uint32_t d2 = 0; d2 < g->n; d2++)
                if (d2 != b && d2 != d && oracle_dom(g, d2, b) && !oracle_dom(g, d2, d)) closest = false;
            if (closest) { EXPECT(want == NONE, "[%s] two closest dominators of block%u", name, b); want = d; }
        }
        EXPECT(want != NONE, "[%s] block%u has no strict dominator", name, b);
        EXPECT(cbae_dom_tree_idom(dt, b) == want, "[%s] idom(block%u): the tree says block%u, brute force block%u",
               name, b, cbae_dom_tree_idom(dt, b), want);
    }

    /* DF(a) = { y : a dominates a predecessor of y, and does not strictly dominate y }. */
    cbae_dom_frontier_t df;
    EXPECT(cbae_dom_frontier_compute(dt, &df) == CBAE_OK, "[%s] dominance frontier failed", name);
    for (uint32_t a = 0; a < g->n; a++) {
        bool want[MAXB], got[MAXB];
        memset(want, 0, sizeof want);
        memset(got, 0, sizeof got);
        for (uint32_t p = 0; p < g->n; p++)
            for (uint32_t k = 0; k < g->nsucc[p]; k++) {
                const uint32_t y = g->succ[p][k];
                if (oracle_dom(g, a, p) && !(a != y && oracle_dom(g, a, y))) want[y] = true;
            }
        const cbae_vector_t *fv = cbae_dom_frontier_of(&df, a);
        for (size_t i = 0; i < cbae_vector_count(fv); i++) {
            const uint32_t y = *(const uint32_t *)cbae_vector_at(fv, i);
            EXPECT(y < g->n && !got[y], "[%s] DF(block%u) lists block%u twice or out of range", name, a, y);
            got[y] = true;
        }
        for (uint32_t y = 0; y < g->n; y++)
            EXPECT(want[y] == got[y], "[%s] block%u %s DF(block%u) in the tree's answer, %s in brute force",
                   name, y, got[y] ? "is in" : "is not in", a, want[y] ? "is" : "is not");
        t->frontier_sets++;
    }
    cbae_dom_frontier_destroy(&df);
}

static void check_post_dominance(const char *name, const cbae_cir_function_t *f, const graph_t *g,
                                 cbae_arena_t *arena, totals_t *t) {
    EXPECT(every_block_reaches_an_exit(g), "[%s] has a block with no way out; the corpus has none", name);
    cbae_pdom_tree_t pt;
    EXPECT(cbae_pdom_tree_build(f, arena, &pt) == CBAE_OK, "[%s] post-dominator tree failed", name);
    for (uint32_t a = 0; a < g->n; a++)
        for (uint32_t b = 0; b < g->n; b++) {
            const bool want = oracle_pdom(g, a, b), got = cbae_pdom_tree_post_dominates(&pt, a, b);
            EXPECT(want == got, "[%s] post_dominates(block%u, block%u): the tree says %d, brute force %d",
                   name, a, b, (int)got, (int)want);
            t->pdom_pairs++;
        }
    /* The immediate post-dominator is the closest strict one; with none, the virtual exit. */
    for (uint32_t b = 0; b < g->n; b++) {
        uint32_t want = CBAE_PDOM_EXIT;
        for (uint32_t d = 0; d < g->n; d++) {
            if (d == b || !oracle_pdom(g, d, b)) continue;
            bool closest = true;
            for (uint32_t d2 = 0; d2 < g->n; d2++)
                if (d2 != b && d2 != d && oracle_pdom(g, d2, b) && !oracle_pdom(g, d2, d)) closest = false;
            if (closest) { EXPECT(want == CBAE_PDOM_EXIT, "[%s] two closest post-dominators of block%u", name, b); want = d; }
        }
        EXPECT(cbae_pdom_tree_ipdom(&pt, b) == want, "[%s] ipdom(block%u): the tree says %d, brute force %d",
               name, b, (int)cbae_pdom_tree_ipdom(&pt, b), (int)want);
    }
    cbae_pdom_tree_destroy(&pt);
}

/* ── SSA and use-def ──────────────────────────────────────────────────── */

static void check_uses(const char *name, const cbae_cir_function_t *f, const cbae_use_def_t *ud,
                       const cbae_dom_tree_t *dt, totals_t *t) {
    uint64_t slots = 0, listed = 0;
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = lh_block(f, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            slots += (in->opcode == CIR_OP_PHI) ? in->phi_incoming_count : in->operand_count;
        }
    }

    for (uint32_t id = 0; id < ud->value_count; id++) {
        const cbae_cir_value_t *v = ud->value_by_id[id];
        if (!v) continue;
        const cbae_use_list_t ul = cbae_use_def_uses(ud, v);
        listed += ul.count;
        const uint32_t def_block = cbae_use_def_def_block(ud, v);
        /* A value nothing uses may be one the SSA constructor replaced (a register-entry placeholder
         * stays in the value table); one that is used must be available somewhere. */
        EXPECT(ul.count == 0 || def_block != CBAE_USE_DEF_NO_BLOCK, "[%s] %%v%u is used but available nowhere", name, v->id);

        for (uint32_t k = 0; k < ul.count; k++) {
            const cbae_use_t *u = &ul.uses[k];
            const bool phi = u->insn->opcode == CIR_OP_PHI;
            EXPECT((u->kind == CBAE_USE_PHI_INCOMING) == phi, "[%s] use of %%v%u has the wrong kind", name, v->id);
            EXPECT(phi ? (u->index < u->insn->phi_incoming_count && u->insn->phi_incoming_values[u->index] == v)
                       : (u->index < u->insn->operand_count && u->insn->operands[u->index] == v),
                   "[%s] a use of %%v%u names a slot that does not hold it", name, v->id);
            EXPECT(u->block_id == cbae_use_def_block_of(ud, u->insn), "[%s] a use of %%v%u is in the wrong block", name, v->id);

            /* SSA: the definition is available at the use. */
            const uint32_t at = cbae_use_point_block(u);
            if (def_block == at) {
                if (v->kind == CIR_VAL_INSN_RESULT && !phi)
                    EXPECT(cbae_use_def_pos_of(ud, v->u.def_insn) < cbae_use_def_pos_of(ud, u->insn),
                           "[%s] %%v%u is used by insn#%u before the instruction that defines it", name, v->id, u->insn->id);
            } else {
                EXPECT(cbae_dom_tree_dominates(dt, def_block, at),
                       "[%s] %%v%u (block%u) does not dominate its use by insn#%u (block%u)",
                       name, v->id, def_block, u->insn->id, at);
            }
            t->uses++;
        }
    }
    EXPECT(listed == slots, "[%s] the use lists hold %llu uses; the instructions have %llu operand slots and phi incomings",
           name, (unsigned long long)listed, (unsigned long long)slots);
}

/* ── Memory and constants ─────────────────────────────────────────────── */

static void check_memory(const char *name, const cbae_cir_function_t *f, const cbae_use_def_t *ud,
                         totals_t *t) {
    cbae_alias_ctx_t alias;
    EXPECT(cbae_alias_ctx_build(ud, &alias) == CBAE_OK, "[%s] alias context failed", name);

    enum { MAX_ACCESSES = 512 };
    const cbae_cir_value_t *addr[MAX_ACCESSES];
    uint32_t size[MAX_ACCESSES], n = 0;
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = lh_block(f, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_value_t *a; uint32_t s;
            if (cbae_alias_mem_access(blk->instructions[i], &a, &s)) {
                assert(n < MAX_ACCESSES);
                addr[n] = a; size[n] = s; n++;
            }
        }
    }
    for (uint32_t i = 0; i < n; i++)
        for (uint32_t j = 0; j < n; j++) {
            const cbae_alias_result_t ij = cbae_alias_query(&alias, addr[i], size[i], addr[j], size[j]);
            const cbae_alias_result_t ji = cbae_alias_query(&alias, addr[j], size[j], addr[i], size[i]);
            EXPECT(ij == ji, "[%s] alias(access %u, access %u) = %d but alias(access %u, access %u) = %d",
                   name, i, j, (int)ij, j, i, (int)ji);
            t->access_pairs++;
        }

    cbae_reaching_stores_t rs;
    EXPECT(cbae_reaching_stores_build(ud, &alias, &rs) == CBAE_OK, "[%s] reaching stores failed", name);
    const uint32_t ndefs = cbae_reaching_stores_def_count(&rs);
    const cbae_rs_def_t *defs[MAX_ACCESSES];
    assert(ndefs <= MAX_ACCESSES);
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = lh_block(f, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *load = blk->instructions[i];
            if (load->opcode != CIR_OP_LOAD) continue;
            uint32_t count = 0;
            bool initial = false;
            EXPECT(cbae_reaching_stores_for_load(&rs, load, defs, ndefs, &count, &initial) == CBAE_OK,
                   "[%s] for_load failed on insn#%u", name, load->id);
            EXPECT(count <= ndefs, "[%s] insn#%u: %u stores reach it, but there are only %u", name, load->id, count, ndefs);
            for (uint32_t k = 0; k < count; k++)
                EXPECT(cbae_reaching_stores_may_reach(&rs, load, defs[k]->insn),
                       "[%s] a store reaches load insn#%u, but not the point just before it", name, load->id);
            const cbae_cir_instruction_t *st = NULL;
            if (cbae_reaching_stores_forwardable(&rs, load, &st)) {
                EXPECT(count == 1 && !initial && st == defs[0]->insn,
                       "[%s] load insn#%u is forwardable but %u stores reach it", name, load->id, count);
                t->forwardable++;
            }
            t->loads++;
            if (count) t->loads_with_stores++;
        }
    }
    cbae_reaching_stores_destroy(&rs);
    cbae_alias_ctx_destroy(&alias);
}

static void check_constants(const char *name, const cbae_cir_function_t *f, const graph_t *g,
                            const cbae_use_def_t *ud, totals_t *t) {
    cbae_const_prop_t cp;
    EXPECT(cbae_const_prop_run(ud, &cp) == CBAE_OK, "[%s] constant propagation failed", name);

    EXPECT(cbae_const_prop_block_executable(&cp, 0), "[%s] the entry is not executable", name);
    for (uint32_t b = 1; b < g->n; b++) {
        bool entered = false;
        for (uint32_t p = 0; p < g->n; p++)
            for (uint32_t k = 0; k < g->nsucc[p]; k++)
                if (g->succ[p][k] == b && cbae_const_prop_edge_executable(&cp, p, b)) entered = true;
        EXPECT(cbae_const_prop_block_executable(&cp, b) == entered,
               "[%s] block%u is %sexecutable, but %s executable edge enters it", name, b,
               cbae_const_prop_block_executable(&cp, b) ? "" : "not ", entered ? "an" : "no");
        if (!entered) t->folded_blocks++;
    }

    for (uint32_t b = 0; b < g->n; b++) {
        const cbae_cir_block_t *blk = lh_block(f, b);
        const bool exec = cbae_const_prop_block_executable(&cp, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_value_t *r = blk->instructions[i]->result;
            if (!r) continue;
            const cbae_cp_value_t v = cbae_const_prop_value(&cp, r);
            EXPECT((v.kind == CBAE_CP_UNREACHED) == !exec,
                   "[%s] %%v%u in block%u is %s although the block is %sexecutable", name, r->id, b,
                   v.kind == CBAE_CP_UNREACHED ? "UNREACHED" : "reached", exec ? "" : "not ");
            if (v.kind == CBAE_CP_CONSTANT) {
                const uint8_t bits = cir_type_bits(r->type);
                EXPECT(bits >= 64 || (v.value >> bits) == 0,
                       "[%s] %%v%u is the constant 0x%llx, which does not fit %u bits", name, r->id,
                       (unsigned long long)v.value, bits);
                uint64_t c = 0;
                EXPECT(cbae_const_prop_is_constant(&cp, r, &c) && c == v.value, "[%s] is_constant disagrees with value", name);
                t->constants++;
            } else {
                EXPECT(v.value == 0, "[%s] a non-constant carries the value 0x%llx", name, (unsigned long long)v.value);
            }
        }
    }
    cbae_const_prop_destroy(&cp);
}

/* ── One function ─────────────────────────────────────────────────────── */

static void check_function(const corpus_fn_t *fn, totals_t *t) {
    lifted_t L;
    lift_x86(&L, fn->code, fn->len, 0x401000, fn->name);     /* asserts the structural check */
    const cbae_cir_function_t *f = L.func;

    const cbae_cir_verify_result_t vr = cbae_ssa_verify_function(f);
    EXPECT(vr.ok, "[%s] the SSA verifier rejects it: %s", fn->name, vr.message);

    const graph_t g = graph_of(f);
    EXPECT(every_block_reached(&g), "[%s] has a block the entry cannot reach; the corpus has none", fn->name);

    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 1024 * 1024) == CBAE_OK);
    cbae_dom_tree_t dt;
    EXPECT(cbae_dom_tree_build(f, &arena, &dt) == CBAE_OK, "[%s] dominator tree failed", fn->name);
    check_dominance(fn->name, &g, &dt, t);
    check_post_dominance(fn->name, f, &g, &arena, t);

    cbae_use_def_t ud;
    EXPECT(cbae_use_def_build(f, &ud) == CBAE_OK, "[%s] use-def failed", fn->name);
    check_uses(fn->name, f, &ud, &dt, t);
    check_memory(fn->name, f, &ud, t);
    check_constants(fn->name, f, &g, &ud, t);

    t->functions++;
    t->blocks += g.n;
    cbae_use_def_destroy(&ud);
    cbae_dom_tree_destroy(&dt);
    cbae_arena_destroy(&arena);
    lifted_destroy(&L);
}

int main(void) {
    totals_t t;
    memset(&t, 0, sizeof t);
    for (size_t c = 0; c < COMPILED_CORPUS_COUNT; c++) check_function(&compiled_corpus[c], &t);

    /* The corpus has to be rich enough for the checks above to mean something. */
    const bool rich = t.functions == COMPILED_CORPUS_COUNT && t.functions >= 30 &&
                      t.blocks >= 150 && t.dom_pairs >= 1000 && t.pdom_pairs >= 1000 &&
                      t.uses >= 500 && t.constants >= 3 && t.loads >= 10 && t.loads_with_stores >= 1;
    if (!rich)
        fprintf(stderr, "FAIL: the corpus is too thin: %llu functions, %llu blocks, %llu dominance pairs, "
                "%llu post-dominance pairs, %llu uses, %llu constants, %llu loads (%llu with a store reaching them)\n",
                (unsigned long long)t.functions, (unsigned long long)t.blocks, (unsigned long long)t.dom_pairs,
                (unsigned long long)t.pdom_pairs, (unsigned long long)t.uses, (unsigned long long)t.constants,
                (unsigned long long)t.loads, (unsigned long long)t.loads_with_stores);
    assert(rich);

    printf("  [PASS] dominator tree, frontier and post-dominator tree match brute force "
           "(%llu functions, %llu blocks, %llu dominance pairs, %llu frontier sets, %llu post-dominance pairs)\n",
           (unsigned long long)t.functions, (unsigned long long)t.blocks, (unsigned long long)t.dom_pairs,
           (unsigned long long)t.frontier_sets, (unsigned long long)t.pdom_pairs);
    printf("  [PASS] every use is dominated by its definition and every use list is exact (%llu uses)\n",
           (unsigned long long)t.uses);
    printf("  [PASS] alias queries are symmetric (%llu pairs); reaching stores agree with themselves "
           "(%llu loads, %llu with a store reaching them, %llu forwardable)\n",
           (unsigned long long)t.access_pairs, (unsigned long long)t.loads,
           (unsigned long long)t.loads_with_stores, (unsigned long long)t.forwardable);
    printf("  [PASS] constant propagation: executability and values are consistent "
           "(%llu constants, %llu blocks folded away)\n",
           (unsigned long long)t.constants, (unsigned long long)t.folded_blocks);
    printf("All compiled-code tests passed.\n");
    return 0;
}
