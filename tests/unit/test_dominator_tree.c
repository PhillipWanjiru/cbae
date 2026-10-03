/**
 * @file test_dominator_tree.c
 * @brief Dominator tree, dominates() queries, and dominance frontier on
 *        CFG shapes whose correct answers are hand-verified below.
 *
 * Pure graph algorithm test: CFGs are built directly through the CIR
 * builder's block/edge API (no x86 bytes, no lifter) since dominance
 * depends only on graph structure, not on instruction content.
 *
 * Every expected value in this file was derived by hand from the
 * definitions BEFORE running anything:
 *   - idom(b): the unique block that strictly dominates b and is
 *     dominated by every other strict dominator of b.
 *   - DF(a): the set of blocks b such that a dominates a predecessor
 *     of b but does NOT strictly dominate b itself.
 */
#include "dataflow/dominator_tree.h"
#include "cir/cir_builder.h"
#include "platform/logging.h"
#include "dom_reference.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Build a function with `nblocks` empty blocks and the given edges. */
static cbae_cir_function_t *make_cfg(cbae_arena_t *arena, uint32_t nblocks,
                                       const uint32_t edges[][2], uint32_t nedges) {
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(arena, 0x1000, "cfg", &f) == CBAE_OK);
    cbae_cir_block_t **blocks = malloc(sizeof(cbae_cir_block_t *) * nblocks);
    for (uint32_t i = 0; i < nblocks; i++)
        assert(cbae_cir_block_create(f, 0x1000 + i * 0x10, &blocks[i]) == CBAE_OK);
    for (uint32_t e = 0; e < nedges; e++)
        assert(cbae_cir_block_add_edge(blocks[edges[e][0]], blocks[edges[e][1]]) == CBAE_OK);
    free(blocks);
    return f;
}

static bool df_equals(const cbae_dom_frontier_t *df, uint32_t block,
                       const uint32_t *expected, uint32_t nexpected) {
    const cbae_vector_t *v = cbae_dom_frontier_of(df, block);
    if (cbae_vector_count(v) != nexpected) return false;
    for (uint32_t i = 0; i < nexpected; i++) {
        bool found = false;
        for (uint32_t j = 0; j < cbae_vector_count(v); j++) {
            uint32_t *e = cbae_vector_at(v, j);
            if (*e == expected[i]) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

/* ── Shape 1: straight line  0 -> 1 -> 2 ─────────────────────────────── */
static void t_straight_line(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {1,2} };
    cbae_cir_function_t *f = make_cfg(&arena, 3, edges, 2);

    cbae_dom_tree_t dt;
    assert(cbae_dom_tree_build(f, &arena, &dt) == CBAE_OK);

    assert(cbae_dom_tree_idom(&dt, 0) == 0);
    assert(cbae_dom_tree_idom(&dt, 1) == 0);
    assert(cbae_dom_tree_idom(&dt, 2) == 1);

    assert(cbae_dom_tree_dominates(&dt, 0, 2));
    assert(cbae_dom_tree_dominates(&dt, 1, 2));
    assert(!cbae_dom_tree_dominates(&dt, 2, 1));
    assert(cbae_dom_tree_dominates(&dt, 2, 2));         /* inclusive */
    assert(!cbae_dom_tree_strictly_dominates(&dt, 2, 2));

    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);
    for (uint32_t b = 0; b < 3; b++) assert(df_equals(&df, b, NULL, 0)); /* no joins */

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] straight line: chain of idoms, empty frontiers\n");
}

/* ── Shape 2: diamond  0 -> {1,2} -> 3 ───────────────────────────────── */
static void t_diamond(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {0,2}, {1,3}, {2,3} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    cbae_dom_tree_t dt;
    assert(cbae_dom_tree_build(f, &arena, &dt) == CBAE_OK);

    /* The join's immediate dominator is the ENTRY, not either branch:
     * both paths reach it, so neither branch dominates it. */
    assert(cbae_dom_tree_idom(&dt, 1) == 0);
    assert(cbae_dom_tree_idom(&dt, 2) == 0);
    assert(cbae_dom_tree_idom(&dt, 3) == 0);

    assert(!cbae_dom_tree_dominates(&dt, 1, 3));
    assert(!cbae_dom_tree_dominates(&dt, 2, 3));
    assert(cbae_dom_tree_dominates(&dt, 0, 3));

    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);
    const uint32_t just3[] = {3};
    assert(df_equals(&df, 0, NULL, 0));
    assert(df_equals(&df, 1, just3, 1));
    assert(df_equals(&df, 2, just3, 1));
    assert(df_equals(&df, 3, NULL, 0));

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] diamond: join idom is entry, DF(1)=DF(2)={3}\n");
}

/* ── Shape 3: loop  0 -> 1 ; 1 -> {2,3} ; 2 -> 1 (back edge) ─────────── */
static void t_loop(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {1,2}, {1,3}, {2,1} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    cbae_dom_tree_t dt;
    assert(cbae_dom_tree_build(f, &arena, &dt) == CBAE_OK);

    assert(cbae_dom_tree_idom(&dt, 1) == 0);
    assert(cbae_dom_tree_idom(&dt, 2) == 1);
    assert(cbae_dom_tree_idom(&dt, 3) == 1);

    assert(cbae_dom_tree_dominates(&dt, 1, 2)); /* header dominates its body */
    assert(cbae_dom_tree_dominates(&dt, 1, 3)); /* and the exit */
    assert(!cbae_dom_tree_dominates(&dt, 2, 3));/* body does NOT dominate exit:
                                                   * 3 is reachable from 1 directly */
    assert(!cbae_dom_tree_dominates(&dt, 2, 1));

    /* Classic loop-header property: the header is in ITS OWN dominance
     * frontier, because the back edge brings control back to it from a
     * block (2) the header dominates but which does not strictly
     * dominate the header. */
    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);
    const uint32_t just1[] = {1};
    assert(df_equals(&df, 0, NULL, 0));
    assert(df_equals(&df, 1, just1, 1));
    assert(df_equals(&df, 2, just1, 1));
    assert(df_equals(&df, 3, NULL, 0));

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] loop: header in its own frontier, body doesn't dominate exit\n");
}

/* ── Shape 4: nested diamond -- exercises deeper idom chains ─────────────
 *
 *        0
 *       / \
 *      1   4
 *     / \   |
 *    2   3  |
 *     \ /   |
 *      5    |
 *       \  /
 *        6
 */
static void t_nested_diamond(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = {
        {0,1}, {0,4}, {1,2}, {1,3}, {2,5}, {3,5}, {5,6}, {4,6}
    };
    cbae_cir_function_t *f = make_cfg(&arena, 7, edges, 8);

    cbae_dom_tree_t dt;
    assert(cbae_dom_tree_build(f, &arena, &dt) == CBAE_OK);

    assert(cbae_dom_tree_idom(&dt, 1) == 0);
    assert(cbae_dom_tree_idom(&dt, 2) == 1);
    assert(cbae_dom_tree_idom(&dt, 3) == 1);
    assert(cbae_dom_tree_idom(&dt, 4) == 0);
    assert(cbae_dom_tree_idom(&dt, 5) == 1); /* inner join: both 2 and 3 lead here,
                                                * their common dominator is 1 */
    assert(cbae_dom_tree_idom(&dt, 6) == 0); /* outer join: 5 (via 1) and 4 both
                                                * lead here; common ancestor is 0 */

    assert(cbae_dom_tree_dominates(&dt, 1, 5));
    assert(!cbae_dom_tree_dominates(&dt, 1, 6)); /* 4 bypasses 1 */
    assert(cbae_dom_tree_dominates(&dt, 0, 6));

    /* DF hand-derived (see file header):
     *   join 5 (preds 2,3, idom 1): DF(2)={5}, DF(3)={5}
     *   join 6 (preds 5,4, idom 0): runner from 5 walks 5->1->0, so DF(5)
     *   and DF(1) both gain 6; runner from 4 gains DF(4)={6} */
    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);
    const uint32_t just5[] = {5}, just6[] = {6};
    assert(df_equals(&df, 0, NULL, 0));
    assert(df_equals(&df, 1, just6, 1));
    assert(df_equals(&df, 2, just5, 1));
    assert(df_equals(&df, 3, just5, 1));
    assert(df_equals(&df, 4, just6, 1));
    assert(df_equals(&df, 5, just6, 1));
    assert(df_equals(&df, 6, NULL, 0));

    /* Dominator-tree children: 0 -> {1,4,6}, 1 -> {2,3,5} */
    assert(cbae_vector_count(cbae_dom_tree_children(&dt, 0)) == 3);
    assert(cbae_vector_count(cbae_dom_tree_children(&dt, 1)) == 3);
    assert(cbae_vector_count(cbae_dom_tree_children(&dt, 2)) == 0);

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] nested diamond: deep idom chain + 7-block frontier all correct\n");
}

/* ── Shape 5: the ENTRY block is itself a loop header ────────────────────
 *
 *   0 -> 1;  1 -> {0, 2}      (block 1 jumps back to the function's first
 *                              block, e.g. a tight loop with no prologue)
 *
 * Entry dominates everything; 1 dominates 1 and 2.
 * By the definition DF(a) = { b : a dominates a predecessor of b and a
 * does not strictly dominate b }:
 *   b = 0: predecessor 1. 0 dominates 1 and does not strictly dominate
 *          itself  -> 0 in DF(0).  1 dominates 1 and does not dominate 0
 *          -> 0 in DF(1).
 *   b = 1: predecessor 0. Only 0 dominates 0, but 0 strictly dominates 1
 *          -> nothing.
 *   b = 2: predecessor 1. 1 dominates 1 but strictly dominates 2 -> no.
 *   So DF(0) = {0}, DF(1) = {0}, DF(2) = {}.
 * The entry has only ONE predecessor here; it still counts as a join
 * because the function's own entry is an implicit second incoming edge.
 * (Found by the randomized cross-check below, which is why it is pinned
 * here by hand.) */
static void t_entry_is_loop_header(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {1,0}, {1,2} };
    cbae_cir_function_t *f = make_cfg(&arena, 3, edges, 3);

    cbae_dom_tree_t dt;
    assert(cbae_dom_tree_build(f, &arena, &dt) == CBAE_OK);
    assert(cbae_dom_tree_idom(&dt, 0) == 0);
    assert(cbae_dom_tree_idom(&dt, 1) == 0);
    assert(cbae_dom_tree_idom(&dt, 2) == 1);

    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);
    const uint32_t just0[] = {0};
    assert(df_equals(&df, 0, just0, 1));
    assert(df_equals(&df, 1, just0, 1));
    assert(df_equals(&df, 2, NULL, 0));

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] entry that is a loop header: entry in its own frontier\n");
}

/* ── Randomized cross-check against the brute-force reference ───────────
 *
 * Random CFGs (every block reachable from entry, at most two successors
 * per block, with back edges, cross edges, self-loops and irreducible
 * regions) are run through both the production tree and the independent
 * set-based reference in dom_reference.h. They must agree on:
 *   - every immediate dominator,
 *   - every dominates(a, b) pair,
 *   - every dominance frontier, where the reference frontier comes
 *     straight from the definition:
 *         DF(a) = { b : a dominates some predecessor of b,
 *                       and a does not strictly dominate b }.  */
static void check_one_random(const rgraph_t *g) {
    const uint32_t n = g->n;

    uint64_t dom[RG_MAX_NODES];
    ref_dominators(n, 0, g->e, g->m, dom);

    cbae_arena_t arena; cbae_arena_init(&arena, 256 * 1024);
    cbae_cir_function_t *f = make_cfg(&arena, n, g->e, g->m);

    cbae_dom_tree_t dt;
    if (cbae_dom_tree_build(f, &arena, &dt) != CBAE_OK) {
        rg_dump(g);
        assert(0 && "cbae_dom_tree_build failed");
    }
    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);

    for (uint32_t b = 0; b < n; b++) {
        uint32_t want = ref_idom(n, 0, dom, b);
        uint32_t got  = cbae_dom_tree_idom(&dt, b);
        if (got != want) {
            rg_dump(g);
            fprintf(stderr, "  block %u: idom got %u, want %u\n", b, got, want);
            assert(0 && "idom mismatch");
        }
        for (uint32_t a = 0; a < n; a++) {
            bool want_d = (dom[b] >> a) & 1;
            bool got_d  = cbae_dom_tree_dominates(&dt, a, b);
            if (want_d != got_d) {
                rg_dump(g);
                fprintf(stderr, "  dominates(%u,%u): got %d, want %d\n",
                        a, b, got_d, want_d);
                assert(0 && "dominates mismatch");
            }
        }
    }

    for (uint32_t a = 0; a < n; a++) {
        uint64_t want_df = 0;
        for (uint32_t i = 0; i < g->m; i++) {
            uint32_t p = g->e[i][0], b = g->e[i][1];
            bool a_dom_pred   = (dom[p] >> a) & 1;
            bool a_strict_dom = (a != b) && ((dom[b] >> a) & 1);
            if (a_dom_pred && !a_strict_dom) want_df |= 1ull << b;
        }
        const cbae_vector_t *v = cbae_dom_frontier_of(&df, a);
        uint64_t got_df = 0;
        for (uint32_t j = 0; j < cbae_vector_count(v); j++)
            got_df |= 1ull << *(const uint32_t *)cbae_vector_at(v, j);
        if (got_df != want_df) {
            rg_dump(g);
            fprintf(stderr, "  DF(%u): got mask %llx, want %llx\n", a,
                    (unsigned long long)got_df, (unsigned long long)want_df);
            assert(0 && "dominance frontier mismatch");
        }
    }

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
}

static void t_random_vs_reference(void) {
    rng_t rng = { 0xD1B54A32D192ED03ull };
    uint32_t looped = 0;

    for (uint32_t k = 0; k < 3000; k++) {
        uint32_t n = 1 + rng_next(&rng) % 14;
        rgraph_t g;
        rg_generate(&g, &rng, n);
        check_one_random(&g);

        /* Count graphs that actually contain a cycle, so the summary
         * shows the loop/irreducible paths were exercised. */
        for (uint32_t i = 0; i < g.m; i++)
            if (g.e[i][1] <= g.e[i][0]) { looped++; break; }
    }
    printf("  [PASS] 3000 random CFGs match the brute-force reference "
           "(idom, dominates, frontier; %u contained back/self edges)\n", looped);
}

int main(void) {
    printf("=== test_dominator_tree ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_straight_line();
    t_diamond();
    t_loop();
    t_nested_diamond();
    t_entry_is_loop_header();
    t_random_vs_reference();

    printf("All dominator tree tests passed.\n");
    return 0;
}
