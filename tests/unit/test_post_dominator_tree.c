/**
 * @file test_post_dominator_tree.c
 * @brief Post-dominator tree on hand-derived CFG shapes (including the
 *        virtual exit and infinite loops) and a randomized cross-check
 *        against an independent brute-force reference.
 *
 * Pure graph algorithm test: CFGs are built directly through the CIR
 * builder's block/edge API since post-dominance depends only on graph
 * structure.
 *
 * Every expected value in the hand-derived shapes was worked out from the
 * definition BEFORE running anything:
 *   - A post-dominates B iff EVERY path from B to the function exit
 *     passes through A.
 *   - ipdom(B): the strict post-dominator of B that is closest to B,
 *     i.e. post-dominated by every other strict post-dominator of B.
 *   - "EXIT" below is the virtual exit node (CBAE_PDOM_EXIT).
 */
#include "dataflow/post_dominator_tree.h"
#include "cir/cir_builder.h"
#include "platform/logging.h"
#include "dom_reference.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT CBAE_PDOM_EXIT

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

/* Does the vector hold exactly the ids in `expected` (any order)? */
static bool vec_is(const cbae_vector_t *v, const uint32_t *expected, uint32_t n) {
    if (cbae_vector_count(v) != n) return false;
    for (uint32_t i = 0; i < n; i++) {
        bool found = false;
        for (uint32_t j = 0; j < cbae_vector_count(v); j++) {
            const uint32_t *e = cbae_vector_at(v, j);
            if (*e == expected[i]) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

/* Build, run `check`, tear down. `check` receives the finished tree. */
typedef void (*check_fn)(const cbae_pdom_tree_t *pt);

static void run_shape(uint32_t nblocks, const uint32_t edges[][2], uint32_t nedges,
                      check_fn check) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    cbae_cir_function_t *f = make_cfg(&arena, nblocks, edges, nedges);

    cbae_pdom_tree_t pt;
    assert(cbae_pdom_tree_build(f, &arena, &pt) == CBAE_OK);
    check(&pt);

    cbae_pdom_tree_destroy(&pt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
}

/* ── Shape 1: straight line  0 -> 1 -> 2 ───────────────────────────────
 * Only block 2 has no successors, so it is the sole exit.
 *   ipdom(2) = EXIT; ipdom(1) = 2; ipdom(0) = 1. */
static void check_line(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 2) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 1) == 2);
    assert(cbae_pdom_tree_ipdom(pt, 0) == 1);

    assert(cbae_pdom_tree_post_dominates(pt, 2, 0));
    assert(cbae_pdom_tree_post_dominates(pt, 1, 0));
    assert(!cbae_pdom_tree_post_dominates(pt, 0, 2));
    assert(cbae_pdom_tree_post_dominates(pt, 1, 1));            /* inclusive */
    assert(!cbae_pdom_tree_strictly_post_dominates(pt, 1, 1));

    const uint32_t roots[] = {2};
    assert(vec_is(cbae_pdom_tree_exit_children(pt), roots, 1));
}

/* ── Shape 2: diamond  0 -> {1,2} -> 3 ─────────────────────────────────
 * Every path from 0, 1 or 2 ends by passing through 3.
 *   ipdom(0) = ipdom(1) = ipdom(2) = 3;  ipdom(3) = EXIT.
 * Neither branch post-dominates the fork: the other branch avoids it. */
static void check_diamond(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 0) == 3);
    assert(cbae_pdom_tree_ipdom(pt, 1) == 3);
    assert(cbae_pdom_tree_ipdom(pt, 2) == 3);
    assert(cbae_pdom_tree_ipdom(pt, 3) == EXIT);

    assert(cbae_pdom_tree_post_dominates(pt, 3, 0));
    assert(!cbae_pdom_tree_post_dominates(pt, 1, 0));
    assert(!cbae_pdom_tree_post_dominates(pt, 2, 0));

    const uint32_t kids[] = {0, 1, 2};
    assert(vec_is(cbae_pdom_tree_children(pt, 3), kids, 3));
}

/* ── Shape 3: if-then, no else  0 -> {1,2}; 1 -> 2 ─────────────────────
 * Path 0->2 skips block 1, so 1 does not post-dominate 0.
 *   ipdom(0) = 2; ipdom(1) = 2; ipdom(2) = EXIT. */
static void check_if_then(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 0) == 2);
    assert(cbae_pdom_tree_ipdom(pt, 1) == 2);
    assert(cbae_pdom_tree_ipdom(pt, 2) == EXIT);
    assert(!cbae_pdom_tree_post_dominates(pt, 1, 0));
}

/* ── Shape 4: loop with exit  0 -> 1; 1 -> {2,3}; 2 -> 1; 3 exit ───────
 *   3: no successors                              -> ipdom(3) = EXIT
 *   1: paths 1->3 and 1->2->1->3 all pass 3       -> ipdom(1) = 3
 *   2: only path is 2->1->...->3; 1 is closer than 3 -> ipdom(2) = 1
 *   0: only path is 0->1->...                     -> ipdom(0) = 1
 * The loop body (2) does NOT post-dominate the header: the header can
 * leave straight to 3. */
static void check_loop_exit(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 3) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 1) == 3);
    assert(cbae_pdom_tree_ipdom(pt, 2) == 1);
    assert(cbae_pdom_tree_ipdom(pt, 0) == 1);
    assert(!cbae_pdom_tree_post_dominates(pt, 2, 1));
    assert(cbae_pdom_tree_post_dominates(pt, 1, 2));
}

/* ── Shape 5: two exits  0 -> {1,2}, both 1 and 2 have no successors ───
 * No single real block is on every path from 0, so the only common
 * post-dominator is the virtual exit.
 *   ipdom(0) = ipdom(1) = ipdom(2) = EXIT. */
static void check_two_exits(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 0) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 1) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 2) == EXIT);
    assert(!cbae_pdom_tree_post_dominates(pt, 1, 0));
    assert(!cbae_pdom_tree_post_dominates(pt, 2, 0));

    const uint32_t roots[] = {0, 1, 2};
    assert(vec_is(cbae_pdom_tree_exit_children(pt), roots, 3));
}

/* ── Shape 6: single block, which is an exit ───────────────────────────*/
static void check_single(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 0) == EXIT);
    assert(cbae_pdom_tree_post_dominates(pt, 0, 0));
    const uint32_t roots[] = {0};
    assert(vec_is(cbae_pdom_tree_exit_children(pt), roots, 1));
}

/* ── Shape 7: infinite loop, no exit at all  0->1; 1->2; 2->1 ──────────
 * SCCs: {0}, {1,2}. {1,2} has no edge leaving it: a SINK. Its highest
 * block id, 2, gets the synthetic edge to the virtual exit.
 *   ipdom(2) = EXIT; ipdom(1) = 2 (its only successor); ipdom(0) = 1. */
static void check_infinite_loop(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 2) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 1) == 2);
    assert(cbae_pdom_tree_ipdom(pt, 0) == 1);
}

/* ── Shape 8: real exit plus a self-loop  0->{1,2}; 1 exit; 2->2 ───────
 * Block 2 cannot exit; {2} is a sink SCC (its self-edge stays inside),
 * so 2 is linked to the virtual exit. Both routes from 0 end at EXIT
 * without a common real block.
 *   ipdom(0) = ipdom(1) = ipdom(2) = EXIT. */
static void check_exit_plus_selfloop(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 0) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 1) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 2) == EXIT);
}

/* ── Shape 9: a loop that leads into a self-loop sink ──────────────────
 *   0 -> 2;  2 -> {3,1};  3 -> 2;  1 -> 1
 * SCCs: {0}, {2,3} (loop), {1} (self-loop). Only {1} is a sink: the loop
 * {2,3} leaves via the edge 2->1. The block numbering is deliberate: the
 * loop has the HIGHEST id (3), so a rule that simply linked "the
 * highest-numbered block that cannot exit" would link 3 and invent an
 * exit route 3->EXIT. Linking only sinks links 1.
 *   ipdom(1) = EXIT
 *   ipdom(2) = 1   (2->1, and 2->3->2->...->1: all paths pass 1)
 *   ipdom(3) = 2   (3's only successor)
 *   ipdom(0) = 2   (0's only successor)
 * With the wrong rule, ipdom(2) would be EXIT instead of 1. */
static void check_loop_into_sink(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 1) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 2) == 1);
    assert(cbae_pdom_tree_ipdom(pt, 3) == 2);
    assert(cbae_pdom_tree_ipdom(pt, 0) == 2);
    assert(cbae_pdom_tree_post_dominates(pt, 1, 3));
}

/* ── Shape 10: two separate sinks  0->{1,2}; 1->1; 2->2 ────────────────
 * Both {1} and {2} are sinks; each is linked. Nothing real is common to
 * both routes.  ipdom(0) = ipdom(1) = ipdom(2) = EXIT. */
static void check_two_sinks(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 0) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 1) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 2) == EXIT);
}

/* ── Shape 11: block unreachable from entry is tolerated ───────────────
 *   0 -> 1;  2 -> 1     (block 2 has no path from entry)
 * Post-dominance never consults the entry, so this is well defined.
 *   ipdom(1) = EXIT; ipdom(0) = 1; ipdom(2) = 1. */
static void check_unreachable_from_entry(const cbae_pdom_tree_t *pt) {
    assert(cbae_pdom_tree_ipdom(pt, 1) == EXIT);
    assert(cbae_pdom_tree_ipdom(pt, 0) == 1);
    assert(cbae_pdom_tree_ipdom(pt, 2) == 1);
}

static void t_handcrafted_shapes(void) {
    { const uint32_t e[][2] = {{0,1},{1,2}};
      run_shape(3, e, 2, check_line); }
    printf("  [PASS] straight line: chain of ipdoms ending at the virtual exit\n");

    { const uint32_t e[][2] = {{0,1},{0,2},{1,3},{2,3}};
      run_shape(4, e, 4, check_diamond); }
    printf("  [PASS] diamond: join post-dominates the fork and both branches\n");

    { const uint32_t e[][2] = {{0,1},{0,2},{1,2}};
      run_shape(3, e, 3, check_if_then); }
    printf("  [PASS] if-then: skipped block does not post-dominate the fork\n");

    { const uint32_t e[][2] = {{0,1},{1,2},{1,3},{2,1}};
      run_shape(4, e, 4, check_loop_exit); }
    printf("  [PASS] loop with exit: body does not post-dominate header\n");

    { const uint32_t e[][2] = {{0,1},{0,2}};
      run_shape(3, e, 2, check_two_exits); }
    printf("  [PASS] two exits: only the virtual exit is common\n");

    run_shape(1, NULL, 0, check_single);
    printf("  [PASS] single block\n");

    { const uint32_t e[][2] = {{0,1},{1,2},{2,1}};
      run_shape(3, e, 3, check_infinite_loop); }
    printf("  [PASS] infinite loop: sink SCC linked from its highest block\n");

    { const uint32_t e[][2] = {{0,1},{0,2},{2,2}};
      run_shape(3, e, 3, check_exit_plus_selfloop); }
    printf("  [PASS] real exit + self-loop sink\n");

    { const uint32_t e[][2] = {{0,2},{2,3},{2,1},{3,2},{1,1}};
      run_shape(4, e, 5, check_loop_into_sink); }
    printf("  [PASS] loop feeding a sink: only the sink is linked, not the loop\n");

    { const uint32_t e[][2] = {{0,1},{0,2},{1,1},{2,2}};
      run_shape(3, e, 4, check_two_sinks); }
    printf("  [PASS] two independent sink SCCs\n");

    { const uint32_t e[][2] = {{0,1},{2,1}};
      run_shape(3, e, 2, check_unreachable_from_entry); }
    printf("  [PASS] block unreachable from entry tolerated\n");
}

/* ── Randomized cross-check against the brute-force reference ───────────
 *
 * For each random CFG in which every block can reach an exit (so no
 * synthetic edges are involved), build the reversed graph with a virtual
 * exit INDEPENDENTLY here, run the set-based reference dominators on it,
 * and demand that the production tree agrees on every ipdom and on every
 * post_dominates(a, b) pair. Includes self-loops, back edges, cross edges
 * and irreducible regions. */
static void check_one_random(const rgraph_t *g) {
    const uint32_t n = g->n;
    const uint32_t N = n + 1, X = n;

    uint32_t redges[RG_MAX_EDGES + RG_MAX_NODES][2];
    uint32_t rm = 0;
    for (uint32_t i = 0; i < g->m; i++) {         /* u->w becomes w->u */
        redges[rm][0] = g->e[i][1];
        redges[rm][1] = g->e[i][0];
        rm++;
    }
    for (uint32_t b = 0; b < n; b++)               /* X -> every real exit */
        if (g->outdeg[b] == 0) { redges[rm][0] = X; redges[rm][1] = b; rm++; }

    uint64_t dom[RG_MAX_NODES + 1];
    ref_dominators(N, X, (const uint32_t (*)[2])redges, rm, dom);

    cbae_arena_t arena; cbae_arena_init(&arena, 256 * 1024);
    cbae_cir_function_t *f = make_cfg(&arena, n, g->e, g->m);

    cbae_pdom_tree_t pt;
    if (cbae_pdom_tree_build(f, &arena, &pt) != CBAE_OK) {
        rg_dump(g);
        assert(0 && "cbae_pdom_tree_build failed");
    }

    for (uint32_t b = 0; b < n; b++) {
        uint32_t want = ref_idom(N, X, dom, b);
        if (want == X) want = EXIT;
        uint32_t got = cbae_pdom_tree_ipdom(&pt, b);
        if (got != want) {
            rg_dump(g);
            fprintf(stderr, "  block %u: ipdom got %d, want %d\n", b,
                    (int)got, (int)want);
            assert(0 && "ipdom mismatch");
        }
        for (uint32_t a = 0; a < n; a++) {
            bool want_pd = (dom[b] >> a) & 1;
            bool got_pd  = cbae_pdom_tree_post_dominates(&pt, a, b);
            if (want_pd != got_pd) {
                rg_dump(g);
                fprintf(stderr, "  post_dominates(%u,%u): got %d, want %d\n",
                        a, b, got_pd, want_pd);
                assert(0 && "post_dominates mismatch");
            }
        }
    }

    cbae_pdom_tree_destroy(&pt);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
}

static void t_random_vs_reference(void) {
    rng_t rng = { 0x9E3779B97F4A7C15ull };
    uint32_t checked = 0, rejected = 0, with_multi_exit = 0;

    while (checked < 3000) {
        uint32_t n = 1 + rng_next(&rng) % 14;
        rgraph_t g;
        rg_generate(&g, &rng, n);
        if (!rg_all_reach_exit(&g)) { rejected++; continue; }

        uint32_t exits = 0;
        for (uint32_t b = 0; b < g.n; b++) if (g.outdeg[b] == 0) exits++;
        if (exits > 1) with_multi_exit++;

        check_one_random(&g);
        checked++;
    }
    printf("  [PASS] %u random CFGs match the brute-force reference "
           "(%u had several exits; %u infinite-loop graphs set aside)\n",
           checked, with_multi_exit, rejected);
}

int main(void) {
    printf("=== test_post_dominator_tree ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_handcrafted_shapes();
    t_random_vs_reference();

    printf("All post-dominator tree tests passed.\n");
    return 0;
}
