/**
 * @file test_dominance_contracts.c
 * @brief What the dominator tree, the dominance frontier and the post-dominator tree promise a caller
 *        who gets it wrong, or whose request cannot be met (their headers say it; this file holds them to it):
 *
 *   - A NULL argument, a function with no blocks, a block the entry cannot reach (dominator tree only: the
 *     post-dominator tree tolerates it) and a function too large are errors, and an error leaves the output
 *     EMPTY (all zero), also when it was poisoned before the call.
 *   - An empty tree, a destroyed one and a NULL one answer every query "no such block": no crash, no value that
 *     could be taken for an answer. So does a block id that is not in a tree that was built.
 *   - Destroying twice, destroying an empty one and destroying NULL are safe.
 *   - A frontier asked of an empty tree, or of a tree whose function has changed since, is refused.
 *   - dom_core_number_tree() (internal) numbers every tree it is given exactly, and refuses what is not a tree
 *     (a child that does not exist, a node with two parents, a cycle, a node the root does not reach, no nodes)
 *     with an error and not a loop or a write past its stack.
 *   - The frontier of a deep chain whose every block also leads to one join, which the shortcut in the
 *     computation (a walk stops where an earlier walk for the same join has been) is for, is the exact set.
 *
 * Failures of the allocator and of the arena are test_dominance_oom.c.
 */
#include "dataflow/dominator_tree.h"
#include "dataflow/post_dominator_tree.h"
#include "dom_core.h"
#include "cir_test_util.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(msg) printf("  [PASS] %s\n", (msg))

static bool all_zero(const void *p, size_t n) {
    const uint8_t *q = p;
    for (size_t i = 0; i < n; i++) if (q[i]) return false;
    return true;
}

static void make_cfg(fn_t *x, const char *name, uint32_t n, const uint32_t (*edges)[2], uint32_t m) {
    fn_init(x, name);
    cbae_cir_block_t *blk[64];
    assert(n <= 64);
    blk[0] = x->b0;
    for (uint32_t i = 1; i < n; i++) blk[i] = fn_block(x, 0x1000u + 0x10u * i);
    for (uint32_t e = 0; e < m; e++) assert(cbae_cir_block_add_edge(blk[edges[e][0]], blk[edges[e][1]]) == CBAE_OK);
}

/* a diamond: 0 -> 1, 2 -> 3 */
static void make_diamond(fn_t *x) {
    static const uint32_t e[][2] = { {0,1}, {0,2}, {1,3}, {2,3} };
    make_cfg(x, "diamond", 4, e, 4);
}

static bool set_is(const cbae_vector_t *v, const uint32_t *want, uint32_t n) {
    if (cbae_vector_count(v) != n) return false;
    for (uint32_t i = 0; i < n; i++) if (*(const uint32_t *)cbae_vector_at(v, i) != want[i]) return false;
    return true;
}

/* ── Arguments and errors ─────────────────────────────────────────────── */

static void test_arguments(void) {
    fn_t x;
    make_diamond(&x);
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);

    cbae_dom_tree_t dt;
    cbae_pdom_tree_t pt;
    assert(cbae_dom_tree_build(x.f, &arena, NULL) == CBAE_ERR_INVALID);
    assert(cbae_pdom_tree_build(x.f, &arena, NULL) == CBAE_ERR_INVALID);

    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(NULL, &arena, &dt) == CBAE_ERR_INVALID && all_zero(&dt, sizeof dt));
    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(x.f, NULL, &dt) == CBAE_ERR_INVALID && all_zero(&dt, sizeof dt));
    memset(&pt, 0xA5, sizeof pt);
    assert(cbae_pdom_tree_build(NULL, &arena, &pt) == CBAE_ERR_INVALID && all_zero(&pt, sizeof pt));
    memset(&pt, 0xA5, sizeof pt);
    assert(cbae_pdom_tree_build(x.f, NULL, &pt) == CBAE_ERR_INVALID && all_zero(&pt, sizeof pt));

    /* a function with no blocks */
    cbae_cir_function_t *none;
    assert(cbae_cir_function_create(&x.arena, 0x9000, "none", &none) == CBAE_OK);
    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(none, &arena, &dt) == CBAE_ERR_INVALID && all_zero(&dt, sizeof dt));
    memset(&pt, 0xA5, sizeof pt);
    assert(cbae_pdom_tree_build(none, &arena, &pt) == CBAE_ERR_INVALID && all_zero(&pt, sizeof pt));

    /* a block the entry cannot reach: no dominator, so no dominator tree; the post-dominator tree does not need the entry */
    fn_t y;
    static const uint32_t unreachable[][2] = { {0,1}, {2,1} };
    make_cfg(&y, "unreachable", 3, unreachable, 2);
    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(y.f, &arena, &dt) == CBAE_ERR_INVALID && all_zero(&dt, sizeof dt));
    memset(&pt, 0xA5, sizeof pt);
    assert(cbae_pdom_tree_build(y.f, &arena, &pt) == CBAE_OK);
    assert(pt.block_count == 3);
    cbae_pdom_tree_destroy(&pt);

    fn_done(&y);
    cbae_cir_function_destroy(none);
    fn_done(&x);
    cbae_arena_destroy(&arena);
    PASS("arguments: NULLs, a function without blocks and a block the entry cannot reach are refused with an empty (not merely unchanged) output");
}

/* ── A function too large ─────────────────────────────────────────────── */

static void test_too_large(void) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 4096) == CBAE_OK);
    cbae_cir_function_t fake;                     /* a function that claims more blocks than the code takes; nothing reads them */
    memset(&fake, 0, sizeof fake);

    cbae_dom_tree_t dt;
    cbae_pdom_tree_t pt;
    fake.blocks.count = (size_t)DOM_MAX_NODES + 1u;
    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(&fake, &arena, &dt) == CBAE_ERR_OVERFLOW && all_zero(&dt, sizeof dt));
    memset(&pt, 0xA5, sizeof pt);
    assert(cbae_pdom_tree_build(&fake, &arena, &pt) == CBAE_ERR_OVERFLOW && all_zero(&pt, sizeof pt));
    fake.blocks.count = (size_t)1 << 40;
    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(&fake, &arena, &dt) == CBAE_ERR_OVERFLOW && all_zero(&dt, sizeof dt));

    /* the limit itself is not an overflow: it is asked of the arena, which cannot hold it */
    fake.blocks.count = DOM_MAX_NODES;
    memset(&dt, 0xA5, sizeof dt);
    assert(cbae_dom_tree_build(&fake, &arena, &dt) == CBAE_ERR_OOM && all_zero(&dt, sizeof dt));
    memset(&pt, 0xA5, sizeof pt);
    assert(cbae_pdom_tree_build(&fake, &arena, &pt) == CBAE_ERR_OOM && all_zero(&pt, sizeof pt));

    /* the graph core refuses the same sizes before it allocates anything */
    dom_csr_t csr;
    memset(&csr, 0xA5, sizeof csr);
    assert(dom_csr_build(DOM_MAX_NODES + 1u, NULL, NULL, 0, &csr) == CBAE_ERR_OVERFLOW && all_zero(&csr, sizeof csr));
    memset(&csr, 0xA5, sizeof csr);
    assert(dom_csr_build(1, NULL, NULL, 3u * DOM_MAX_NODES + 1u, &csr) == CBAE_ERR_OVERFLOW && all_zero(&csr, sizeof csr));

    cbae_arena_destroy(&arena);
    PASS("a function of more than DOM_MAX_NODES blocks is CBAE_ERR_OVERFLOW with an empty output; the limit itself is not refused as too large");
}

/* ── The adjacency lists ──────────────────────────────────────────────── */

static void test_csr(void) {
    /* 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3, 3 -> 3: the lists keep the order of the edges */
    const uint32_t from[5] = { 0, 0, 1, 2, 3 }, to[5] = { 1, 2, 3, 3, 3 };
    dom_csr_t c;
    assert(dom_csr_build(4, from, to, 5, &c) == CBAE_OK);
    const uint32_t so[5] = { 0, 2, 3, 4, 5 }, sa[5] = { 1, 2, 3, 3, 3 }, po[5] = { 0, 0, 1, 2, 5 }, pa[5] = { 0, 0, 1, 2, 3 };
    assert(memcmp(c.succ_off, so, sizeof so) == 0 && memcmp(c.succ_adj, sa, sizeof sa) == 0);
    assert(memcmp(c.pred_off, po, sizeof po) == 0 && memcmp(c.pred_adj, pa, sizeof pa) == 0);
    dom_csr_free(&c);
    assert(all_zero(&c, sizeof c));
    dom_csr_free(&c);                                           /* a second free is a no-op */
    dom_csr_free(NULL);

    /* no edges at all is a graph */
    assert(dom_csr_build(2, NULL, NULL, 0, &c) == CBAE_OK);
    assert(c.succ_off[0] == 0 && c.succ_off[2] == 0 && c.pred_off[2] == 0);
    dom_csr_free(&c);

    /* an edge that leaves the graph, at either end and anywhere in the list, is refused with nothing held */
    const uint32_t bad_from[3] = { 0, 1, 4 }, bad_to[3] = { 1, 2, 0 };
    memset(&c, 0xA5, sizeof c);
    assert(dom_csr_build(4, bad_from, bad_to, 3, &c) == CBAE_ERR_INVALID && all_zero(&c, sizeof c));
    const uint32_t far_from[3] = { 0, 1, 2 }, far_to[3] = { 1, 2, 4 };
    memset(&c, 0xA5, sizeof c);
    assert(dom_csr_build(4, far_from, far_to, 3, &c) == CBAE_ERR_INVALID && all_zero(&c, sizeof c));
    const uint32_t last_ok_from[3] = { 0, 1, 3 }, last_ok_to[3] = { 1, 2, 3 };
    assert(dom_csr_build(4, last_ok_from, last_ok_to, 3, &c) == CBAE_OK);       /* the highest valid node is 3 */
    dom_csr_free(&c);
    PASS("the adjacency lists: both directions in edge order, an edge outside the graph is refused with an empty result, nothing is held after an error");
}

/* ── Queries on what is not there ─────────────────────────────────────── */

static void test_empty_trees(void) {
    cbae_dom_tree_t e;
    memset(&e, 0, sizeof e);
    for (uint32_t id = 0; id < 3; id++) {
        assert(cbae_dom_tree_idom(&e, id) == CBAE_DOM_NONE);
        assert(!cbae_dom_tree_dominates(&e, id, id));
        assert(!cbae_dom_tree_strictly_dominates(&e, id, id + 1));
        const cbae_vector_t *c = cbae_dom_tree_children(&e, id);
        assert(c && cbae_vector_count(c) == 0 && cbae_vector_at(c, 0) == NULL);
    }
    cbae_dom_tree_destroy(&e);
    cbae_dom_tree_destroy(&e);
    cbae_dom_tree_destroy(NULL);
    assert(cbae_dom_tree_idom(NULL, 0) == CBAE_DOM_NONE && !cbae_dom_tree_dominates(NULL, 0, 0));
    assert(cbae_vector_count(cbae_dom_tree_children(NULL, 0)) == 0);

    cbae_pdom_tree_t p;
    memset(&p, 0, sizeof p);
    for (uint32_t id = 0; id < 3; id++) {
        assert(cbae_pdom_tree_ipdom(&p, id) == CBAE_PDOM_NONE);
        assert(!cbae_pdom_tree_post_dominates(&p, id, id));
        assert(!cbae_pdom_tree_strictly_post_dominates(&p, id, id + 1));
        const cbae_vector_t *c = cbae_pdom_tree_children(&p, id);
        assert(c && cbae_vector_count(c) == 0 && cbae_vector_at(c, 0) == NULL);
    }
    const cbae_vector_t *ec = cbae_pdom_tree_exit_children(&p);
    assert(ec && cbae_vector_count(ec) == 0);
    cbae_pdom_tree_destroy(&p);
    cbae_pdom_tree_destroy(&p);
    cbae_pdom_tree_destroy(NULL);
    assert(cbae_pdom_tree_ipdom(NULL, 0) == CBAE_PDOM_NONE && !cbae_pdom_tree_post_dominates(NULL, 0, 0));
    assert(cbae_vector_count(cbae_pdom_tree_children(NULL, 0)) == 0 && cbae_vector_count(cbae_pdom_tree_exit_children(NULL)) == 0);

    cbae_dom_frontier_t f;
    memset(&f, 0, sizeof f);
    const cbae_vector_t *fv = cbae_dom_frontier_of(&f, 0);
    assert(fv && cbae_vector_count(fv) == 0);
    cbae_dom_frontier_destroy(&f);
    cbae_dom_frontier_destroy(&f);
    cbae_dom_frontier_destroy(NULL);
    assert(cbae_vector_count(cbae_dom_frontier_of(NULL, 0)) == 0);

    assert(CBAE_PDOM_NONE != CBAE_PDOM_EXIT && CBAE_DOM_NONE != CBAE_PDOM_NONE);
    PASS("an empty, destroyed or NULL tree or frontier answers every query \"no such block\", and destroying it again is safe");
}

static void test_block_ids_outside_the_tree(void) {
    fn_t x;
    make_diamond(&x);
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);
    cbae_dom_tree_t dt;
    cbae_pdom_tree_t pt;
    cbae_dom_frontier_t df;
    assert(cbae_dom_tree_build(x.f, &arena, &dt) == CBAE_OK);
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);
    assert(cbae_pdom_tree_build(x.f, &arena, &pt) == CBAE_OK);

    /* the answers for real blocks, so that the "no" below is not what everything says */
    assert(cbae_dom_tree_idom(&dt, 0) == 0 && cbae_dom_tree_idom(&dt, 3) == 0);
    assert(cbae_dom_tree_dominates(&dt, 0, 3) && !cbae_dom_tree_dominates(&dt, 1, 3));
    assert(cbae_pdom_tree_ipdom(&pt, 3) == CBAE_PDOM_EXIT && cbae_pdom_tree_ipdom(&pt, 0) == 3);
    assert(cbae_pdom_tree_post_dominates(&pt, 3, 0) && !cbae_pdom_tree_post_dominates(&pt, 1, 0));
    assert(cbae_vector_count(cbae_pdom_tree_exit_children(&pt)) == 1);

    const uint32_t bad[] = { 4, 5, 1000, UINT32_MAX - 1u, UINT32_MAX };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const uint32_t b = bad[i];
        assert(cbae_dom_tree_idom(&dt, b) == CBAE_DOM_NONE);
        assert(!cbae_dom_tree_dominates(&dt, b, 0) && !cbae_dom_tree_dominates(&dt, 0, b) && !cbae_dom_tree_dominates(&dt, b, b));
        assert(!cbae_dom_tree_strictly_dominates(&dt, b, 0) && !cbae_dom_tree_strictly_dominates(&dt, 0, b));
        const cbae_vector_t *c = cbae_dom_tree_children(&dt, b);
        assert(c && cbae_vector_count(c) == 0 && c != dt.children + b);          /* not the memory past the array either */
        const cbae_vector_t *f = cbae_dom_frontier_of(&df, b);
        assert(f && cbae_vector_count(f) == 0 && f != df.frontier + b);
        assert(cbae_pdom_tree_ipdom(&pt, b) == CBAE_PDOM_NONE);
        assert(!cbae_pdom_tree_post_dominates(&pt, b, 0) && !cbae_pdom_tree_post_dominates(&pt, 0, b) && !cbae_pdom_tree_post_dominates(&pt, b, b));
        assert(!cbae_pdom_tree_strictly_post_dominates(&pt, b, 0) && !cbae_pdom_tree_strictly_post_dominates(&pt, 0, b));
        const cbae_vector_t *pc = cbae_pdom_tree_children(&pt, b);
        assert(pc && cbae_vector_count(pc) == 0 && pc != pt.children + b);
    }
    /* block 4 is the virtual exit of the post-dominator tree, not a block: it is not a node a caller may ask about */
    assert(cbae_pdom_tree_ipdom(&pt, 4) == CBAE_PDOM_NONE && !cbae_pdom_tree_post_dominates(&pt, 4, 3) && !cbae_pdom_tree_post_dominates(&pt, 3, 4));

    /* a destroyed tree keeps its arrays (the arena owns them) and has no children */
    cbae_dom_tree_destroy(&dt);
    cbae_dom_tree_destroy(&dt);
    assert(cbae_dom_tree_dominates(&dt, 0, 3) && cbae_vector_count(cbae_dom_tree_children(&dt, 0)) == 0);
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)          /* and still says no to what is not there */
        assert(!cbae_dom_tree_dominates(&dt, 0, bad[i]) && !cbae_dom_tree_dominates(&dt, bad[i], 0) && cbae_dom_tree_idom(&dt, bad[i]) == CBAE_DOM_NONE);
    cbae_pdom_tree_destroy(&pt);
    cbae_pdom_tree_destroy(&pt);
    cbae_dom_frontier_destroy(&df);
    cbae_dom_frontier_destroy(&df);
    assert(df.frontier == NULL && df.block_count == 0);
    assert(cbae_vector_count(cbae_dom_frontier_of(&df, 0)) == 0);

    cbae_arena_destroy(&arena);
    fn_done(&x);
    PASS("block ids that are not in a built tree (one past the end, far past it, the two largest values, the virtual exit) are answered \"no\", and a double destroy is safe");
}

/* ── The frontier of a tree that is not usable ────────────────────────── */

static void test_frontier_arguments(void) {
    fn_t x;
    make_diamond(&x);
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);
    cbae_dom_tree_t dt;
    assert(cbae_dom_tree_build(x.f, &arena, &dt) == CBAE_OK);

    cbae_dom_frontier_t df;
    assert(cbae_dom_frontier_compute(&dt, NULL) == CBAE_ERR_INVALID);
    memset(&df, 0xA5, sizeof df);
    assert(cbae_dom_frontier_compute(NULL, &df) == CBAE_ERR_INVALID && all_zero(&df, sizeof df));

    cbae_dom_tree_t empty;
    memset(&empty, 0, sizeof empty);
    memset(&df, 0xA5, sizeof df);
    assert(cbae_dom_frontier_compute(&empty, &df) == CBAE_ERR_INVALID && all_zero(&df, sizeof df));

    /* a tree that failed to build is an empty one, and a frontier of it is refused, not computed from garbage */
    cbae_arena_t tiny;
    assert(cbae_arena_init(&tiny, 16) == CBAE_OK);
    cbae_dom_tree_t failed;
    memset(&failed, 0xA5, sizeof failed);
    assert(cbae_dom_tree_build(x.f, &tiny, &failed) == CBAE_ERR_OOM);
    memset(&df, 0xA5, sizeof df);
    assert(cbae_dom_frontier_compute(&failed, &df) == CBAE_ERR_INVALID && all_zero(&df, sizeof df));
    cbae_arena_destroy(&tiny);

    /* the tree borrows the function: one that has gained a block since is not the one the tree describes */
    (void)fn_block(&x, 0x5000);
    memset(&df, 0xA5, sizeof df);
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_ERR_INVALID && all_zero(&df, sizeof df));

    cbae_dom_tree_destroy(&dt);
    cbae_arena_destroy(&arena);
    fn_done(&x);
    PASS("a frontier is refused (and left empty) for a NULL, an empty or a failed tree and for one whose function has changed since");
}

/* ── dom_core_number_tree ─────────────────────────────────────────────── */

/* The children of one node: how many, and which. */
typedef struct { uint32_t n; uint32_t kid[4]; } kids_t;

static void build_children(cbae_vector_t *c, const kids_t *k, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        assert(cbae_vector_init(&c[i], sizeof(uint32_t), 2) == CBAE_OK);
        for (uint32_t j = 0; j < k[i].n; j++) assert(cbae_vector_push(&c[i], &k[i].kid[j]) == CBAE_OK);
    }
}

static void free_children(cbae_vector_t *c, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) cbae_vector_destroy(&c[i]);
}

/* The arrays and the children are exactly n long, on the heap, so that a read or a write one past them is an error the
 * address sanitizer reports; the arrays start as something that is not "not numbered". The numbers come back in en and lv. */
static cbae_err_t number(const kids_t *k, uint32_t n, uint32_t root, uint32_t *en, uint32_t *lv) {
    cbae_vector_t *c = malloc(sizeof *c * n);
    uint32_t *enter = malloc(sizeof *enter * n), *leave = malloc(sizeof *leave * n);
    assert(c && enter && leave);
    memset(enter, 0x5A, sizeof *enter * n);
    memset(leave, 0x5A, sizeof *leave * n);
    build_children(c, k, n);
    const cbae_err_t rc = dom_core_number_tree(n, root, c, enter, leave);
    free_children(c, n);
    if (rc == CBAE_OK) { memcpy(en, enter, sizeof *enter * n); memcpy(lv, leave, sizeof *leave * n); }
    free(c); free(enter); free(leave);
    return rc;
}

static void test_number_tree(void) {
    uint32_t en[8], lv[8];

    /*        0            the intervals, by hand:
     *      / | \             0:[0,13]  1:[1,4]  3:[2,3]  2:[5,6]  4:[7,12]  5:[8,11]  6:[9,10]
     *     1  2  4
     *     |     |
     *     3     5
     *           |
     *           6                                                                          */
    const kids_t tree[7] = { {3, {1, 2, 4}}, {1, {3}}, {0}, {0}, {1, {5}}, {1, {6}}, {0} };
    assert(number(tree, 7, 0, en, lv) == CBAE_OK);
    const uint32_t want_en[7] = { 0, 1, 5, 2, 7, 8, 9 }, want_lv[7] = { 13, 4, 6, 3, 12, 11, 10 };
    assert(memcmp(en, want_en, sizeof want_en) == 0 && memcmp(lv, want_lv, sizeof want_lv) == 0);

    /* one node; a chain, which fills the stack exactly; a root that is not node 0 */
    const kids_t one[1] = { {0} };
    assert(number(one, 1, 0, en, lv) == CBAE_OK && en[0] == 0 && lv[0] == 1);
    const kids_t chain[4] = { {1, {1}}, {1, {2}}, {1, {3}}, {0} };
    assert(number(chain, 4, 0, en, lv) == CBAE_OK);
    assert(en[0] == 0 && en[1] == 1 && en[2] == 2 && en[3] == 3 && lv[3] == 4 && lv[2] == 5 && lv[1] == 6 && lv[0] == 7);
    const kids_t rooted[3] = { {0}, {2, {2, 0}}, {0} };
    assert(number(rooted, 3, 1, en, lv) == CBAE_OK);
    assert(en[1] == 0 && en[2] == 1 && lv[2] == 2 && en[0] == 3 && lv[0] == 4 && lv[1] == 5);

    /* what is not a tree is refused */
    const kids_t far_child[2] = { {1, {7}}, {0} };                               /* node 7 does not exist (n = 2)     */
    assert(number(far_child, 2, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t at_n[2] = { {1, {2}}, {0} };
    assert(number(at_n, 2, 0, en, lv) == CBAE_ERR_INVALID);                      /* the first id past the end         */
    const kids_t at_max[2] = { {1, {UINT32_MAX}}, {0} };
    assert(number(at_max, 2, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t cycle[3] = { {1, {1}}, {1, {2}}, {1, {1}} };                    /* 0 -> 1 -> 2 -> 1                  */
    assert(number(cycle, 3, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t self_loop[2] = { {1, {1}}, {1, {1}} };
    assert(number(self_loop, 2, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t two_parents[4] = { {2, {1, 2}}, {1, {3}}, {1, {3}}, {0} };      /* 3 below both 1 and 2              */
    assert(number(two_parents, 4, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t two_parents_same[3] = { {2, {1, 1}}, {0}, {0} };                /* 1 listed twice, 2 not reached     */
    assert(number(two_parents_same, 3, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t not_reached[3] = { {1, {1}}, {0}, {0} };                        /* node 2 is nobody's child          */
    assert(number(not_reached, 3, 0, en, lv) == CBAE_ERR_INVALID);
    const kids_t back_to_root[2] = { {1, {1}}, {1, {0}} };                       /* the root as somebody's child      */
    assert(number(back_to_root, 2, 0, en, lv) == CBAE_ERR_INVALID);

    /* no nodes, a root that is not a node */
    cbae_vector_t c[1];
    build_children(c, one, 1);
    assert(dom_core_number_tree(0, 0, c, en, lv) == CBAE_ERR_INVALID);
    assert(dom_core_number_tree(1, 1, c, en, lv) == CBAE_ERR_INVALID);
    assert(dom_core_number_tree(1, UINT32_MAX, c, en, lv) == CBAE_ERR_INVALID);
    assert(dom_core_number_tree(DOM_MAX_NODES + 1u, 0, c, en, lv) == CBAE_ERR_OVERFLOW);   /* refused before anything is touched */
    free_children(c, 1);

    PASS("dom_core_number_tree numbers a tree exactly (times 0..2n-1), and refuses a child that does not exist, a node with two parents, "
         "a cycle, the root as a child, a node the root does not reach and no nodes, each with CBAE_ERR_INVALID");
}

/* ── The frontier shortcut ────────────────────────────────────────────── */

static void test_deep_chain_wide_join(void) {
    enum { K = 40 };                         /* the chain 0 -> 1 -> ... -> K, and every block but the last also leads to J = K + 1 */
    uint32_t edges[2 * K + 1][2];
    uint32_t m = 0;
    for (uint32_t i = 0; i < K; i++) { edges[m][0] = i; edges[m][1] = i + 1; m++; }
    for (uint32_t i = 0; i < K; i++) { edges[m][0] = i; edges[m][1] = K + 1; m++; }
    edges[m][0] = K; edges[m][1] = K + 1; m++;
    const uint32_t (*e)[2] = (const uint32_t (*)[2])edges;
    fn_t x;
    make_cfg(&x, "chain", K + 2, e, m);

    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);
    cbae_dom_tree_t dt;
    cbae_dom_frontier_t df;
    assert(cbae_dom_tree_build(x.f, &arena, &dt) == CBAE_OK);
    assert(cbae_dom_frontier_compute(&dt, &df) == CBAE_OK);

    /* J's immediate dominator is the entry (the entry leads to it directly); every other block of the chain dominates a
     * predecessor of J (itself) without strictly dominating J, so J is in the frontier of each of them. The entry
     * strictly dominates J, and J dominates nothing but itself. */
    const uint32_t join = K + 1;
    assert(cbae_dom_tree_idom(&dt, join) == 0);
    assert(cbae_vector_count(cbae_dom_frontier_of(&df, 0)) == 0);
    for (uint32_t i = 1; i <= K; i++) assert(set_is(cbae_dom_frontier_of(&df, i), &join, 1));
    assert(cbae_vector_count(cbae_dom_frontier_of(&df, join)) == 0);

    cbae_dom_frontier_destroy(&df);
    cbae_dom_tree_destroy(&dt);
    cbae_arena_destroy(&arena);
    fn_done(&x);
    PASS("a chain of 40 blocks that all lead to one join: the frontier of each is exactly {join}, of the entry and of the join empty");
}

int main(void) {
    printf("=== test_dominance_contracts ===\n");
    test_arguments();
    test_too_large();
    test_csr();
    test_empty_trees();
    test_block_ids_outside_the_tree();
    test_frontier_arguments();
    test_number_tree();
    test_deep_chain_wide_join();
    printf("All dominance contract tests passed.\n");
    return 0;
}
