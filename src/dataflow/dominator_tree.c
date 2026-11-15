/**
 * @file dominator_tree.c
 * @brief Forward dominator tree of a CIR function, plus dominance
 *        frontier. The dominator computation itself is the shared
 *        Cooper-Harvey-Kennedy core in dom_core.c; this file adapts a
 *        CIR function's CFG to it and exposes the query API.
 */
#include "dataflow/dominator_tree.h"
#include "dom_core.h"
#include "cfg_graph.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

/* ── Public API ───────────────────────────────────────────────────────── */

/* What a query answers for a block that is not in the tree: no children, no frontier. All zero is an empty vector. */
static const cbae_vector_t NO_BLOCKS;

cbae_err_t cbae_dom_tree_build(const cbae_cir_function_t *func,
                                cbae_arena_t *arena, cbae_dom_tree_t *out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    memset(out, 0, sizeof(*out));
    if (!func || !arena) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    const size_t count = cbae_vector_count(&func->blocks);
    if (count == 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "function has no blocks");
    if (count > DOM_MAX_NODES)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "dominator tree: %zu blocks, more than the %u it takes", count, DOM_MAX_NODES);
    const uint32_t nblocks = (uint32_t)count;

    /* The tree is built in `t` and handed over whole: whatever step fails, *out stays empty. */
    cbae_dom_tree_t t;
    memset(&t, 0, sizeof(t));
    t.func        = func;
    t.block_count = nblocks;
    t.idom        = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    t.rpo_order   = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    t.rpo_number  = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    t.dt_enter    = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    t.dt_exit     = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    t.children    = CBAE_ARENA_ALLOC_N(arena, cbae_vector_t, nblocks);
    if (!t.idom || !t.rpo_order || !t.rpo_number || !t.dt_enter || !t.dt_exit || !t.children)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator tree: array alloc failed");

    /* The CFG as CSR adjacency. Entry is always block 0, per the id==index
     * invariant every CIR block creation upholds. */
    dom_csr_t csr;
    CBAE_CHECK(cfg_csr_build(func, &csr));

    const dom_graph_t g = { nblocks, 0, csr.succ_off, csr.succ_adj,
                            csr.pred_off, csr.pred_adj };
    cbae_err_t rc = dom_core_compute(&g, "dominator tree", t.idom, t.rpo_order, t.rpo_number);
    dom_csr_free(&csr);
    CBAE_CHECK(rc);

    CBAE_CHECK(dom_core_build_children(nblocks, 0, t.idom, t.children));
    rc = dom_core_number_tree(nblocks, 0, t.children, t.dt_enter, t.dt_exit);
    if (rc != CBAE_OK) {
        for (uint32_t i = 0; i < nblocks; i++) cbae_vector_destroy(&t.children[i]);
        return rc;
    }

    *out = t;
    LOG_DEBUG("dominator tree built: %u blocks", nblocks);
    return CBAE_OK;
}

void cbae_dom_tree_destroy(cbae_dom_tree_t *dt) {
    if (!dt || dt->block_count == 0) return;                /* nothing to release in an empty tree */
    for (uint32_t i = 0; i < dt->block_count; i++)
        cbae_vector_destroy(&dt->children[i]);
}

uint32_t cbae_dom_tree_idom(const cbae_dom_tree_t *dt, uint32_t block_id) {
    if (!dt || block_id >= dt->block_count) return CBAE_DOM_NONE;
    return dt->idom[block_id];
}

bool cbae_dom_tree_dominates(const cbae_dom_tree_t *dt, uint32_t a, uint32_t b) {
    if (!dt || a >= dt->block_count || b >= dt->block_count) return false;
    return dt->dt_enter[a] <= dt->dt_enter[b] && dt->dt_exit[b] <= dt->dt_exit[a];
}

const cbae_vector_t *cbae_dom_tree_children(const cbae_dom_tree_t *dt,
                                             uint32_t block_id) {
    if (!dt || block_id >= dt->block_count) return &NO_BLOCKS;
    return &dt->children[block_id];
}

/* ── Dominance frontier (Cytron et al.) ───────────────────────────────── */

/* Destroys the n sets (an all-zero one is an already destroyed one) and the array that holds them. */
static void frontier_free(cbae_vector_t *sets, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) cbae_vector_destroy(&sets[i]);
    free(sets);
}

cbae_err_t cbae_dom_frontier_compute(const cbae_dom_tree_t *dt,
                                      cbae_dom_frontier_t *out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    memset(out, 0, sizeof(*out));
    if (!dt || dt->block_count == 0)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dominance frontier: the dominator tree is empty");
    const uint32_t n = dt->block_count;
    if (cbae_vector_count(&dt->func->blocks) != n)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dominance frontier: the tree was built for %u blocks, the function has %zu now",
                        n, cbae_vector_count(&dt->func->blocks));

    /* frontier[] is heap-allocated (not arena) -- cbae_dom_tree_t
     * doesn't retain an arena reference beyond build time, and this
     * function only receives the tree, not an arena, to allocate from.
     * calloc: until a set is initialised it is the all-zero (destroyed) vector. */
    cbae_vector_t *sets = calloc(n, sizeof(*sets));
    if (!sets) CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominance frontier alloc failed");
    for (uint32_t i = 0; i < n; i++) {
        const cbae_err_t rc = cbae_vector_init(&sets[i], sizeof(uint32_t), 2);
        if (rc != CBAE_OK) { frontier_free(sets, n); return rc; }
    }

    for (uint32_t b = 0; b < n; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&dt->func->blocks, b);
        const uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);

        /* Only join points can be in a DF -- two or more incoming edges.
         * The ENTRY block is the one exception: the function's own entry
         * is an implicit extra incoming edge, so entry is a join as soon
         * as ANY block jumps back to it (a function whose first block is
         * a loop header). */
        if (npred < (b == 0 ? 1u : 2u)) continue;

        for (uint32_t pi = 0; pi < npred; pi++) {
            uint32_t runner = *(const uint32_t *)cbae_vector_at(&blk->predecessors, pi);
            for (;;) {
                /* idom(b) strictly dominates b, so b is not in ITS
                 * frontier: stop before it. The entry has no such
                 * block, and is not strictly dominated by anything, so
                 * for b == 0 the walk continues through entry itself. */
                if (b != 0 && runner == dt->idom[b]) break;

                /* The blocks are taken in increasing order, so a set holds the blocks before b and, once an earlier walk
                 * for b has passed through its owner, b as its LAST member. That walk went on from there up to idom(b),
                 * and this one would only repeat it: stop. (This is what makes the whole computation linear in the
                 * edges and the size of the result, instead of walking the dominator chain again for every edge.) */
                cbae_vector_t *set = &sets[runner];
                const size_t have = cbae_vector_count(set);
                if (have > 0 && *(const uint32_t *)cbae_vector_at(set, have - 1) == b) break;

                const cbae_err_t rc = cbae_vector_push(set, &b);
                if (rc != CBAE_OK) { frontier_free(sets, n); return rc; }
                if (runner == 0) break;          /* nothing above the root */
                runner = dt->idom[runner];
            }
        }
    }

    out->block_count = n;
    out->frontier    = sets;
    return CBAE_OK;
}

void cbae_dom_frontier_destroy(cbae_dom_frontier_t *df) {
    if (!df || df->block_count == 0) return;                /* nothing to release in an empty frontier */
    frontier_free(df->frontier, df->block_count);
    memset(df, 0, sizeof(*df));
}

const cbae_vector_t *cbae_dom_frontier_of(const cbae_dom_frontier_t *df,
                                           uint32_t block_id) {
    if (!df || block_id >= df->block_count) return &NO_BLOCKS;
    return &df->frontier[block_id];
}
