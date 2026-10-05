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

cbae_err_t cbae_dom_tree_build(const cbae_cir_function_t *func,
                                cbae_arena_t *arena, cbae_dom_tree_t *out) {
    if (!func || !arena || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    memset(out, 0, sizeof(*out));
    out->func = func;
    uint32_t nblocks = (uint32_t)cbae_vector_count(&func->blocks);
    out->block_count = nblocks;
    if (nblocks == 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "function has no blocks");

    out->idom       = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    out->rpo_order   = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    out->rpo_number   = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    out->dt_enter      = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    out->dt_exit         = CBAE_ARENA_ALLOC_N(arena, uint32_t, nblocks);
    out->children          = CBAE_ARENA_ALLOC_N(arena, cbae_vector_t, nblocks);
    if (!out->idom || !out->rpo_order || !out->rpo_number ||
        !out->dt_enter || !out->dt_exit || !out->children)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator tree: array alloc failed");

    /* The CFG as CSR adjacency. Entry is always block 0, per the id==index
     * invariant every CIR block creation upholds. */
    dom_csr_t csr;
    CBAE_CHECK(cfg_csr_build(func, &csr));

    dom_graph_t g = { nblocks, 0, csr.succ_off, csr.succ_adj,
                      csr.pred_off, csr.pred_adj };
    cbae_err_t rc = dom_core_compute(&g, "dominator tree",
                          out->idom, out->rpo_order, out->rpo_number);
    dom_csr_free(&csr);
    CBAE_CHECK(rc);

    CBAE_CHECK(dom_core_build_children(nblocks, 0, out->idom, out->children));
    dom_core_number_tree(nblocks, 0, out->children, out->dt_enter, out->dt_exit);

    LOG_DEBUG("dominator tree built: %u blocks", nblocks);
    return CBAE_OK;
}

void cbae_dom_tree_destroy(cbae_dom_tree_t *dt) {
    if (!dt || !dt->children) return;
    for (uint32_t i = 0; i < dt->block_count; i++)
        cbae_vector_destroy(&dt->children[i]);
}

uint32_t cbae_dom_tree_idom(const cbae_dom_tree_t *dt, uint32_t block_id) {
    return dt->idom[block_id];
}

bool cbae_dom_tree_dominates(const cbae_dom_tree_t *dt, uint32_t a, uint32_t b) {
    return dt->dt_enter[a] <= dt->dt_enter[b] && dt->dt_exit[b] <= dt->dt_exit[a];
}

const cbae_vector_t *cbae_dom_tree_children(const cbae_dom_tree_t *dt,
                                             uint32_t block_id) {
    return &dt->children[block_id];
}

/* ── Dominance frontier (Cytron et al.) ───────────────────────────────── */

static bool vector_contains_u32(const cbae_vector_t *v, uint32_t val) {
    uint32_t n = (uint32_t)cbae_vector_count(v);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t *e = cbae_vector_at(v, i);
        if (*e == val) return true;
    }
    return false;
}

cbae_err_t cbae_dom_frontier_compute(const cbae_dom_tree_t *dt,
                                      cbae_dom_frontier_t *out) {
    if (!dt || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    memset(out, 0, sizeof(*out));
    out->block_count = dt->block_count;

    /* frontier[] is heap-allocated (not arena) -- cbae_dom_tree_t
     * doesn't retain an arena reference beyond build time, and this
     * function only receives the tree, not an arena, to allocate from. */
    out->frontier = malloc(sizeof(cbae_vector_t) * dt->block_count);
    if (!out->frontier) CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominance frontier alloc failed");

    for (uint32_t i = 0; i < dt->block_count; i++)
        cbae_vector_init(&out->frontier[i], sizeof(uint32_t), 2);

    for (uint32_t b = 0; b < dt->block_count; b++) {
        cbae_cir_block_t **bp = cbae_vector_at(&dt->func->blocks, b);
        cbae_cir_block_t *blk = *bp;
        uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);

        /* Only join points can be in a DF -- two or more incoming edges.
         * The ENTRY block is the one exception: the function's own entry
         * is an implicit extra incoming edge, so entry is a join as soon
         * as ANY block jumps back to it (a function whose first block is
         * a loop header). */
        if (npred < (b == 0 ? 1u : 2u)) continue;

        for (uint32_t pi = 0; pi < npred; pi++) {
            uint32_t *pred_id = cbae_vector_at(&blk->predecessors, pi);
            uint32_t runner = *pred_id;
            for (;;) {
                /* idom(b) strictly dominates b, so b is not in ITS
                 * frontier: stop before it. The entry has no such
                 * block, and is not strictly dominated by anything, so
                 * for b == 0 the walk continues through entry itself. */
                if (b != 0 && runner == dt->idom[b]) break;
                if (!vector_contains_u32(&out->frontier[runner], b))
                    cbae_vector_push(&out->frontier[runner], &b);
                if (runner == 0) break;          /* nothing above the root */
                runner = dt->idom[runner];
            }
        }
    }
    return CBAE_OK;
}

void cbae_dom_frontier_destroy(cbae_dom_frontier_t *df) {
    if (!df || !df->frontier) return;
    for (uint32_t i = 0; i < df->block_count; i++)
        cbae_vector_destroy(&df->frontier[i]);
    free(df->frontier);
    df->frontier = NULL;
}

const cbae_vector_t *cbae_dom_frontier_of(const cbae_dom_frontier_t *df,
                                           uint32_t block_id) {
    return &df->frontier[block_id];
}
