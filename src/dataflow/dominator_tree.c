/**
 * @file dominator_tree.c
 * @brief Cooper-Harvey-Kennedy dominator tree construction.
 *
 * FOUR STEPS:
 *   1. Iterative postorder DFS over the CFG (explicit stack, not
 *      recursion -- avoids any stack-depth risk on unusually large
 *      functions), reversed into an RPO numbering.
 *   2. The CHK fixed-point loop itself: for each block in increasing
 *      RPO order, intersect the already-known idoms of its
 *      predecessors. Terminates because every non-entry block in a
 *      REDUCIBLE cfg (true for all compiler-generated code -- no
 *      goto-spaghetti irreducible loops) has at least one predecessor
 *      with strictly smaller RPO number, guaranteeing that predecessor
 *      is already resolved on the very first pass.
 *   3. Build dominator-tree children[] lists directly from idom[].
 *   4. A second DFS -- this time over the DOMINATOR TREE, not the CFG
 *      -- assigns [enter,exit] intervals so dominates(a,b) becomes an
 *      O(1) interval-containment check afterward.
 */
#include "dataflow/dominator_tree.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

/* ── Step 1: postorder DFS -> RPO ─────────────────────────────────────── */

typedef struct { uint32_t block_id; uint32_t next_child; } dfs_frame_t;

static cbae_err_t compute_rpo(const cbae_cir_function_t *func, uint32_t nblocks,
                               uint32_t *rpo_order, uint32_t *rpo_number) {
    bool *visited = calloc(nblocks, sizeof(bool));
    dfs_frame_t *stack = malloc(sizeof(dfs_frame_t) * nblocks);
    uint32_t *postorder = malloc(sizeof(uint32_t) * nblocks);
    if (!visited || !stack || !postorder) {
        free(visited); free(stack); free(postorder);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator tree: DFS scratch alloc failed");
    }

    uint32_t pcount = 0;
    int sp = 0;
    stack[sp].block_id = 0; /* entry is always block 0, per the id==index
                              * invariant every CIR block creation upholds */
    stack[sp].next_child = 0;
    visited[0] = true;
    sp++;

    while (sp > 0) {
        dfs_frame_t *top = &stack[sp - 1];
        cbae_cir_block_t **bp =
            cbae_vector_at(&func->blocks, top->block_id);
        cbae_cir_block_t *blk = *bp;

        if (top->next_child < blk->successor_count) {
            uint32_t succ_id = blk->successors[top->next_child];
            top->next_child++;
            if (!visited[succ_id]) {
                visited[succ_id] = true;
                stack[sp].block_id = succ_id;
                stack[sp].next_child = 0;
                sp++;
            }
        } else {
            postorder[pcount++] = top->block_id;
            sp--;
        }
    }

    /* Every block Phase 3/4 create is reachable from entry by
     * construction (recursive-descent CFG building) -- a mismatch
     * here means an invariant elsewhere was violated, not a normal
     * runtime condition. */
    if (pcount != nblocks) {
        free(visited); free(stack); free(postorder);
        CBAE_RETURN_ERR(CBAE_ERR_INVALID,
            "dominator tree: %u of %u blocks unreachable from entry "
            "(function's CFG should be fully connected by construction)",
            nblocks - pcount, nblocks);
    }

    /* RPO is simply postorder reversed. */
    for (uint32_t i = 0; i < nblocks; i++) {
        uint32_t block_id = postorder[nblocks - 1 - i];
        rpo_order[i] = block_id;
        rpo_number[block_id] = i;
    }

    free(visited);
    free(stack);
    free(postorder);
    return CBAE_OK;
}

/* ── Step 2: the CHK fixed-point loop ─────────────────────────────────── */

static uint32_t intersect(const uint32_t *idom, const uint32_t *rpo_number,
                           uint32_t b1, uint32_t b2) {
    uint32_t f1 = b1, f2 = b2;
    while (f1 != f2) {
        while (rpo_number[f1] > rpo_number[f2]) f1 = idom[f1];
        while (rpo_number[f2] > rpo_number[f1]) f2 = idom[f2];
    }
    return f1;
}

#define UNDEFINED_IDOM UINT32_MAX

static void compute_idom(const cbae_cir_function_t *func, uint32_t nblocks,
                          const uint32_t *rpo_order, const uint32_t *rpo_number,
                          uint32_t *idom) {
    for (uint32_t i = 0; i < nblocks; i++) idom[i] = UNDEFINED_IDOM;
    idom[0] = 0; /* entry is its own immediate dominator, by convention */

    bool changed = true;
    while (changed) {
        changed = false;
        for (uint32_t rank = 1; rank < nblocks; rank++) {
            uint32_t b = rpo_order[rank];
            cbae_cir_block_t **bp = cbae_vector_at(&func->blocks, b);
            cbae_cir_block_t *blk = *bp;
            uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);

            uint32_t new_idom = UNDEFINED_IDOM;
            for (uint32_t pi = 0; pi < npred; pi++) {
                uint32_t *pred_id = cbae_vector_at(&blk->predecessors, pi);
                if (idom[*pred_id] == UNDEFINED_IDOM) continue;
                new_idom = (new_idom == UNDEFINED_IDOM)
                    ? *pred_id
                    : intersect(idom, rpo_number, new_idom, *pred_id);
            }

            if (idom[b] != new_idom) {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
}

/* ── Step 3 + 4: dominator-tree children[], then interval numbering ────── */

static cbae_err_t build_children(uint32_t nblocks, const uint32_t *idom,
                                  cbae_vector_t *children) {
    for (uint32_t i = 0; i < nblocks; i++)
        CBAE_CHECK(cbae_vector_init(&children[i], sizeof(uint32_t), 2));

    for (uint32_t b = 1; b < nblocks; b++) /* entry (0) has no parent */
        CBAE_CHECK(cbae_vector_push(&children[idom[b]], &b));

    return CBAE_OK;
}

static void number_dom_tree(uint32_t nblocks, const cbae_vector_t *children,
                             uint32_t *dt_enter, uint32_t *dt_exit) {
    dfs_frame_t *stack = malloc(sizeof(dfs_frame_t) * nblocks);
    uint32_t timer = 0;
    int sp = 0;

    stack[sp].block_id = 0;
    stack[sp].next_child = 0;
    dt_enter[0] = timer++;
    sp++;

    while (sp > 0) {
        dfs_frame_t *top = &stack[sp - 1];
        const cbae_vector_t *kids = &children[top->block_id];
        uint32_t nkids = (uint32_t)cbae_vector_count(kids);

        if (top->next_child < nkids) {
            uint32_t *child_id = cbae_vector_at(kids, top->next_child);
            top->next_child++;
            dt_enter[*child_id] = timer++;
            stack[sp].block_id = *child_id;
            stack[sp].next_child = 0;
            sp++;
        } else {
            dt_exit[top->block_id] = timer++;
            sp--;
        }
    }
    free(stack);
}

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

    CBAE_CHECK(compute_rpo(func, nblocks, out->rpo_order, out->rpo_number));
    compute_idom(func, nblocks, out->rpo_order, out->rpo_number, out->idom);
    CBAE_CHECK(build_children(nblocks, out->idom, out->children));
    number_dom_tree(nblocks, out->children, out->dt_enter, out->dt_exit);

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
        if (npred < 2) continue; /* only join points can be in a DF */

        for (uint32_t pi = 0; pi < npred; pi++) {
            uint32_t *pred_id = cbae_vector_at(&blk->predecessors, pi);
            uint32_t runner = *pred_id;
            while (runner != dt->idom[b]) {
                if (!vector_contains_u32(&out->frontier[runner], b))
                    cbae_vector_push(&out->frontier[runner], &b);
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
