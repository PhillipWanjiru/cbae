/**
 * @file post_dominator_tree.c
 * @brief Post-dominator tree = dominator tree of the reversed CFG rooted
 *        at a virtual exit node, computed by the shared CHK core.
 *
 * STEPS
 *   1. Collect the CFG as an edge list; build forward adjacency.
 *   2. Real exits are blocks with no successors. Mark every block that
 *      can reach one (reverse DFS).
 *   3. Blocks that cannot reach an exit lie in infinite regions. Find the
 *      SINK strongly connected components among them (graph_scc.c) and
 *      link one member of each to the virtual exit, so every block has a
 *      path to it. See post_dominator_tree.h for the reasoning.
 *   4. Reverse every edge, add virtual-exit -> exit-block edges, and hand
 *      the result to dom_core_compute() with the virtual exit as root.
 *
 * All intermediate arrays are heap scratch freed before returning; only
 * the result arrays (arena) and children vectors (heap) outlive the call.
 */
#include "dataflow/post_dominator_tree.h"
#include "dom_core.h"
#include "graph_scc.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

/* ── Step 2: which blocks can reach an exit ───────────────────────────── */

static cbae_err_t mark_reaching_exit(uint32_t n, const dom_csr_t *fwd,
                                     const bool *to_vexit, bool *reaches) {
    uint32_t *stack = malloc(sizeof(uint32_t) * n);
    if (!stack) CBAE_RETURN_ERR(CBAE_ERR_OOM, "post-dominator tree: scratch alloc failed");

    uint32_t sp = 0;
    for (uint32_t b = 0; b < n; b++) {
        if (to_vexit[b]) { reaches[b] = true; stack[sp++] = b; }
    }
    while (sp > 0) {
        uint32_t v = stack[--sp];
        for (uint32_t e = fwd->pred_off[v]; e < fwd->pred_off[v + 1]; e++) {
            uint32_t p = fwd->pred_adj[e];
            if (!reaches[p]) {
                reaches[p] = true;
                stack[sp++] = p;       /* each node is pushed at most once */
            }
        }
    }
    free(stack);
    return CBAE_OK;
}

/* ── Step 3: sink SCCs of the part of the CFG that cannot exit ───────────
 *
 * The strongly connected components (graph_scc.c) of the blocks with
 * reaches[b] == false. That set is closed under successors -- a block with
 * a successor that reaches an exit would itself reach an exit -- so no edge
 * leaves it. A component is a SINK when no edge leads from it to a
 * different component. For every sink, link its highest-numbered block to
 * the virtual exit by setting link_to_exit[rep] = true. */

static cbae_err_t link_sink_sccs(uint32_t n, const dom_csr_t *fwd,
                                 const bool *reaches, bool *link_to_exit) {
    bool     *active = malloc(sizeof(bool) * n);
    uint32_t *comp   = malloc(sizeof(uint32_t) * n);
    if (!active || !comp) {
        free(active); free(comp);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "post-dominator tree: SCC scratch alloc failed");
    }
    for (uint32_t b = 0; b < n; b++) active[b] = !reaches[b];

    uint32_t ncomp = 0;
    cbae_err_t rc = graph_scc_compute(n, fwd->succ_off, fwd->succ_adj, active,
                                      comp, &ncomp);
    if (rc != CBAE_OK) { free(active); free(comp); return rc; }

    uint32_t *rep     = calloc(ncomp ? ncomp : 1, sizeof(uint32_t));  /* highest id per comp */
    bool     *has_out = calloc(ncomp ? ncomp : 1, sizeof(bool));
    if (!rep || !has_out) {
        free(active); free(comp); free(rep); free(has_out);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "post-dominator tree: SCC scratch alloc failed");
    }

    for (uint32_t u = 0; u < n; u++) {
        if (!active[u]) continue;
        if (u > rep[comp[u]]) rep[comp[u]] = u;
        for (uint32_t e = fwd->succ_off[u]; e < fwd->succ_off[u + 1]; e++) {
            const uint32_t w = fwd->succ_adj[e];
            if (active[w] && comp[w] != comp[u]) has_out[comp[u]] = true;
        }
    }
    for (uint32_t c = 0; c < ncomp; c++) {
        if (!has_out[c]) link_to_exit[rep[c]] = true;
    }

    free(active); free(comp); free(rep); free(has_out);
    return CBAE_OK;
}

/* ── Public API ───────────────────────────────────────────────────────── */

cbae_err_t cbae_pdom_tree_build(const cbae_cir_function_t *func,
                                 cbae_arena_t *arena, cbae_pdom_tree_t *out) {
    if (!func || !arena || !out)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "post-dominator tree: null argument");

    memset(out, 0, sizeof(*out));
    out->func = func;
    const uint32_t n = (uint32_t)cbae_vector_count(&func->blocks);
    if (n == 0)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "post-dominator tree: function has no blocks");
    const uint32_t total = n + 1;          /* real blocks + the virtual exit */
    const uint32_t vexit = n;
    out->block_count = n;

    out->ipdom      = CBAE_ARENA_ALLOC_N(arena, uint32_t, total);
    out->rpo_order  = CBAE_ARENA_ALLOC_N(arena, uint32_t, total);
    out->rpo_number = CBAE_ARENA_ALLOC_N(arena, uint32_t, total);
    out->dt_enter   = CBAE_ARENA_ALLOC_N(arena, uint32_t, total);
    out->dt_exit    = CBAE_ARENA_ALLOC_N(arena, uint32_t, total);
    out->children   = CBAE_ARENA_ALLOC_N(arena, cbae_vector_t, total);
    if (!out->ipdom || !out->rpo_order || !out->rpo_number ||
        !out->dt_enter || !out->dt_exit || !out->children)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "post-dominator tree: array alloc failed");

    /* Step 1: the REVERSED CFG as an edge list. CFG edge u->w becomes
     * (rf=w) -> (rt=u). Capacity leaves room for one virtual-exit edge
     * per block. */
    uint32_t ncfg = 0;
    for (uint32_t b = 0; b < n; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&func->blocks, b);
        ncfg += blk->successor_count;
    }
    uint32_t *rf = malloc(sizeof(uint32_t) * (ncfg + n));
    uint32_t *rt = malloc(sizeof(uint32_t) * (ncfg + n));
    bool *to_vexit  = calloc(n, sizeof(bool));
    bool *reaches  = calloc(n, sizeof(bool));
    if (!rf || !rt || !to_vexit || !reaches) {
        free(rf); free(rt); free(to_vexit); free(reaches);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "post-dominator tree: scratch alloc failed");
    }

    uint32_t ei = 0;
    for (uint32_t b = 0; b < n; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&func->blocks, b);
        for (uint32_t k = 0; k < blk->successor_count; k++) {
            rf[ei] = blk->successors[k];
            rt[ei] = b;
            ei++;
        }
        if (blk->successor_count == 0) to_vexit[b] = true;
    }

    /* Forward adjacency (CFG direction) = the reversed list read backwards. */
    dom_csr_t fwd;
    cbae_err_t rc = dom_csr_build(n, rt, rf, ncfg, &fwd);
    if (rc != CBAE_OK) {
        free(rf); free(rt); free(to_vexit); free(reaches);
        return rc;
    }

    /* Steps 2 + 3: real exits, then synthetic links for infinite regions. */
    rc = mark_reaching_exit(n, &fwd, to_vexit, reaches);
    if (rc == CBAE_OK) {
        bool all_reach = true;
        for (uint32_t b = 0; b < n; b++) if (!reaches[b]) { all_reach = false; break; }
        if (!all_reach) rc = link_sink_sccs(n, &fwd, reaches, to_vexit);
    }
    dom_csr_free(&fwd);
    if (rc != CBAE_OK) {
        free(rf); free(rt); free(to_vexit); free(reaches);
        return rc;
    }

    /* Step 4: virtual exit -> every real or synthetic exit block. */
    for (uint32_t b = 0; b < n; b++) {
        if (to_vexit[b]) { rf[ei] = vexit; rt[ei] = b; ei++; }
    }

    dom_csr_t rev;
    rc = dom_csr_build(total, rf, rt, ei, &rev);
    free(rf); free(rt); free(to_vexit); free(reaches);
    CBAE_CHECK(rc);

    dom_graph_t g = { total, vexit, rev.succ_off, rev.succ_adj,
                      rev.pred_off, rev.pred_adj };
    rc = dom_core_compute(&g, "post-dominator tree",
                          out->ipdom, out->rpo_order, out->rpo_number);
    dom_csr_free(&rev);
    CBAE_CHECK(rc);

    CBAE_CHECK(dom_core_build_children(total, vexit, out->ipdom, out->children));
    dom_core_number_tree(total, vexit, out->children, out->dt_enter, out->dt_exit);

    LOG_DEBUG("post-dominator tree built: %u blocks + virtual exit", n);
    return CBAE_OK;
}

void cbae_pdom_tree_destroy(cbae_pdom_tree_t *pt) {
    if (!pt || !pt->children) return;
    for (uint32_t i = 0; i <= pt->block_count; i++)
        cbae_vector_destroy(&pt->children[i]);
}

uint32_t cbae_pdom_tree_ipdom(const cbae_pdom_tree_t *pt, uint32_t block_id) {
    uint32_t p = pt->ipdom[block_id];
    return p == pt->block_count ? CBAE_PDOM_EXIT : p;
}

bool cbae_pdom_tree_post_dominates(const cbae_pdom_tree_t *pt,
                                    uint32_t a, uint32_t b) {
    return pt->dt_enter[a] <= pt->dt_enter[b] && pt->dt_exit[b] <= pt->dt_exit[a];
}

const cbae_vector_t *cbae_pdom_tree_children(const cbae_pdom_tree_t *pt,
                                              uint32_t block_id) {
    return &pt->children[block_id];
}

const cbae_vector_t *cbae_pdom_tree_exit_children(const cbae_pdom_tree_t *pt) {
    return &pt->children[pt->block_count];
}
