/**
 * @file dom_core.c
 * @brief Cooper-Harvey-Kennedy immediate-dominator computation over an
 *        abstract rooted graph. See dom_core.h for why this is shared.
 *
 * FOUR STEPS:
 *   1. Iterative postorder DFS from the root (explicit stack, not
 *      recursion -- no stack-depth risk on unusually large functions),
 *      reversed into an RPO numbering.
 *   2. The CHK fixed-point loop: visit nodes in increasing RPO order and
 *      set idom[b] to the intersection of the already-known idoms of its
 *      predecessors. Every non-root node has at least one predecessor
 *      with a smaller RPO number (its DFS-tree parent), so on the very
 *      first pass each node already has a defined candidate; later
 *      passes only refine them. This holds for ANY graph reachable from
 *      the root, reducible or not -- irreducible graphs just need more
 *      passes.
 *   3. children[] lists from idom[].
 *   4. A second DFS over the dominator TREE assigns [enter,leave]
 *      intervals so dominates(a,b) becomes an O(1) containment check.
 */
#include "dom_core.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ── CSR construction ─────────────────────────────────────────────────── */

cbae_err_t dom_csr_build(uint32_t n, const uint32_t *from, const uint32_t *to,
                         uint32_t m, dom_csr_t *out) {
    memset(out, 0, sizeof(*out));
    if (n > DOM_MAX_NODES || m > 3u * DOM_MAX_NODES)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW,
            "dominator core: a graph of %u nodes and %u edges is larger than the %u nodes it takes", n, m, DOM_MAX_NODES);

    out->succ_off = calloc((size_t)n + 1, sizeof(uint32_t));
    out->pred_off = calloc((size_t)n + 1, sizeof(uint32_t));
    out->succ_adj = malloc(sizeof(uint32_t) * (m ? m : 1));
    out->pred_adj = malloc(sizeof(uint32_t) * (m ? m : 1));
    uint32_t *scur = malloc(sizeof(uint32_t) * (n ? n : 1));
    uint32_t *pcur = malloc(sizeof(uint32_t) * (n ? n : 1));
    if (!out->succ_off || !out->pred_off || !out->succ_adj || !out->pred_adj ||
        !scur || !pcur) {
        free(scur); free(pcur);
        dom_csr_free(out);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator core: CSR alloc failed");
    }

    for (uint32_t i = 0; i < m; i++) {
        if (from[i] >= n || to[i] >= n) {
            free(scur); free(pcur);
            dom_csr_free(out);
            CBAE_RETURN_ERR(CBAE_ERR_INVALID,
                "dominator core: edge %u->%u out of range (%u nodes)",
                from[i], to[i], n);
        }
        out->succ_off[from[i] + 1]++;
        out->pred_off[to[i] + 1]++;
    }
    for (uint32_t i = 0; i < n; i++) {
        out->succ_off[i + 1] += out->succ_off[i];
        out->pred_off[i + 1] += out->pred_off[i];
    }
    for (uint32_t i = 0; i < n; i++) {
        scur[i] = out->succ_off[i];
        pcur[i] = out->pred_off[i];
    }
    for (uint32_t i = 0; i < m; i++) {
        out->succ_adj[scur[from[i]]++] = to[i];
        out->pred_adj[pcur[to[i]]++]   = from[i];
    }

    free(scur);
    free(pcur);
    return CBAE_OK;
}

void dom_csr_free(dom_csr_t *c) {
    if (!c) return;
    free(c->succ_off); free(c->succ_adj);
    free(c->pred_off); free(c->pred_adj);
    memset(c, 0, sizeof(*c));
}

/* ── Step 1: postorder DFS -> RPO ─────────────────────────────────────── */

typedef struct { uint32_t node; uint32_t next_edge; } dfs_frame_t;

static cbae_err_t compute_rpo(const dom_graph_t *g, const char *what,
                              uint32_t *rpo_order, uint32_t *rpo_number) {
    const uint32_t n = g->n;
    bool        *visited   = calloc(n, sizeof(bool));
    dfs_frame_t *stack     = malloc(sizeof(dfs_frame_t) * n);
    uint32_t    *postorder = malloc(sizeof(uint32_t) * n);
    if (!visited || !stack || !postorder) {
        free(visited); free(stack); free(postorder);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "%s: DFS scratch alloc failed", what);
    }

    uint32_t pcount = 0;
    uint32_t sp = 0;
    stack[sp].node = g->root;
    stack[sp].next_edge = g->succ_off[g->root];
    visited[g->root] = true;
    sp++;

    while (sp > 0) {
        dfs_frame_t *top = &stack[sp - 1];
        if (top->next_edge < g->succ_off[top->node + 1]) {
            uint32_t succ = g->succ_adj[top->next_edge++];
            if (!visited[succ]) {
                visited[succ] = true;
                stack[sp].node = succ;
                stack[sp].next_edge = g->succ_off[succ];
                sp++;
            }
        } else {
            postorder[pcount++] = top->node;
            sp--;
        }
    }

    if (pcount != n) {
        free(visited); free(stack); free(postorder);
        CBAE_RETURN_ERR(CBAE_ERR_INVALID,
            "%s: %u of %u nodes unreachable from the root "
            "(the graph should be fully connected by construction)",
            what, n - pcount, n);
    }

    for (uint32_t i = 0; i < n; i++) {
        uint32_t node = postorder[n - 1 - i];
        rpo_order[i] = node;
        rpo_number[node] = i;
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

cbae_err_t dom_core_compute(const dom_graph_t *g, const char *what,
                            uint32_t *idom, uint32_t *rpo_order,
                            uint32_t *rpo_number) {
    const uint32_t n = g->n;
    if (g->root >= n)                       /* also when there are no nodes: no root is one of them */
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "%s: empty graph or bad root", what);

    CBAE_CHECK(compute_rpo(g, what, rpo_order, rpo_number));

    for (uint32_t i = 0; i < n; i++) idom[i] = UNDEFINED_IDOM;
    idom[g->root] = g->root;   /* the root is its own immediate dominator */

    bool changed = true;
    while (changed) {
        changed = false;
        for (uint32_t rank = 1; rank < n; rank++) {
            uint32_t b = rpo_order[rank];

            uint32_t new_idom = UNDEFINED_IDOM;
            for (uint32_t e = g->pred_off[b]; e < g->pred_off[b + 1]; e++) {
                uint32_t p = g->pred_adj[e];
                if (idom[p] == UNDEFINED_IDOM) continue;
                new_idom = (new_idom == UNDEFINED_IDOM)
                    ? p
                    : intersect(idom, rpo_number, new_idom, p);
            }

            if (idom[b] != new_idom) {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    return CBAE_OK;
}

/* ── Steps 3 + 4: dominator-tree children[], then interval numbering ──── */

cbae_err_t dom_core_build_children(uint32_t n, uint32_t root,
                                   const uint32_t *idom,
                                   cbae_vector_t *children) {
    for (uint32_t i = 0; i < n; i++) {
        cbae_err_t rc = cbae_vector_init(&children[i], sizeof(uint32_t), 2);
        if (rc != CBAE_OK) {
            for (uint32_t j = 0; j < i; j++) cbae_vector_destroy(&children[j]);
            return rc;
        }
    }

    for (uint32_t b = 0; b < n; b++) {
        if (b == root) continue;           /* the root has no parent */
        cbae_err_t rc = cbae_vector_push(&children[idom[b]], &b);
        if (rc != CBAE_OK) {
            for (uint32_t j = 0; j < n; j++) cbae_vector_destroy(&children[j]);
            return rc;
        }
    }
    return CBAE_OK;
}

#define UNNUMBERED UINT32_MAX     /* no time reaches it: a tree of at most DOM_MAX_NODES nodes uses times below 2^30 */

cbae_err_t dom_core_number_tree(uint32_t n, uint32_t root,
                                const cbae_vector_t *children,
                                uint32_t *enter, uint32_t *leave) {
    if (root >= n)                          /* also: no nodes at all, for then no root is one of them */
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dominator tree numbering: no nodes, or the root is not one of them");
    if (n > DOM_MAX_NODES)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "dominator tree numbering: %u nodes, more than the %u it takes", n, DOM_MAX_NODES);
    dfs_frame_t *stack = malloc(sizeof(dfs_frame_t) * n);
    if (!stack) CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator tree numbering: DFS stack alloc failed");

    /* `enter` doubles as the record of which nodes have been entered. A node entered twice is a node with two parents or
     * a cycle: refused, and that is what keeps the stack (n frames, one per node on the path) from overflowing and the
     * work from growing past one visit per node. A tree of n nodes uses the times 0 .. 2n-1, so if the walk ends on any
     * other count a node was never reached. */
    for (uint32_t i = 0; i < n; i++) enter[i] = UNNUMBERED;
    uint32_t timer = 0;
    uint32_t sp = 0;

    stack[sp].node = root;
    stack[sp].next_edge = 0;
    enter[root] = timer++;
    sp++;

    while (sp > 0) {
        dfs_frame_t *top = &stack[sp - 1];
        const cbae_vector_t *kids = &children[top->node];
        const uint32_t nkids = (uint32_t)cbae_vector_count(kids);

        if (top->next_edge < nkids) {
            const uint32_t child = *(const uint32_t *)cbae_vector_at(kids, top->next_edge);
            top->next_edge++;
            if (child >= n || enter[child] != UNNUMBERED) {
                free(stack);
                CBAE_RETURN_ERR(CBAE_ERR_INVALID,
                    "dominator tree numbering: the children of the nodes are not a tree (node %u is a child that does not exist, "
                    "or is reached twice)", child);
            }
            enter[child] = timer++;
            stack[sp].node = child;
            stack[sp].next_edge = 0;
            sp++;
        } else {
            leave[top->node] = timer++;
            sp--;
        }
    }
    free(stack);
    if (timer != 2u * n)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dominator tree numbering: the root reaches %u of the %u nodes", timer / 2u, n);
    return CBAE_OK;
}
