/**
 * @file dom_core.h  (INTERNAL -- not part of the public include/ tree)
 * @brief The one Cooper-Harvey-Kennedy dominator implementation, shared
 *        by the forward dominator tree and the post-dominator tree.
 *
 * Post-dominance IS dominance on the reversed CFG rooted at a virtual
 * exit node, so both trees reduce to the same problem: "given a
 * directed graph and a root, compute immediate dominators". Keeping a
 * single implementation of the subtle part (RPO numbering plus the
 * intersect() fixed point) means a bug can only live in one place, and
 * the cross-check against a brute-force reference in the tests covers
 * both trees at once.
 *
 * Graphs are passed as an immutable CSR (compressed sparse row) view:
 * for node x, its successors are succ_adj[succ_off[x] .. succ_off[x+1])
 * and its predecessors pred_adj[pred_off[x] .. pred_off[x+1]).
 */
#ifndef CBAE_DOM_CORE_H
#define CBAE_DOM_CORE_H

#include "cbae/cbae_error.h"
#include "platform/vector.h"
#include <stdint.h>

typedef struct dom_graph {
    uint32_t        n;          /* nodes are 0..n-1                        */
    uint32_t        root;       /* the entry the dominance is relative to  */
    const uint32_t *succ_off;   /* n+1 entries                             */
    const uint32_t *succ_adj;
    const uint32_t *pred_off;   /* n+1 entries                             */
    const uint32_t *pred_adj;
} dom_graph_t;

/** Heap-owned CSR arrays built from an edge list. */
typedef struct dom_csr {
    uint32_t *succ_off, *succ_adj;
    uint32_t *pred_off, *pred_adj;
} dom_csr_t;

/** Build both adjacency directions for an n-node graph from m edges
 *  (from[i] -> to[i]). Every endpoint must be < n, else CBAE_ERR_INVALID.
 *  Release with dom_csr_free(). */
cbae_err_t dom_csr_build(uint32_t n, const uint32_t *from, const uint32_t *to,
                         uint32_t m, dom_csr_t *out);
void       dom_csr_free (dom_csr_t *c);

/** Compute reverse-postorder numbering and immediate dominators of every
 *  node relative to g->root. All three output arrays have g->n entries
 *  and are caller-provided. idom[root] == root.
 *
 *  Returns CBAE_ERR_INVALID if some node is unreachable from the root,
 *  because an unreachable node has no dominator. `what` names the
 *  calling analysis in that message. */
cbae_err_t dom_core_compute(const dom_graph_t *g, const char *what,
                            uint32_t *idom, uint32_t *rpo_order,
                            uint32_t *rpo_number);

/** children[x] = nodes whose idom is x (root excluded). The n vectors
 *  are heap-backed (uint32_t elements); the caller destroys them. */
cbae_err_t dom_core_build_children(uint32_t n, uint32_t root,
                                   const uint32_t *idom,
                                   cbae_vector_t *children);

/** DFS over the dominator TREE assigning [enter, leave] intervals so that
 *  "a dominates b" is enter[a] <= enter[b] && leave[b] <= leave[a]. */
void dom_core_number_tree(uint32_t n, uint32_t root,
                          const cbae_vector_t *children,
                          uint32_t *enter, uint32_t *leave);

#endif /* CBAE_DOM_CORE_H */
