/**
 * @file post_dominator_tree.h
 * @brief Post-dominator tree: ipdom queries and O(1) post_dominates()
 *        queries over a CIR function's CFG.
 *
 * Block A POST-DOMINATES block B when every path from B to the function's
 * exit passes through A. Equivalently: A dominates B in the REVERSED CFG
 * rooted at the exit. The computation therefore reuses the same
 * Cooper-Harvey-Kennedy core as the forward dominator tree
 * (src/dataflow/dom_core.c); see dominator_tree.h for the algorithm and
 * why it was chosen.
 *
 * THE VIRTUAL EXIT
 *   A function can have several exits (every `ret`; every block with no
 *   successors), but dominance needs a single root. The tree is rooted at
 *   a VIRTUAL EXIT node numbered `block_count` (one past the last real
 *   block). Every real exit block gets an edge to it. cbae_pdom_tree_ipdom()
 *   reports CBAE_PDOM_EXIT for a block whose immediate post-dominator is
 *   that virtual node, which is the normal answer for a block that can
 *   leave the function by more than one route.
 *
 * INFINITE LOOPS
 *   A block that cannot reach any exit (it ends in a loop with no way
 *   out) would otherwise have no post-dominator at all. So that every
 *   block gets a well-defined answer, the CFG is augmented before the
 *   computation: each "sink" strongly connected component -- an SCC that
 *   cannot reach any exit AND has no edge leaving it -- gets ONE synthetic
 *   edge to the virtual exit, from its member with the HIGHEST block id
 *   (the member created last, i.e. latest in discovery order, which in
 *   practice is the loop's back-edge source).
 *
 *   Why per-sink-SCC rather than per-block: a block in a non-sink part of
 *   an infinite region leaves it via an edge into a downstream sink, and
 *   should post-dominate through that sink. Linking only the sinks keeps
 *   that true; linking some arbitrary unreachable block would invent an
 *   exit route that does not exist.
 *
 *   The synthetic edge is a modelling convention, not a fact about the
 *   binary. It exists only inside this computation; the CIR function is
 *   never modified.
 */
#ifndef CBAE_POST_DOMINATOR_TREE_H
#define CBAE_POST_DOMINATOR_TREE_H

#include "cir/cir_function.h"
#include "cbae/cbae_error.h"
#include "platform/vector.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Returned by cbae_pdom_tree_ipdom() when the immediate post-dominator
 *  is the virtual exit rather than a real block. */
#define CBAE_PDOM_EXIT UINT32_MAX

typedef struct cbae_pdom_tree {
    const cbae_cir_function_t *func;    /* borrowed                          */
    uint32_t   block_count;             /* REAL blocks. Node `block_count`
                                         * is the virtual exit; the arrays
                                         * below have block_count+1 entries. */

    uint32_t  *ipdom;       /* [node] -> immediate post-dominator node
                              * (== block_count for the virtual exit; the
                              * virtual exit's own entry is itself)        */
    uint32_t  *rpo_order;   /* [rank] -> node, reverse postorder of the
                              * REVERSED CFG from the virtual exit         */
    uint32_t  *rpo_number;  /* [node] -> rank                              */

    cbae_vector_t *children; /* [node] -> cbae_vector_t of child node ids in
                               * the post-dominator tree (heap-backed)     */

    uint32_t  *dt_enter;     /* [node] -> DFS enter time on the tree        */
    uint32_t  *dt_exit;      /* [node] -> DFS exit time on the tree         */
} cbae_pdom_tree_t;

/** Build the post-dominator tree of `func`. Arrays are arena-allocated;
 * the `children` vectors are heap-backed and released by
 * cbae_pdom_tree_destroy(). Blocks unreachable from the function entry
 * are tolerated (post-dominance does not depend on the entry). */
cbae_err_t cbae_pdom_tree_build(const cbae_cir_function_t *func,
                                 cbae_arena_t *arena, cbae_pdom_tree_t *out);

void cbae_pdom_tree_destroy(cbae_pdom_tree_t *pt);

/** Immediate post-dominator of real block `block_id`: another real
 *  block's id, or CBAE_PDOM_EXIT. */
uint32_t cbae_pdom_tree_ipdom(const cbae_pdom_tree_t *pt, uint32_t block_id);

/** True if real block `a` post-dominates real block `b`, INCLUSIVE
 *  (every block post-dominates itself). */
bool cbae_pdom_tree_post_dominates(const cbae_pdom_tree_t *pt,
                                    uint32_t a, uint32_t b);

/** True if `a` strictly post-dominates `b` (post-dominates AND a != b). */
static inline bool cbae_pdom_tree_strictly_post_dominates(
        const cbae_pdom_tree_t *pt, uint32_t a, uint32_t b) {
    return a != b && cbae_pdom_tree_post_dominates(pt, a, b);
}

/** Blocks whose immediate post-dominator is real block `block_id`.
 *  Never NULL (an empty vector for a leaf). */
const cbae_vector_t *cbae_pdom_tree_children(const cbae_pdom_tree_t *pt,
                                              uint32_t block_id);

/** Blocks whose immediate post-dominator is the virtual exit -- the tree
 *  roots. Never NULL, never empty for a valid function. */
const cbae_vector_t *cbae_pdom_tree_exit_children(const cbae_pdom_tree_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_POST_DOMINATOR_TREE_H */
