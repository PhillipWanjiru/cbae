/**
 * @file dominator_tree.h
 * @brief General-purpose dominator tree: idom queries, O(1) dominates()
 *        queries, tree children iteration, dominance frontier.
 *
 * ALGORITHM: Cooper, Harvey, Kennedy, "A Simple, Fast Dominance
 * Algorithm" (2001) -- an iterative fixed-point computation over a
 * reverse-postorder block numbering, using an intersect() operation
 * that walks two immediate-dominator chains toward their common
 * ancestor. O(n^2) worst case, but CBAE analyses one FUNCTION's CFG at
 * a time (rarely more than a few hundred blocks), where that bound is
 * irrelevant in practice and the alternative -- Lengauer-Tarjan's
 * O(n a(n)) link-eval virtual forest with path compression -- is one
 * of the most commonly miscoded algorithms in compiler literature.
 * Simpler and provably correct beats optimal and risky at this scale;
 * see docs/architecture/PHASE5.md for the full reasoning.
 *
 * O(1) dominates(a,b) QUERIES: after building the tree, a DFS over the
 * dominator tree itself (not the CFG) assigns each block an
 * [enter,exit] interval. "a dominates b" iff a's interval CONTAINS b's
 * interval -- the standard technique, avoiding an O(depth) idom-chain
 * walk (and the off-by-one risk of hand-rolling that check) per query.
 */
#ifndef CBAE_DOMINATOR_TREE_H
#define CBAE_DOMINATOR_TREE_H

#include "cir/cir_function.h"
#include "cbae/cbae_error.h"
#include "platform/vector.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Returned by cbae_dom_tree_idom() for a block id that is not in the tree. */
#define CBAE_DOM_NONE UINT32_MAX

typedef struct cbae_dom_tree {
    const cbae_cir_function_t *func;   /* borrowed                          */
    uint32_t   block_count;

    uint32_t  *idom;         /* [block_id] -> immediate dominator's id
                               * (entry's own id for entry itself)          */
    uint32_t  *rpo_order;    /* [rank] -> block_id, reverse postorder       */
    uint32_t  *rpo_number;   /* [block_id] -> rank (inverse of rpo_order)   */

    cbae_vector_t *children; /* [block_id] -> cbae_vector_t of child ids in
                               * the dominator tree (heap-backed vectors)   */

    uint32_t  *dt_enter;     /* [block_id] -> DFS enter time in the
                               * DOMINATOR TREE (not the CFG)               */
    uint32_t  *dt_exit;      /* [block_id] -> DFS exit time, dominator tree */
} cbae_dom_tree_t;

/** Build the dominator tree for `func`. Arrays are arena-allocated;
 * the `children` vectors are heap-backed and must be released via
 * cbae_dom_tree_destroy().
 *
 * Errors: CBAE_ERR_INVALID for a NULL argument, a function with no blocks, or a block the entry cannot reach (it has no
 * dominator); CBAE_ERR_OVERFLOW for more blocks than the code takes (about 536 million); CBAE_ERR_OOM when the heap or
 * the arena is out of memory. On ANY error `*out` is all zero (when `out` is not NULL): an empty tree that
 * cbae_dom_tree_destroy() accepts and every query below answers "no such block" for. Memory taken from the arena before
 * the error stays in it, like any arena allocation. */
cbae_err_t cbae_dom_tree_build(const cbae_cir_function_t *func,
                                cbae_arena_t *arena, cbae_dom_tree_t *out);

/** Release the heap-backed children vectors. Does not touch the arena
 * (idom/rpo/enter/exit arrays are arena-owned). Safe on an empty tree and on one already destroyed. */
void cbae_dom_tree_destroy(cbae_dom_tree_t *dt);

/** Immediate dominator of `block_id` (returns block_id itself for the
 * entry block, matching the algorithm's own idom[entry]=entry fact).
 * CBAE_DOM_NONE if `block_id` is not a block of the tree. */
uint32_t cbae_dom_tree_idom(const cbae_dom_tree_t *dt, uint32_t block_id);

/** True if `a` dominates `b`, INCLUSIVE (every block dominates itself).
 * False if either is not a block of the tree. */
bool cbae_dom_tree_dominates(const cbae_dom_tree_t *dt, uint32_t a, uint32_t b);

/** True if `a` strictly dominates `b` (dominates AND a != b). */
static inline bool cbae_dom_tree_strictly_dominates(const cbae_dom_tree_t *dt,
                                                      uint32_t a, uint32_t b) {
    return a != b && cbae_dom_tree_dominates(dt, a, b);
}

/** Children of `block_id` in the dominator tree. Never NULL (may be
 * an empty vector for a leaf, and is one for a block that is not in the tree). */
const cbae_vector_t *cbae_dom_tree_children(const cbae_dom_tree_t *dt,
                                             uint32_t block_id);

/* ── Dominance frontier (Cytron et al.) ───────────────────────────────── */

typedef struct cbae_dom_frontier {
    uint32_t       block_count;
    cbae_vector_t *frontier;  /* [block_id] -> cbae_vector_t of block ids,
                                * heap-backed                               */
} cbae_dom_frontier_t;

/** Compute the dominance frontier of every block from an already-built
 * dominator tree. The sets are in the order the blocks were found, which is
 * increasing block id.
 *
 * Errors: CBAE_ERR_INVALID for a NULL argument, an empty tree (one that failed to build or was never built), or a tree
 * whose function has since gained or lost blocks; CBAE_ERR_OOM when the heap is out of memory. On ANY error `*out` is all
 * zero: an empty frontier that cbae_dom_frontier_destroy() accepts and cbae_dom_frontier_of() answers with an empty set. */
cbae_err_t cbae_dom_frontier_compute(const cbae_dom_tree_t *dt,
                                      cbae_dom_frontier_t *out);
/** Release the sets and leave `*df` empty. Safe on an empty frontier and on one already destroyed. */
void cbae_dom_frontier_destroy(cbae_dom_frontier_t *df);
/** The frontier of `block_id`. Never NULL: an empty set for a block that is not in the frontier structure. */
const cbae_vector_t *cbae_dom_frontier_of(const cbae_dom_frontier_t *df,
                                           uint32_t block_id);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DOMINATOR_TREE_H */
