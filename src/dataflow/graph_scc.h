/**
 * @file graph_scc.h  (INTERNAL -- not part of the public include/ tree)
 * @brief Strongly connected components of a directed graph, by iterative
 *        Tarjan, over the same CSR adjacency the dominator core uses.
 *
 * Two clients, both inside cbae_dataflow:
 *   - the post-dominator tree needs the SINK components of the part of a
 *     CFG that cannot reach an exit (infinite loops);
 *   - alias analysis needs to know which blocks lie on a CFG cycle.
 * One implementation serves both, and it is tested directly against a
 * brute-force transitive-closure reference.
 *
 * "Iterative" matters: a CIR function's CFG can be a long chain, and a
 * recursive DFS would use stack proportional to its length.
 */
#ifndef CBAE_GRAPH_SCC_H
#define CBAE_GRAPH_SCC_H

#include "cbae/cbae_error.h"
#include <stdbool.h>
#include <stdint.h>

/** comp[] value of a node excluded from the computation. */
#define GRAPH_SCC_NONE UINT32_MAX

/** Components of the subgraph induced by the nodes with active[x] == true
 *  (every node when `active` is NULL). Edges to or from inactive nodes are
 *  ignored.
 *
 *  Successors of x are succ_adj[succ_off[x] .. succ_off[x+1]).
 *
 *  Output: comp[x] in [0, *ncomp) for an active node, GRAPH_SCC_NONE for an
 *  inactive one. comp must have n entries.
 *
 *  Component ids are assigned in the order Tarjan completes them, which is a
 *  reverse topological order of the component DAG: if an edge leads from
 *  component A to a different component B, then id(B) < id(A). */
cbae_err_t graph_scc_compute(uint32_t n, const uint32_t *succ_off,
                             const uint32_t *succ_adj, const bool *active,
                             uint32_t *comp, uint32_t *ncomp);

/** on_cycle[x] = true iff a non-empty path leads from x back to x: x's
 *  component has at least two nodes, or x has an edge to itself.
 *  on_cycle must have n entries. */
cbae_err_t graph_scc_on_cycle(uint32_t n, const uint32_t *succ_off,
                              const uint32_t *succ_adj, bool *on_cycle);

#endif /* CBAE_GRAPH_SCC_H */
