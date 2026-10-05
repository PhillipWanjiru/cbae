/**
 * @file cfg_graph.h  (INTERNAL -- not part of the public include/ tree)
 * @brief A CIR function's control-flow graph as CSR adjacency, for the
 *        analyses that work on plain graphs (dominators, SCCs).
 */
#ifndef CBAE_CFG_GRAPH_H
#define CBAE_CFG_GRAPH_H

#include "dom_core.h"
#include "cir/cir_function.h"

/** The forward CFG of `func`: node b is block b (ids equal indices), and
 *  node b's successors are block b's successors[]. Built from the same
 *  edges the verifier checks. Release with dom_csr_free(). */
cbae_err_t cfg_csr_build(const cbae_cir_function_t *func, dom_csr_t *out);

#endif /* CBAE_CFG_GRAPH_H */
