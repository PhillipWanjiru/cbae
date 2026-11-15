/**
 * @file cfg_graph.c
 * @brief CIR function -> CSR adjacency. See cfg_graph.h.
 */
#include "cfg_graph.h"
#include "platform/logging.h"
#include <stdlib.h>

cbae_err_t cfg_csr_build(const cbae_cir_function_t *func, dom_csr_t *out) {
    if (!func || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cfg graph: null argument");

    const uint32_t nblocks = (uint32_t)cbae_vector_count(&func->blocks);
    uint32_t nedges = 0;
    for (uint32_t b = 0; b < nblocks; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&func->blocks, b);
        nedges += blk->successor_count;
    }

    uint32_t *from = malloc(sizeof(uint32_t) * (nedges ? nedges : 1));
    uint32_t *to   = malloc(sizeof(uint32_t) * (nedges ? nedges : 1));
    if (!from || !to) {
        free(from); free(to);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "cfg graph: edge list alloc failed");
    }

    uint32_t ei = 0;
    for (uint32_t b = 0; b < nblocks; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&func->blocks, b);
        for (uint32_t k = 0; k < blk->successor_count; k++) {
            from[ei] = b;
            to[ei]   = blk->successors[k];
            ei++;
        }
    }

    cbae_err_t rc = dom_csr_build(nblocks, from, to, nedges, out);
    free(from);
    free(to);
    return rc;
}
