/**
 * @file cir_block.h
 * @brief CIR basic block -- a dense-id container of phi nodes followed
 *        by ordinary instructions, with predecessor/successor edges.
 */
#ifndef CBAE_CIR_BLOCK_H
#define CBAE_CIR_BLOCK_H

#include "cir_instruction.h"
#include "cbae/cbae_types.h"
#include "platform/vector.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Successors are structurally bounded at 2 (branch=2, jump/call=1,
 * return=0) -- a direct fact carried over from Phase 3's basic block
 * model. Predecessors have NO such bound: arbitrarily many blocks can
 * jump to the same target, so predecessors use a growable vector. */
#define CIR_BLOCK_MAX_SUCCESSORS 2

typedef struct cbae_cir_block {
    uint32_t      id;
    cbae_addr_t   start_addr;

    cbae_cir_instruction_t **instructions;
    uint32_t                  instruction_count;
    uint32_t                  instruction_capacity;

    cbae_vector_t  predecessors;  /* elem = uint32_t block id */

    uint32_t  successors[CIR_BLOCK_MAX_SUCCESSORS];
    uint32_t  successor_count;
} cbae_cir_block_t;

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_BLOCK_H */
