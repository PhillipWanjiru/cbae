/**
 * @file basic_block.h
 * @brief Basic block: instruction run, successor edges.
 */
#ifndef CBAE_BASIC_BLOCK_H
#define CBAE_BASIC_BLOCK_H

#include "cbae/cbae_types.h"
#include "disasm/instruction.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A basic block never has more than 2 direct successors: fallthrough
 * and taken-branch (Jcc), or a single call-return / jump target.       */
#define CBAE_BB_MAX_SUCCESSORS 2

typedef enum cbae_edge_kind {
    CBAE_EDGE_NONE = 0,
    CBAE_EDGE_FALLTHROUGH,   /* straight-line flow to the next block    */
    CBAE_EDGE_BRANCH_TAKEN,  /* Jcc taken / JMP target (forward)        */
    CBAE_EDGE_BACK,          /* target address <= source (loop back)   */
    CBAE_EDGE_CALL_RETURN,   /* return-site edge after a CALL           */
} cbae_edge_kind_t;

typedef struct cbae_bb_edge {
    cbae_addr_t      target;
    cbae_edge_kind_t kind;
} cbae_bb_edge_t;

typedef struct cbae_basic_block {
    cbae_addr_t start_addr;
    cbae_addr_t end_addr;      /* address AFTER the last instruction    */

    cbae_instruction_t *instructions;   /* arena-allocated array         */
    uint32_t             instruction_count;

    cbae_bb_edge_t successors[CBAE_BB_MAX_SUCCESSORS];
    uint8_t        successor_count;

    bool ends_in_call;
    bool ends_in_ret;
    bool ends_in_unresolved_branch;   /* indirect jmp/call not
                                        * statically resolved in Phase 3 */
} cbae_basic_block_t;

#ifdef __cplusplus
}
#endif

#endif /* CBAE_BASIC_BLOCK_H */
