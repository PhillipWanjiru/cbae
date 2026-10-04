/**
 * @file use_def.h
 * @brief Use-def chains and a function-wide index of instructions and
 *        values, built once per SSA-form CIR function.
 *
 * In SSA every value has exactly ONE definition, so the definition side
 * of a use-def chain is just the value itself (v->u.def_insn for an
 * instruction result; a CIR_VAL_PARAM or CIR_VAL_CONST has no defining
 * instruction). What SSA does not hand you is the other direction --
 * every place a value is USED -- and that is what this module computes.
 *
 * Besides the use lists it records, for every instruction, which block
 * contains it and at which position. Every Phase 5 analysis needs that
 * map (dominance checks, memory dataflow queries, alias analysis), so it
 * lives here once rather than being rebuilt by each of them. Later
 * analyses therefore take a `const cbae_use_def_t *` as their shared
 * index and the caller keeps it alive for as long as they are used.
 *
 * TWO KINDS OF USE
 *   OPERAND       the value is operand `index` of an ordinary instruction;
 *                 it must be available where that instruction executes.
 *   PHI_INCOMING  the value is incoming edge `index` of a phi; it must be
 *                 available at the END of that edge's predecessor block
 *                 (insn->phi_incoming_blocks[index]), NOT in the phi's own
 *                 block -- a phi "reads" its operands on the edges, and a
 *                 loop phi legitimately uses a value defined later in the
 *                 loop body. cbae_use_point_block() gives that block.
 *
 * Ordering: each use list is sorted by block id, then instruction position
 * within the block, then operand/incoming index -- the order a walk over
 * func->blocks meets the uses. Block ids are the lifter's creation order,
 * which is neither address order nor reverse post-order, so do not read
 * "earlier in the list" as "earlier on any execution path".
 *
 * MEMORY: everything is heap-backed in compact arrays (CSR layout, no
 * per-value allocations) and released by cbae_use_def_destroy().
 */
#ifndef CBAE_USE_DEF_H
#define CBAE_USE_DEF_H

#include "cir/cir_function.h"
#include "cir/cir_instruction.h"
#include "cbae/cbae_error.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Returned by block queries for something not placed in any block. */
#define CBAE_USE_DEF_NO_BLOCK UINT32_MAX

/** Returned by cbae_use_def_pos_of() for an instruction not placed in a block. */
#define CBAE_USE_DEF_NO_POS   UINT32_MAX

typedef enum cbae_use_kind {
    CBAE_USE_OPERAND = 0,
    CBAE_USE_PHI_INCOMING
} cbae_use_kind_t;

typedef struct cbae_use {
    cbae_cir_instruction_t *insn;      /* the using instruction                  */
    uint32_t                block_id;  /* block that CONTAINS `insn`             */
    uint32_t                index;     /* operand index, or phi incoming index   */
    cbae_use_kind_t         kind;
} cbae_use_t;

typedef struct cbae_use_list {
    const cbae_use_t *uses;            /* NULL when count == 0                   */
    uint32_t          count;
} cbae_use_list_t;

typedef struct cbae_use_def {
    const cbae_cir_function_t *func;   /* borrowed                               */

    uint32_t            value_count;   /* == func->next_value_id                 */
    cbae_cir_value_t  **value_by_id;   /* [value id] -> value (NULL: unused id)  */
    uint32_t           *use_off;       /* [value_count+1] CSR offsets into uses  */
    cbae_use_t         *uses;

    uint32_t            insn_count;    /* == func->next_insn_id                  */
    cbae_cir_instruction_t **insn_by_id; /* [insn id] -> instruction (NULL: unused) */
    uint32_t           *insn_block;    /* [insn id] -> block id, or NO_BLOCK     */
    uint32_t           *insn_pos;      /* [insn id] -> index within its block    */
} cbae_use_def_t;

/** Index `func` and compute every value's use list.
 *  Fails with CBAE_ERR_INVALID if an operand or phi incoming value is not
 *  one of the function's own values (corrupt function), or if a value or
 *  instruction id is out of range or duplicated. */
cbae_err_t cbae_use_def_build(const cbae_cir_function_t *func, cbae_use_def_t *out);

void cbae_use_def_destroy(cbae_use_def_t *ud);

/** Every use of `v`, ordered as described above. Empty for a value nothing reads,
 *  and for a value that does not belong to the indexed function. */
cbae_use_list_t cbae_use_def_uses(const cbae_use_def_t *ud, const cbae_cir_value_t *v);

static inline uint32_t cbae_use_def_use_count(const cbae_use_def_t *ud,
                                               const cbae_cir_value_t *v) {
    return cbae_use_def_uses(ud, v).count;
}

/** True if nothing uses `v`. */
static inline bool cbae_use_def_is_dead(const cbae_use_def_t *ud,
                                         const cbae_cir_value_t *v) {
    return cbae_use_def_uses(ud, v).count == 0;
}

/** Block containing `insn`, or CBAE_USE_DEF_NO_BLOCK (also returned for an
 *  instruction that does not belong to the indexed function). */
uint32_t cbae_use_def_block_of(const cbae_use_def_t *ud, const cbae_cir_instruction_t *insn);

/** Index of `insn` within its block's instruction list, or
 *  CBAE_USE_DEF_NO_POS if `insn` is not placed in the indexed function. */
uint32_t cbae_use_def_pos_of(const cbae_use_def_t *ud, const cbae_cir_instruction_t *insn);

/** The block in which `v` becomes available:
 *    instruction result -> the block containing the defining instruction
 *    CIR_VAL_PARAM / CIR_VAL_CONST -> block 0 (available from function entry)
 *    anything else (an unresolved placeholder) -> CBAE_USE_DEF_NO_BLOCK. */
uint32_t cbae_use_def_def_block(const cbae_use_def_t *ud, const cbae_cir_value_t *v);

/** The block at whose END (phi) or at whose instruction (operand) the used
 *  value must be available: for PHI_INCOMING the incoming edge's
 *  predecessor block, otherwise the block containing the instruction. */
uint32_t cbae_use_point_block(const cbae_use_t *use);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_USE_DEF_H */
