/**
 * @file cir_builder.h
 * @brief Programmatic CIR construction API.
 *
 * A cbae_cir_builder_t is a thin cursor: it tracks which function and
 * which block new instructions get appended to. All CIR memory (blocks,
 * instructions, values) comes from the function's arena.
 */
#ifndef CBAE_CIR_BUILDER_H
#define CBAE_CIR_BUILDER_H

#include "cir_function.h"
#include "cir_instruction.h"
#include "cir_value.h"
#include "cir_opcodes.h"
#include "cir_type.h"
#include "cbae/cbae_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Function / block / module lifecycle ─────────────────────────────── */

cbae_err_t cbae_cir_function_create(cbae_arena_t *arena, cbae_addr_t entry_addr,
                                     const char *name, cbae_cir_function_t **out);

/** Free the function's heap-backed bookkeeping containers (block/value
 * vectors, the addr_to_block hashmap, and each block's predecessor
 * vector). Does NOT touch the arena -- block/instruction/value structs
 * themselves are arena-owned and freed when the caller destroys the
 * arena. Safe to call on a function not registered in any module. */
void cbae_cir_function_destroy(cbae_cir_function_t *func);

cbae_err_t cbae_cir_block_create(cbae_cir_function_t *func, cbae_addr_t start_addr,
                                  cbae_cir_block_t **out);

cbae_cir_block_t *cbae_cir_function_block_at(const cbae_cir_function_t *func,
                                              cbae_addr_t x86_addr);

cbae_err_t cbae_cir_block_add_edge(cbae_cir_block_t *from, cbae_cir_block_t *to);

/* ── Builder cursor ─────────────────────────────────────────────────── */

typedef struct cbae_cir_builder {
    cbae_cir_function_t *func;
    cbae_cir_block_t     *block;
} cbae_cir_builder_t;

void cbae_cir_builder_init(cbae_cir_builder_t *b, cbae_cir_function_t *func,
                            cbae_cir_block_t *block);

/* ── Value construction ─────────────────────────────────────────────── */

cbae_cir_value_t *cbae_cir_const(cbae_cir_builder_t *b, cbae_cir_type_t type,
                                  int64_t val);
cbae_cir_value_t *cbae_cir_param(cbae_cir_builder_t *b, cbae_reg_t reg);

/* ── Generic instruction emission ────────────────────────────────────── */
cbae_cir_value_t *cbae_cir_emit(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                 cbae_cir_type_t result_type,
                                 cbae_addr_t source_addr,
                                 cbae_cir_value_t **operands,
                                 uint8_t operand_count);

/* ── Convenience wrappers ─────────────────────────────────────────────── */

cbae_cir_value_t *cbae_cir_load (cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                  cbae_cir_type_t type, cbae_addr_t src);
void               cbae_cir_store(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                  cbae_cir_value_t *val, cbae_addr_t src);
cbae_cir_value_t *cbae_cir_binop(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                 cbae_cir_value_t *lhs, cbae_cir_value_t *rhs,
                                 cbae_cir_type_t result_type, cbae_addr_t src);
void               cbae_cir_branch(cbae_cir_builder_t *b, cbae_cir_value_t *cond,
                                   cbae_cir_block_t *true_blk,
                                   cbae_cir_block_t *false_blk, cbae_addr_t src);
void               cbae_cir_jump(cbae_cir_builder_t *b, cbae_cir_block_t *target,
                                 cbae_addr_t src);
cbae_cir_value_t *cbae_cir_call(cbae_cir_builder_t *b, const char *target_name,
                                 cbae_cir_value_t **args, uint8_t argc,
                                 cbae_cir_type_t result_type, cbae_addr_t src);
void               cbae_cir_return(cbae_cir_builder_t *b, cbae_cir_value_t *retval,
                                   cbae_addr_t src);

cbae_cir_value_t *cbae_cir_phi_create(cbae_cir_function_t *func,
                                       cbae_cir_block_t *block,
                                       cbae_cir_type_t type);
cbae_err_t cbae_cir_phi_add_incoming(cbae_cir_function_t *func,
                                      cbae_cir_instruction_t *phi,
                                      cbae_cir_value_t *value,
                                      uint32_t from_block_id);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_BUILDER_H */
