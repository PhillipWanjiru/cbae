/**
 * @file cir_builder.h
 * @brief Programmatic CIR construction API.
 *
 * A cbae_cir_builder_t is a thin cursor: it tracks which function and which block new instructions get appended to.
 * Blocks, instructions, values and call-target names are allocated from the function's arena (an arena gives nothing
 * back, so they live until the arena is destroyed). The function's bookkeeping - the block and value vectors, the
 * address map and each block's predecessor vector - is heap memory that cbae_cir_function_destroy frees.
 *
 * WHAT A CALL DOES. Every call does what it was asked or nothing at all:
 *   - it succeeds, and the function has changed by exactly what was asked;
 *   - it refuses an argument that cannot be right (CBAE_ERR_INVALID): a NULL, a count or a name that does not fit, an
 *     opcode or type that does not exist, an operand or block that belongs to another function, a block that would
 *     have a third successor;
 *   - it runs out of memory (CBAE_ERR_OOM) or one of the function's counters would wrap (CBAE_ERR_OVERFLOW).
 * After the last two kinds of failure the function is exactly as it was: no id is used up, no value is registered
 * that no instruction defines, no edge has one end, no instruction is half added. (What the call had already taken
 * from the arena stays taken.) A call that returns a pointer returns NULL and says why in cbae_error_get_context(); the
 * one NULL that is not a failure is a void result, see cbae_cir_emit.
 *
 * What the builder checks is structure, which is what keeps a function the serializer, the verifier and the analyses can
 * walk. Whether the function is well-formed CIR - operand counts and types that fit the opcode, one terminator at the
 * end of each block, phis that match the predecessors - is the verifier's question; the builder will build a function
 * that fails it.
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

/* ── Function / block lifecycle ──────────────────────────────────────── */

/** Creates an empty function in @p arena. @p name may be NULL (empty); one longer than the 127 bytes the function
 * holds is cut. *out is NULL on failure. */
cbae_err_t cbae_cir_function_create(cbae_arena_t *arena, cbae_addr_t entry_addr,
                                     const char *name, cbae_cir_function_t **out);

/** Frees the function's heap-backed bookkeeping: the block and value vectors, the address map and each block's
 * predecessor vector. It does not touch the arena - the block, instruction and value structs are arena memory and go
 * with it. Accepts NULL, a function already destroyed, and a block slot that is empty. */
void cbae_cir_function_destroy(cbae_cir_function_t *func);

/** Adds an empty block. Blocks are numbered 0, 1, 2 ... in the order they are created. Two blocks may start at the same
 * address (the lifter's synthetic entry block and the real one do): both are blocks, and the address finds the later.
 * *out is NULL on failure. */
cbae_err_t cbae_cir_block_create(cbae_cir_function_t *func, cbae_addr_t start_addr,
                                  cbae_cir_block_t **out);

/** The block most recently created at @p x86_addr, or NULL. */
cbae_cir_block_t *cbae_cir_function_block_at(const cbae_cir_function_t *func,
                                              cbae_addr_t x86_addr);

/** Adds the edge @p from -> @p to. An edge that is there is not added again (it is not an error: a sweep that adds
 * every edge a block needs can run over edges that a branch or jump already added). A block has at most
 * CIR_BLOCK_MAX_SUCCESSORS successors; a third is CBAE_ERR_INVALID. */
cbae_err_t cbae_cir_block_add_edge(cbae_cir_block_t *from, cbae_cir_block_t *to);

/* ── Builder cursor ─────────────────────────────────────────────────── */

typedef struct cbae_cir_builder {
    cbae_cir_function_t *func;
    cbae_cir_block_t     *block;
} cbae_cir_builder_t;

/** Points @p b at @p block of @p func. A builder that has no function or no block refuses what needs one. */
void cbae_cir_builder_init(cbae_cir_builder_t *b, cbae_cir_function_t *func,
                            cbae_cir_block_t *block);

/* ── Value construction ─────────────────────────────────────────────── */

/** A constant. The type is a width or a pointer, not void. */
cbae_cir_value_t *cbae_cir_const(cbae_cir_builder_t *b, cbae_cir_type_t type,
                                  int64_t val);
/** The value register @p reg holds when the function is entered (64 bits wide). */
cbae_cir_value_t *cbae_cir_param(cbae_cir_builder_t *b, cbae_reg_t reg);

/* ── Instruction emission ────────────────────────────────────────────── */

/** Appends an instruction to the builder's block. Every operand is a value of the function (not NULL); there are at
 * most CIR_MAX_OPERANDS. Returns the instruction through @p out, which is NULL on failure. An instruction whose type is
 * void has no result value: this is the call that tells that from a refusal. */
cbae_err_t cbae_cir_emit_insn(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                               cbae_cir_type_t result_type, cbae_addr_t source_addr,
                               cbae_cir_value_t *const *operands, uint8_t operand_count,
                               cbae_cir_instruction_t **out);

/** cbae_cir_emit_insn that returns the instruction's result. A void result_type gives NULL as well, with no error
 * set, so a caller that emits void instructions uses cbae_cir_emit_insn. */
cbae_cir_value_t *cbae_cir_emit(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                 cbae_cir_type_t result_type,
                                 cbae_addr_t source_addr,
                                 cbae_cir_value_t *const *operands,
                                 uint8_t operand_count);

/* ── Convenience wrappers ─────────────────────────────────────────────── */

/** LOAD; the type is the width loaded, not void. */
cbae_cir_value_t *cbae_cir_load (cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                  cbae_cir_type_t type, cbae_addr_t src);
/** STORE. */
cbae_err_t         cbae_cir_store(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                  cbae_cir_value_t *val, cbae_addr_t src);
/** A two-operand instruction with a result; the type is not void. */
cbae_cir_value_t *cbae_cir_binop(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                 cbae_cir_value_t *lhs, cbae_cir_value_t *rhs,
                                 cbae_cir_type_t result_type, cbae_addr_t src);
/** BRANCH on @p cond, with the edges to both blocks. Both are blocks of the function, and the builder's block ends up
 * with at most CIR_BLOCK_MAX_SUCCESSORS successors: if it would have more, nothing is added. */
cbae_err_t         cbae_cir_branch(cbae_cir_builder_t *b, cbae_cir_value_t *cond,
                                   cbae_cir_block_t *true_blk,
                                   cbae_cir_block_t *false_blk, cbae_addr_t src);
/** JUMP, with the edge to @p target (a block of the function; same limit as cbae_cir_branch). */
cbae_err_t         cbae_cir_jump(cbae_cir_builder_t *b, cbae_cir_block_t *target,
                                 cbae_addr_t src);
/** CALL. The target name is copied (the caller's buffer may be reused); NULL or empty means no name, and a name has at
 * most CIR_MAX_CALL_NAME bytes. At most CIR_MAX_OPERANDS arguments. The type is the type of the result; a void call
 * has no result value, so the caller cannot tell it from a failure (see cbae_cir_emit). */
cbae_cir_value_t *cbae_cir_call(cbae_cir_builder_t *b, const char *target_name,
                                 cbae_cir_value_t *const *args, uint8_t argc,
                                 cbae_cir_type_t result_type, cbae_addr_t src);
/** RETURN, with a value or (NULL) without. */
cbae_err_t         cbae_cir_return(cbae_cir_builder_t *b, cbae_cir_value_t *retval,
                                   cbae_addr_t src);

/* ── Phi ──────────────────────────────────────────────────────────────── */

/** A phi at the front of @p block, with no incoming values yet. The type is a width or a pointer, not void. */
cbae_cir_value_t *cbae_cir_phi_create(cbae_cir_function_t *func,
                                       cbae_cir_block_t *block,
                                       cbae_cir_type_t type);
/** Adds the incoming pair (@p value, @p from_block_id) to @p phi: a value of the function, and a block that exists. */
cbae_err_t cbae_cir_phi_add_incoming(cbae_cir_function_t *func,
                                      cbae_cir_instruction_t *phi,
                                      cbae_cir_value_t *value,
                                      uint32_t from_block_id);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_BUILDER_H */
