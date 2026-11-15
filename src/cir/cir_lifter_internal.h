/**
 * @file cir_lifter_internal.h
 * @brief PRIVATE -- shared lifting context and helpers used by every
 *        cir_lifter_*.c specialized module and the dispatcher itself.
 *
 * REGISTER TRACKING MODEL:
 *   Each of the 16 general-purpose x86-64 registers (RAX-R15, including
 *   RSP/RBP) is tracked as its own SSA "variable" in a per-block local
 *   map, reset at the start of lifting each block. Reading a register
 *   already written earlier in the SAME block returns that value
 *   directly (trivial, no recursion). Reading a register NOT yet
 *   written in this block produces a CIR_VAL_REG_ENTRY placeholder --
 *   deliberately unresolved, since resolving it may require walking
 *   predecessors and inserting a phi, which is the SSA constructor's
 *   job (Stage 4), not the lifter's.
 *
 *   RSP/RBP are tracked exactly like any other register -- there is
 *   nothing special-cased about them. What Phase 4 does NOT attempt is
 *   modelling stack MEMORY contents (e.g. knowing that [rbp-8] and
 *   [rbp-16] are distinct local variables) as promoted SSA values --
 *   that needs alias analysis and is deferred to a later phase. Every
 *   stack access still lifts correctly as an ordinary CIR_OP_LOAD /
 *   CIR_OP_STORE through a computed address.
 *
 *   RIP is never register-mapped (x86 doesn't expose it as a normal
 *   write target; jumps/calls become CIR control flow, not RIP writes).
 *   EFLAGS is never register-mapped either -- CIR_OP_CMP/CIR_OP_TEST
 *   produce an ordinary i1-typed SSA value consumed directly by the
 *   following CIR_OP_BRANCH, so there is no mutable "flags variable"
 *   to track at all.
 *
 * KNOWN SIMPLIFICATION: every register is treated as a single 64-bit
 * SSA variable regardless of the access width Phase 3 decoded (e.g. a
 * write to EAX is treated the same as a write to RAX). Real x86-64
 * semantics differ here (a 32-bit write zero-extends into the full
 * 64-bit register; a 16/8-bit write preserves the upper bits) --
 * modelling that precisely is a documented deferred refinement, not
 * silently ignored. Compiler-generated kernel driver code overwhelmingly
 * uses full-width or zero-extending 32-bit operations, so this is a
 * narrow, low-impact simplification for Phase 4's scope.
 */
#ifndef CBAE_SRC_CIR_LIFTER_INTERNAL_H
#define CBAE_SRC_CIR_LIFTER_INTERNAL_H

#include "cir/cir_builder.h"
#include "cir/cir_function.h"
#include "disasm/cfg.h"
#include "disasm/call_graph.h"
#include "disasm/instruction.h"
#include "loader/binary_image.h"

#define CIR_REG_MAP_SIZE CIR_BLOCK_REG_SLOTS  /* reuse the canonical size
                                                * from cir_block.h so the two
                                                * never drift apart          */

typedef struct cir_lift_ctx {
    const cbae_binary_image_t *img;
    const cbae_cfg_t           *cfg;
    const cbae_call_graph_t    *cg;   /* may be NULL -- call lifting degrades
                                        * gracefully to unresolved CIR_OP_CALL */
    cbae_cir_function_t        *func;
    cbae_cir_block_t            *cir_block;
    cbae_cir_builder_t            builder;

    cbae_cir_value_t *reg_map[CIR_REG_MAP_SIZE];
} cir_lift_ctx_t;

/** Reset the register map at the start of lifting a new block. */
void cir_lift_reg_map_reset(cir_lift_ctx_t *ctx);

/** Read the current value of `reg` in the block being lifted: a local
 * definition if one exists, otherwise a freshly-created (and cached)
 * CIR_VAL_REG_ENTRY placeholder for the SSA constructor to resolve. */
cbae_cir_value_t *cir_lift_read_reg(cir_lift_ctx_t *ctx, cbae_reg_t reg);

/** Record that `reg` now holds `value` for the remainder of this block. */
void cir_lift_write_reg(cir_lift_ctx_t *ctx, cbae_reg_t reg, cbae_cir_value_t *value);

/** Convert one Phase 3 operand (REG/IMM/MEM) into a CIR value read.
 * For MEM operands this computes the full base+index*scale+disp
 * address expression via CIR_OP_ADD/CIR_OP_MUL and returns that
 * address value (NOT a load -- callers needing the loaded value call
 * cbae_cir_load() themselves; LEA needs just the address).
 *
 * Takes the full owning instruction (not just an address) because
 * RIP-relative operands need insn->address + insn->length (the address
 * AFTER this instruction, per x86-64 RIP-relative semantics -- the
 * same formula Phase 3's call_graph_builder.c uses), which is a
 * DIFFERENT address than insn->address itself (used for CIR
 * traceability on any emitted arithmetic). Passing one ambiguous
 * "source_addr" for both purposes was an early design mistake caught
 * before implementation -- see git history / PHASE4.md for the note. */
cbae_cir_value_t *cir_lift_operand_value(cir_lift_ctx_t *ctx,
                                          const cbae_operand_t *op,
                                          const cbae_instruction_t *insn);

/** True if `op` is a memory operand (needs address computation). */
static inline bool cir_operand_is_mem(const cbae_operand_t *op) {
    return op->kind == CBAE_OPND_MEM;
}

/* ── Specialized lifter entry points, one x86 instruction at a time ──── */
void cir_lift_memory_insn    (cir_lift_ctx_t *ctx, const cbae_instruction_t *insn);
void cir_lift_io_insn        (cir_lift_ctx_t *ctx, const cbae_instruction_t *insn);
void cir_lift_call_insn      (cir_lift_ctx_t *ctx, const cbae_instruction_t *insn);
void cir_lift_arithmetic_insn(cir_lift_ctx_t *ctx, const cbae_instruction_t *insn);
void cir_lift_branch_insn    (cir_lift_ctx_t *ctx, const cbae_instruction_t *insn,
                               const cbae_basic_block_t *x86_block);

#endif /* CBAE_SRC_CIR_LIFTER_INTERNAL_H */
