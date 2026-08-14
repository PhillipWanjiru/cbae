/**
 * @file cir_lifter_branch.c
 * @brief Jcc/JMP/RET -> CIR_OP_BRANCH/JUMP/RETURN.
 *
 * Reuses Phase 3's ALREADY-COMPUTED successor edges directly rather
 * than re-deriving branch targets from the raw instruction -- Phase 3's
 * cfg_builder.c did this work once, correctly (including the FALLTHROUGH
 * vs BRANCH_TAKEN vs BACK classification), so Phase 4 just maps those
 * x86 block addresses to the corresponding CIR blocks (created in pass 1
 * of the dispatcher, so every lookup here is guaranteed to succeed).
 */
#include "cir_lifter_internal.h"

void cir_lift_branch_insn(cir_lift_ctx_t *ctx, const cbae_instruction_t *insn,
                           const cbae_basic_block_t *x86_block) {
    if (insn->iclass == CBAE_ICLASS_RET) {
        cbae_cir_value_t *retval = cir_lift_read_reg(ctx, CBAE_REG_RAX);
        cbae_cir_return(&ctx->builder, retval, insn->address);
        return;
    }

    if (insn->iclass == CBAE_ICLASS_JMP) {
        /* An indirect jmp (jump table / computed goto) has ZERO
         * successors recorded by Phase 3 (ends_in_unresolved_branch) --
         * honestly emit no CIR terminator rather than guess a target. */
        if (x86_block->successor_count >= 1) {
            cbae_addr_t target_addr = x86_block->successors[0].target;
            cbae_cir_block_t *target = cbae_cir_function_block_at(ctx->func, target_addr);
            if (target) cbae_cir_jump(&ctx->builder, target, insn->address);
        }
        return;
    }

    if (insn->iclass == CBAE_ICLASS_JCC) {
        /* Condition value relayed from cir_lift_arithmetic_insn's
         * CMP/TEST handling -- see that file's header for why this
         * same-block relay through the reg_map's EFLAGS slot is safe. */
        cbae_cir_value_t *cond = ctx->reg_map[CBAE_REG_EFLAGS];
        if (!cond) {
            /* No preceding CMP/TEST was lifted in this block (shouldn't
             * happen for compiler-generated code, but never crash on
             * unusual input) -- emit a well-formed placeholder i1 so
             * the branch still lifts structurally rather than being
             * silently dropped. */
            cond = cbae_cir_const(&ctx->builder, cir_type_i1(), 1);
        }

        if (x86_block->successor_count < 2) return; /* malformed, skip */

        cbae_addr_t true_addr = CBAE_ADDR_INVALID, false_addr = CBAE_ADDR_INVALID;
        for (int i = 0; i < x86_block->successor_count; i++) {
            if (x86_block->successors[i].kind == CBAE_EDGE_FALLTHROUGH)
                false_addr = x86_block->successors[i].target;
            else
                true_addr = x86_block->successors[i].target;
        }

        cbae_cir_block_t *true_blk  = cbae_cir_function_block_at(ctx->func, true_addr);
        cbae_cir_block_t *false_blk = cbae_cir_function_block_at(ctx->func, false_addr);
        if (true_blk && false_blk)
            cbae_cir_branch(&ctx->builder, cond, true_blk, false_blk, insn->address);
    }
}
