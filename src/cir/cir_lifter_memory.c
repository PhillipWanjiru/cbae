/**
 * @file cir_lifter_memory.c
 * @brief MOV/LEA/PUSH/POP -> CIR_OP_LOAD/STORE/LEA, plus implicit
 *        register propagation for register-to-register/immediate moves.
 *
 * MOV VARIANTS UNIFIED: MOV, MOVZX, MOVSX, MOVSXD, and MOVABS all lift
 * identically here. Phase 4 tracks every register as a single 64-bit
 * SSA value (see cir_lifter_internal.h's header comment) so the
 * zero-extend/sign-extend distinction these variants encode doesn't
 * change how the destination register ends up tracked -- a documented
 * simplification, not an oversight.
 *
 * REGISTER-TO-REGISTER/IMMEDIATE MOVES EMIT NO CIR INSTRUCTION: in
 * SSA form, "copying" a value doesn't need a new operation -- the
 * destination register simply becomes an alias for the same SSA value
 * (or the newly-created constant). This matches how LLVM and other
 * SSA-based IRs handle trivial moves; an explicit CIR_OP_COPY here
 * would just be redundant bookkeeping a later pass would immediately
 * eliminate. Real work (an actual memory access) always gets a real
 * CIR_OP_LOAD or CIR_OP_STORE.
 */
#include "cir_lifter_internal.h"
#include <string.h>

void cir_lift_memory_insn(cir_lift_ctx_t *ctx, const cbae_instruction_t *insn) {
    /* ── PUSH / POP: implicitly read AND write RSP, handled specially
     * since they don't fit the plain "dest, src" MOV shape. ────────── */
    if (insn->iclass == CBAE_ICLASS_STACK) {
        bool is_push = (strncmp(insn->mnemonic, "push", 4) == 0);
        cbae_cir_value_t *rsp   = cir_lift_read_reg(ctx, CBAE_REG_RSP);
        cbae_cir_value_t *eight = cbae_cir_const(&ctx->builder, cir_type_ptr(), 8);

        if (is_push) {
            cbae_cir_value_t *new_rsp = cbae_cir_binop(
                &ctx->builder, CIR_OP_SUB, rsp, eight, cir_type_ptr(), insn->address);
            cir_lift_write_reg(ctx, CBAE_REG_RSP, new_rsp);
            if (insn->operand_count >= 1) {
                cbae_cir_value_t *src =
                    cir_lift_operand_value(ctx, &insn->operands[0], insn);
                cbae_cir_store(&ctx->builder, new_rsp, src, insn->address);
            }
        } else { /* pop */
            if (insn->operand_count >= 1 && insn->operands[0].kind == CBAE_OPND_REG) {
                cbae_cir_value_t *val =
                    cbae_cir_load(&ctx->builder, rsp, cir_type_i(64), insn->address);
                cir_lift_write_reg(ctx, insn->operands[0].u.reg.reg, val);
            }
            cbae_cir_value_t *new_rsp = cbae_cir_binop(
                &ctx->builder, CIR_OP_ADD, rsp, eight, cir_type_ptr(), insn->address);
            cir_lift_write_reg(ctx, CBAE_REG_RSP, new_rsp);
        }
        return;
    }

    if (insn->operand_count < 1) return;

    /* ── LEA dst, [mem]: destination gets the computed ADDRESS, no
     * memory access happens at all. ────────────────────────────────── */
    if (insn->iclass == CBAE_ICLASS_LEA) {
        if (insn->operand_count < 2 || insn->operands[0].kind != CBAE_OPND_REG) return;
        cbae_cir_value_t *addr = cir_lift_operand_value(ctx, &insn->operands[1], insn);
        cir_lift_write_reg(ctx, insn->operands[0].u.reg.reg, addr);
        return;
    }

    /* ── MOV dst, src ─────────────────────────────────────────────── */
    if (insn->operand_count < 2) return;
    const cbae_operand_t *dst = &insn->operands[0];
    const cbae_operand_t *src = &insn->operands[1];

    if (cir_operand_is_mem(dst)) {
        cbae_cir_value_t *addr = cir_lift_operand_value(ctx, dst, insn);
        cbae_cir_value_t *val  = cir_lift_operand_value(ctx, src, insn);
        cbae_cir_store(&ctx->builder, addr, val, insn->address);
        return;
    }

    if (cir_operand_is_mem(src)) {
        if (dst->kind != CBAE_OPND_REG) return;
        cbae_cir_value_t *addr = cir_lift_operand_value(ctx, src, insn);
        cbae_cir_value_t *val =
            cbae_cir_load(&ctx->builder, addr, cir_type_i(64), insn->address);
        cir_lift_write_reg(ctx, dst->u.reg.reg, val);
        return;
    }

    /* reg-to-reg or imm-to-reg: pure value propagation, no instruction */
    if (dst->kind == CBAE_OPND_REG) {
        cbae_cir_value_t *val = cir_lift_operand_value(ctx, src, insn);
        cir_lift_write_reg(ctx, dst->u.reg.reg, val);
    }
}
