/**
 * @file cir_lifter_io.c
 * @brief IN/OUT/RDMSR/WRMSR -> CIR_OP_PORT_READ/WRITE, CIR_OP_MSR_READ/WRITE.
 *
 * These are the cleanest lifts in the whole engine: x86 gives us zero
 * ambiguity about what these instructions do. IN/OUT are port I/O,
 * full stop; RDMSR/WRMSR are model-specific-register access, full stop.
 * No semantic guessing needed at all -- unlike CIR_OP_MMIO_READ/WRITE
 * (Phase 6 territory), these opcodes are syntactically certain.
 */
#include "cir_lifter_internal.h"
#include <string.h>

void cir_lift_io_insn(cir_lift_ctx_t *ctx, const cbae_instruction_t *insn) {
    if (insn->iclass == CBAE_ICLASS_IO) {
        bool is_in = (strncmp(insn->mnemonic, "in", 2) == 0);

        if (is_in) {
            /* IN dst, port */
            cbae_cir_value_t *port =
                (insn->operand_count >= 2)
                    ? cir_lift_operand_value(ctx, &insn->operands[1], insn)
                    : cbae_cir_const(&ctx->builder, cir_type_i(16), 0);
            cbae_cir_value_t *ops[1] = { port };
            cbae_cir_value_t *val = cbae_cir_emit(&ctx->builder, CIR_OP_PORT_READ,
                                                   cir_type_i(64), insn->address, ops, 1);
            if (insn->operand_count >= 1 && insn->operands[0].kind == CBAE_OPND_REG)
                cir_lift_write_reg(ctx, insn->operands[0].u.reg.reg, val);
        } else {
            /* OUT port, src */
            cbae_cir_value_t *port =
                (insn->operand_count >= 1)
                    ? cir_lift_operand_value(ctx, &insn->operands[0], insn)
                    : cbae_cir_const(&ctx->builder, cir_type_i(16), 0);
            cbae_cir_value_t *val =
                (insn->operand_count >= 2)
                    ? cir_lift_operand_value(ctx, &insn->operands[1], insn)
                    : cbae_cir_const(&ctx->builder, cir_type_i(64), 0);
            cbae_cir_value_t *ops[2] = { port, val };
            cbae_cir_emit(&ctx->builder, CIR_OP_PORT_WRITE, cir_type_void(),
                          insn->address, ops, 2);
        }
        return;
    }

    if (insn->iclass == CBAE_ICLASS_MSR) {
        bool is_rdmsr = (strncmp(insn->mnemonic, "rdmsr", 5) == 0);

        /* RDMSR/WRMSR are fixed-register instructions -- Capstone
         * reports zero explicit operands. The MSR index lives in ECX
         * and the value in EDX:EAX; Phase 4's single-64-bit-register
         * model tracks that pair as one RAX-slot value rather than
         * splitting EDX:EAX precisely (consistent with the same
         * simplification documented in cir_lifter_internal.h). */
        cbae_cir_value_t *msr_index = cir_lift_read_reg(ctx, CBAE_REG_RCX);

        if (is_rdmsr) {
            cbae_cir_value_t *ops[1] = { msr_index };
            cbae_cir_value_t *val = cbae_cir_emit(&ctx->builder, CIR_OP_MSR_READ,
                                                   cir_type_i(64), insn->address, ops, 1);
            cir_lift_write_reg(ctx, CBAE_REG_RAX, val);
        } else {
            cbae_cir_value_t *msr_val = cir_lift_read_reg(ctx, CBAE_REG_RAX);
            cbae_cir_value_t *ops[2] = { msr_index, msr_val };
            cbae_cir_emit(&ctx->builder, CIR_OP_MSR_WRITE, cir_type_void(),
                          insn->address, ops, 2);
        }
    }
}
