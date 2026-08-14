/**
 * @file cir_lifter_arithmetic.c
 * @brief ADD/SUB/AND/XOR/CMP -> CIR arithmetic and comparison opcodes.
 *
 * MNEMONIC-STRING DISPATCH, DELIBERATELY: cbae_insn_class_t buckets
 * every arithmetic instruction into one CBAE_ICLASS_ARITH category
 * (see Phase 3's instruction_lifter.c), so this file needs its own,
 * finer-grained dispatch to know WHICH operation a given instruction
 * performs. Phase 3's cbae_instruction_t carries the raw Capstone
 * instruction id (cs_id) which could do this numerically, but using it
 * here would leak a Capstone dependency into Phase 4's lifter layer --
 * Phase 3 is the only layer meant to know Capstone exists. Mnemonic
 * strings ("add", "sub", "cmp", ...) are completely stable for this
 * narrow set of instructions and keep that boundary clean.
 *
 * CMP/TEST -> BRANCH RELAY: a comparison's i1 result is stashed in the
 * reg_map's otherwise-unused CBAE_REG_EFLAGS slot for cir_lifter_branch.c
 * to pick up when it lifts the immediately-following Jcc. This is safe
 * because Phase 3's cfg_builder.c guarantees a Jcc is always the LAST
 * instruction of its block, with any preceding CMP/TEST in the SAME
 * block processed immediately before it in program order -- see
 * cir_lifter_branch.c for the read side of this relay.
 */
#include "cir_lifter_internal.h"
#include <string.h>

static cbae_cir_opcode_t mnemonic_to_cir_op(const char *mnemonic) {
    if (!strcmp(mnemonic, "add"))  return CIR_OP_ADD;
    if (!strcmp(mnemonic, "sub"))  return CIR_OP_SUB;
    if (!strcmp(mnemonic, "and"))  return CIR_OP_AND;
    if (!strcmp(mnemonic, "or"))   return CIR_OP_OR;
    if (!strcmp(mnemonic, "xor"))  return CIR_OP_XOR;
    if (!strcmp(mnemonic, "not"))  return CIR_OP_NOT;
    if (!strcmp(mnemonic, "neg"))  return CIR_OP_NEG;
    if (!strcmp(mnemonic, "shl"))  return CIR_OP_SHL;
    if (!strcmp(mnemonic, "sal"))  return CIR_OP_SHL; /* sal is a shl alias */
    if (!strcmp(mnemonic, "shr"))  return CIR_OP_SHR;
    if (!strcmp(mnemonic, "sar"))  return CIR_OP_SAR;
    if (!strcmp(mnemonic, "imul")) return CIR_OP_MUL;
    if (!strcmp(mnemonic, "mul"))  return CIR_OP_MUL;
    if (!strcmp(mnemonic, "idiv")) return CIR_OP_DIV;
    if (!strcmp(mnemonic, "div"))  return CIR_OP_DIV;
    if (!strcmp(mnemonic, "inc"))  return CIR_OP_ADD;
    if (!strcmp(mnemonic, "dec"))  return CIR_OP_SUB;
    return CIR_OP_INVALID;
}

void cir_lift_arithmetic_insn(cir_lift_ctx_t *ctx, const cbae_instruction_t *insn) {
    if (insn->iclass == CBAE_ICLASS_CMP) {
        cbae_cir_opcode_t op = (!strcmp(insn->mnemonic, "test")) ? CIR_OP_TEST : CIR_OP_CMP;
        if (insn->operand_count < 2) return;
        cbae_cir_value_t *lhs = cir_lift_operand_value(ctx, &insn->operands[0], insn);
        cbae_cir_value_t *rhs = cir_lift_operand_value(ctx, &insn->operands[1], insn);
        cbae_cir_value_t *ops[2] = { lhs, rhs };
        cbae_cir_value_t *result =
            cbae_cir_emit(&ctx->builder, op, cir_type_i1(), insn->address, ops, 2);
        /* Relay slot -- see file header. Not a real register read/write. */
        ctx->reg_map[CBAE_REG_EFLAGS] = result;
        return;
    }

    bool is_inc   = !strcmp(insn->mnemonic, "inc");
    bool is_dec   = !strcmp(insn->mnemonic, "dec");
    bool is_unary = !strcmp(insn->mnemonic, "not") || !strcmp(insn->mnemonic, "neg");

    if (insn->operand_count < 1 || insn->operands[0].kind != CBAE_OPND_REG) return;
    cbae_reg_t dst_reg = insn->operands[0].u.reg.reg;

    cbae_cir_opcode_t op = mnemonic_to_cir_op(insn->mnemonic);
    if (op == CIR_OP_INVALID) return; /* unrecognized mnemonic, skip defensively */

    cbae_cir_value_t *result;
    if (is_unary) {
        cbae_cir_value_t *src = cir_lift_read_reg(ctx, dst_reg);
        cbae_cir_value_t *ops[1] = { src };
        result = cbae_cir_emit(&ctx->builder, op, cir_type_i(64), insn->address, ops, 1);
    } else if (is_inc || is_dec) {
        cbae_cir_value_t *src = cir_lift_read_reg(ctx, dst_reg);
        cbae_cir_value_t *one = cbae_cir_const(&ctx->builder, cir_type_i(64), 1);
        result = cbae_cir_binop(&ctx->builder, op, src, one, cir_type_i(64), insn->address);
    } else {
        if (insn->operand_count < 2) return;
        cbae_cir_value_t *lhs = cir_lift_read_reg(ctx, dst_reg);
        cbae_cir_value_t *rhs = cir_lift_operand_value(ctx, &insn->operands[1], insn);
        result = cbae_cir_binop(&ctx->builder, op, lhs, rhs, cir_type_i(64), insn->address);
    }
    cir_lift_write_reg(ctx, dst_reg, result);
}
