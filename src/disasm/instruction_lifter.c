/**
 * @file instruction_lifter.c
 * @brief Capstone insn -> internal Instruction struct.
 *
 * Classification is a coarse category enum (cbae_insn_class_t), not a
 * reimplementation of Capstone's ~1500-mnemonic opcode table. Control
 * flow instructions (JMP/JCC/CALL/RET) are identified through both
 * their Capstone instruction id (for the common cases) AND Capstone's
 * instruction-group membership (X86_GRP_JUMP/CALL/RET), which reliably
 * catches all ~30 individual Jcc mnemonic variants (JE, JNE, JG, JL,
 * JA, JB, ...) without an enormous per-mnemonic switch.
 */
#include "instruction_lifter.h"
#include "operand_decoder.h"
#include <string.h>

static cbae_insn_class_t classify(const cs_insn *ci) {
    switch (ci->id) {
        case X86_INS_MOV: case X86_INS_MOVZX: case X86_INS_MOVSX:
        case X86_INS_MOVSXD: case X86_INS_MOVABS:
            return CBAE_ICLASS_MOV;
        case X86_INS_LEA:
            return CBAE_ICLASS_LEA;
        case X86_INS_ADD: case X86_INS_SUB: case X86_INS_AND:
        case X86_INS_OR:  case X86_INS_XOR: case X86_INS_INC:
        case X86_INS_DEC: case X86_INS_NEG: case X86_INS_NOT:
        case X86_INS_SHL: case X86_INS_SHR: case X86_INS_SAR:
        case X86_INS_IMUL:case X86_INS_MUL: case X86_INS_IDIV:
        case X86_INS_DIV:
            return CBAE_ICLASS_ARITH;
        case X86_INS_CMP:
        case X86_INS_TEST:
            return CBAE_ICLASS_CMP;
        case X86_INS_PUSH: case X86_INS_POP:
            return CBAE_ICLASS_STACK;
        case X86_INS_CALL:
            return CBAE_ICLASS_CALL;
        case X86_INS_RET: case X86_INS_RETF:
            return CBAE_ICLASS_RET;
        case X86_INS_JMP:
            return CBAE_ICLASS_JMP;
        case X86_INS_NOP:
            return CBAE_ICLASS_NOP;
        case X86_INS_IN: case X86_INS_OUT:
            return CBAE_ICLASS_IO;
        case X86_INS_RDMSR: case X86_INS_WRMSR:
            return CBAE_ICLASS_MSR;
        case X86_INS_INT3: case X86_INS_INT: case X86_INS_IRET:
        case X86_INS_IRETD:
            return CBAE_ICLASS_INT;
        case X86_INS_CLI: case X86_INS_STI: case X86_INS_HLT:
        case X86_INS_WBINVD:
            return CBAE_ICLASS_PRIV;
        default:
            /* Not one of the ids handled above -- check group membership
             * for the ~30 individual Jcc mnemonics (JE, JNE, JG, ...).
             * X86_INS_JMP is already handled by id above, so anything
             * reaching here tagged X86_GRP_JUMP is a conditional variant. */
            if (ci->detail) {
                for (int i = 0; i < ci->detail->groups_count; i++) {
                    if (ci->detail->groups[i] == X86_GRP_JUMP)
                        return CBAE_ICLASS_JCC;
                }
            }
            return CBAE_ICLASS_OTHER;
    }
}

void cbae_lift_instruction(const cs_insn *ci, cbae_instruction_t *out) {
    memset(out, 0, sizeof(*out));

    out->address = ci->address;
    out->length  = ci->size;
    memcpy(out->raw, ci->bytes,
           ci->size <= CBAE_INSN_MAX_BYTES ? ci->size : CBAE_INSN_MAX_BYTES);

    strncpy(out->mnemonic, ci->mnemonic, CBAE_MNEMONIC_MAX - 1);
    out->cs_id  = (uint32_t)ci->id;
    out->iclass = classify(ci);

    bool is_jump = false, is_call = false, is_ret = false;
    if (ci->detail) {
        for (int i = 0; i < ci->detail->groups_count; i++) {
            uint8_t g = ci->detail->groups[i];
            if (g == X86_GRP_JUMP) is_jump = true;
            if (g == X86_GRP_CALL) is_call = true;
            if (g == X86_GRP_RET)  is_ret  = true;
        }
    }
    out->is_call = is_call;
    out->is_ret  = is_ret || (out->iclass == CBAE_ICLASS_RET);
    out->is_branch = is_jump || is_call || out->is_ret;
    out->is_conditional = (out->iclass == CBAE_ICLASS_JCC);

    /* Operands */
    if (ci->detail) {
        const cs_x86 *x86 = &ci->detail->x86;
        uint8_t n = x86->op_count;
        if (n > CBAE_INSN_MAX_OPERANDS) n = CBAE_INSN_MAX_OPERANDS;
        out->operand_count = n;
        for (uint8_t i = 0; i < n; i++)
            cbae_decode_operand(&x86->operands[i], &out->operands[i]);
    }

    /* Direct branch target: for JMP/JCC/CALL with a single immediate
     * operand, Capstone resolves the ABSOLUTE target address into that
     * immediate (not a raw relative displacement) -- true for both
     * rel8 and rel32 encodings. */
    if ((is_jump || is_call) && out->operand_count >= 1 &&
        out->operands[0].kind == CBAE_OPND_IMM) {
        out->branch_target_is_direct = true;
        out->branch_target = (cbae_addr_t)out->operands[0].u.imm.value;
    } else {
        out->branch_target_is_direct = false;
        out->branch_target = CBAE_ADDR_INVALID;
    }
}
