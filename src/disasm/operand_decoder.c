/**
 * @file operand_decoder.c
 * @brief ModRM/SIB/disp/imm -> Operand structs.
 *
 * Capstone has already fully decoded the raw ModRM/SIB/displacement/
 * immediate bytes into a cs_x86_op struct by the time this file sees
 * an instruction -- this module's job is bridging THAT representation
 * into CBAE's own unified operand model (cbae_operand_t), not redoing
 * byte-level decoding from scratch.
 */
#include "operand_decoder.h"
#include <string.h>

cbae_reg_t cbae_map_cs_reg(uint16_t r) {
    switch (r) {
        case X86_REG_RAX: return CBAE_REG_RAX;
        case X86_REG_RBX: return CBAE_REG_RBX;
        case X86_REG_RCX: return CBAE_REG_RCX;
        case X86_REG_RDX: return CBAE_REG_RDX;
        case X86_REG_RSI: return CBAE_REG_RSI;
        case X86_REG_RDI: return CBAE_REG_RDI;
        case X86_REG_RBP: return CBAE_REG_RBP;
        case X86_REG_RSP: return CBAE_REG_RSP;
        case X86_REG_R8:  return CBAE_REG_R8;
        case X86_REG_R9:  return CBAE_REG_R9;
        case X86_REG_R10: return CBAE_REG_R10;
        case X86_REG_R11: return CBAE_REG_R11;
        case X86_REG_R12: return CBAE_REG_R12;
        case X86_REG_R13: return CBAE_REG_R13;
        case X86_REG_R14: return CBAE_REG_R14;
        case X86_REG_R15: return CBAE_REG_R15;
        case X86_REG_RIP: return CBAE_REG_RIP;
        case X86_REG_EFLAGS: return CBAE_REG_EFLAGS;
        case X86_REG_INVALID: return CBAE_REG_NONE;
        default: return CBAE_REG_OTHER;
    }
}

const char *cbae_reg_name(cbae_reg_t r) {
    switch (r) {
        case CBAE_REG_RAX: return "rax"; case CBAE_REG_RBX: return "rbx";
        case CBAE_REG_RCX: return "rcx"; case CBAE_REG_RDX: return "rdx";
        case CBAE_REG_RSI: return "rsi"; case CBAE_REG_RDI: return "rdi";
        case CBAE_REG_RBP: return "rbp"; case CBAE_REG_RSP: return "rsp";
        case CBAE_REG_R8:  return "r8";  case CBAE_REG_R9:  return "r9";
        case CBAE_REG_R10: return "r10"; case CBAE_REG_R11: return "r11";
        case CBAE_REG_R12: return "r12"; case CBAE_REG_R13: return "r13";
        case CBAE_REG_R14: return "r14"; case CBAE_REG_R15: return "r15";
        case CBAE_REG_RIP: return "rip"; case CBAE_REG_EFLAGS: return "eflags";
        case CBAE_REG_OTHER: return "other";
        default: return "none";
    }
}

void cbae_decode_operand(const cs_x86_op *cs_op, cbae_operand_t *out) {
    memset(out, 0, sizeof(*out));
    out->size = cs_op->size;

    /* Best-effort only -- DIET-mode Capstone builds leave access as 0.
     * CBAE's own logic never depends on these; see operand.h. */
    out->is_read  = (cs_op->access & CS_AC_READ)  != 0;
    out->is_write = (cs_op->access & CS_AC_WRITE) != 0;

    switch (cs_op->type) {
        case X86_OP_REG:
            out->kind = CBAE_OPND_REG;
            out->cs_reg_id = (uint16_t)cs_op->reg;
            out->u.reg.reg = cbae_map_cs_reg((uint16_t)cs_op->reg);
            break;

        case X86_OP_IMM:
            out->kind = CBAE_OPND_IMM;
            out->u.imm.value = cs_op->imm;
            break;

        case X86_OP_MEM:
            out->kind = CBAE_OPND_MEM;
            out->u.mem.base  = cbae_map_cs_reg((uint16_t)cs_op->mem.base);
            out->u.mem.index = cbae_map_cs_reg((uint16_t)cs_op->mem.index);
            out->u.mem.scale = (uint8_t)(cs_op->mem.scale > 0 ? cs_op->mem.scale : 1);
            out->u.mem.disp  = cs_op->mem.disp;
            if (cs_op->mem.base == X86_REG_RIP)
                out->cs_reg_id = (uint16_t)X86_REG_RIP;
            break;

        default:
            out->kind = CBAE_OPND_NONE;
            break;
    }
}
