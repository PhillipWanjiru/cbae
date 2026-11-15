/**
 * @file instruction.h
 * @brief Decoded instruction model — opcode class, operands, branch info.
 */
#ifndef CBAE_INSTRUCTION_H
#define CBAE_INSTRUCTION_H

#include "cbae/cbae_types.h"
#include "disasm/operand.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBAE_INSN_MAX_OPERANDS  4
#define CBAE_INSN_MAX_BYTES     15   /* x86-64 architectural max length  */
#define CBAE_MNEMONIC_MAX       32

/* Coarse instruction classification used by CFG construction and later
 * CIR lifting. NOT a full x86 opcode table -- Capstone already has
 * that (see cs_id below); this is the minimal categorisation CBAE's
 * own passes actually branch on. */
typedef enum cbae_insn_class {
    CBAE_ICLASS_OTHER = 0,
    CBAE_ICLASS_MOV,
    CBAE_ICLASS_LEA,
    CBAE_ICLASS_ARITH,     /* add/sub/and/or/xor/inc/dec/neg/not/shl/... */
    CBAE_ICLASS_CMP,       /* cmp/test                                  */
    CBAE_ICLASS_STACK,     /* push/pop                                  */
    CBAE_ICLASS_CALL,
    CBAE_ICLASS_RET,
    CBAE_ICLASS_JMP,       /* unconditional jump                        */
    CBAE_ICLASS_JCC,       /* conditional jump, any condition code      */
    CBAE_ICLASS_NOP,
    CBAE_ICLASS_IO,        /* in / out                                  */
    CBAE_ICLASS_MSR,       /* rdmsr / wrmsr                             */
    CBAE_ICLASS_INT,       /* int3 / int / iret                         */
    CBAE_ICLASS_PRIV,      /* cli / sti / hlt / wbinvd / ...            */
} cbae_insn_class_t;

typedef struct cbae_instruction {
    cbae_addr_t address;
    uint8_t     length;
    uint8_t     raw[CBAE_INSN_MAX_BYTES];

    char              mnemonic[CBAE_MNEMONIC_MAX];
    cbae_insn_class_t iclass;
    uint32_t          cs_id;     /* raw Capstone x86_insn enum value     */

    cbae_operand_t operands[CBAE_INSN_MAX_OPERANDS];
    uint8_t        operand_count;

    bool        is_branch;               /* jmp/jcc/call/ret            */
    bool        is_call;
    bool        is_ret;
    bool        is_conditional;          /* jcc only                    */
    bool        branch_target_is_direct; /* target encoded as immediate */
    cbae_addr_t branch_target;           /* valid iff branch_target_is_direct */
} cbae_instruction_t;

#ifdef __cplusplus
}
#endif

#endif /* CBAE_INSTRUCTION_H */
