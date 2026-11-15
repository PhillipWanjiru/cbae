/**
 * @file cir_instruction.h
 * @brief One CIR operation: opcode, operands, optional result, and the
 *        control-flow / call / phi metadata specific to certain opcodes.
 */
#ifndef CBAE_CIR_INSTRUCTION_H
#define CBAE_CIR_INSTRUCTION_H

#include "cir_opcodes.h"
#include "cir_type.h"
#include "cir_value.h"
#include "cbae/cbae_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CIR_MAX_OPERANDS 4

/* The longest call target name an instruction can hold, in bytes (the serialized form keeps a 16-bit length). */
#define CIR_MAX_CALL_NAME 65535u

typedef struct cbae_cir_instruction {
    uint32_t           id;            /* unique within the function, printed as #N */
    cbae_cir_opcode_t  opcode;

    cbae_cir_value_t  *result;        /* NULL if this instruction produces
                                        * no value (STORE, JUMP, RETURN, ...) */

    cbae_cir_value_t  *operands[CIR_MAX_OPERANDS];
    uint8_t             operand_count;

    cbae_addr_t          source_addr;  /* originating x86 instruction address,
                                        * for traceability back to Phase 3   */

    const char           *call_target_name;

    uint32_t               branch_true_block;
    uint32_t               branch_false_block;

    cbae_cir_value_t     **phi_incoming_values;
    uint32_t               *phi_incoming_blocks;
    uint32_t                 phi_incoming_count;
    uint32_t                 phi_incoming_capacity;
} cbae_cir_instruction_t;

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_INSTRUCTION_H */
