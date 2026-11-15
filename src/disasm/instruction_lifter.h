/**
 * @file instruction_lifter.h
 * @brief PRIVATE — converts a fully-decoded Capstone instruction into
 *        CBAE's instruction model.
 */
#ifndef CBAE_SRC_INSTRUCTION_LIFTER_H
#define CBAE_SRC_INSTRUCTION_LIFTER_H

#include "disasm/instruction.h"
#include <capstone/capstone.h>

/* Convert one fully-decoded Capstone instruction (with CS_OPT_DETAIL on)
 * into CBAE's instruction model, including classification and direct
 * branch-target extraction. */
void cbae_lift_instruction(const cs_insn *ci, cbae_instruction_t *out);

#endif /* CBAE_SRC_INSTRUCTION_LIFTER_H */
