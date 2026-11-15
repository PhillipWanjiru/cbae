/**
 * @file operand_decoder.h
 * @brief PRIVATE — converts Capstone x86 operands into CBAE's operand model.
 *
 * Internal to the disasm module. Not part of the public API in include/.
 */
#ifndef CBAE_SRC_OPERAND_DECODER_H
#define CBAE_SRC_OPERAND_DECODER_H

#include "disasm/operand.h"
#include <capstone/capstone.h>

/* Convert one Capstone x86 operand into CBAE's operand model. */
void cbae_decode_operand(const cs_x86_op *cs_op, cbae_operand_t *out);

/* Map a Capstone x86_reg id to CBAE's coarse register enum. */
cbae_reg_t cbae_map_cs_reg(uint16_t cs_reg_id);

#endif /* CBAE_SRC_OPERAND_DECODER_H */
