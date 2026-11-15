/**
 * @file disassembler.h
 * @brief Capstone-backed single-instruction decoder.
 */
#ifndef CBAE_DISASSEMBLER_H
#define CBAE_DISASSEMBLER_H

#include "cbae/cbae_error.h"
#include "loader/binary_image.h"
#include "disasm/instruction.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_disassembler cbae_disassembler_t;

/* Create a disassembler configured for the given architecture.
 * Phase 3 supports CBAE_ARCH_X86_64 only. */
cbae_err_t cbae_disasm_create(cbae_binary_arch_t arch,
                               cbae_disassembler_t **out);
void       cbae_disasm_destroy(cbae_disassembler_t **d);

/*
 * Decode exactly one instruction at `addr`.
 * `bytes` must point to at least `max_len` valid bytes; the decoder
 * never reads past max_len (critical near the end of a section).
 *
 * On success: CBAE_OK, *out filled, instruction length in out->length.
 * On failure (invalid/incomplete opcode): CBAE_ERR_PARSE.
 */
cbae_err_t cbae_disasm_decode_one(cbae_disassembler_t *d,
                                   const uint8_t *bytes, cbae_size_t max_len,
                                   cbae_addr_t addr,
                                   cbae_instruction_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DISASSEMBLER_H */
