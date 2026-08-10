/**
 * @file cir_printer.h
 * @brief Human-readable CIR text dump for debugging.
 */
#ifndef CBAE_CIR_PRINTER_H
#define CBAE_CIR_PRINTER_H

#include "cir_function.h"
#include "cir_value.h"
#include "cir_instruction.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void cbae_cir_print_function(const cbae_cir_function_t *f, FILE *out);
void cbae_cir_print_block(const cbae_cir_block_t *blk, FILE *out);
void cbae_cir_print_instruction(const cbae_cir_instruction_t *insn, FILE *out);
void cbae_cir_format_value(const cbae_cir_value_t *v, char *buf, int bufsz);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_PRINTER_H */
