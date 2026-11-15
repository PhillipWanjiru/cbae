/**
 * @file cir_verifier.h
 * @brief Structural correctness checks for a CIR function.
 *
 * SCOPE: structure, not SSA dominance. A function that passes has ids that are
 * unique and equal to their table indices, operand slots that hold registered
 * values (none an unresolved placeholder), results that belong to their
 * instructions, phis that lead their block and match its predecessors exactly,
 * branch targets that exist, and edges recorded once on both sides. The full
 * list, in the order it is checked, is at the top of cir_verifier.c.
 *
 * What it does NOT say is whether a value is available where it is used: that
 * needs the dominator relation (Phase 5) and is cbae_ssa_verify_function() in
 * dataflow/ssa_verifier.h, which calls this first. Operand types and operand
 * counts per opcode are not checked by either.
 */
#ifndef CBAE_CIR_VERIFIER_H
#define CBAE_CIR_VERIFIER_H

#include "cir_function.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CIR_VERIFY_MSG_MAX 256

typedef struct cbae_cir_verify_result {
    bool ok;
    char message[CIR_VERIFY_MSG_MAX];   /* empty when ok; else the first violation found */
} cbae_cir_verify_result_t;

/** Check `f`'s structure. A NULL function is reported as "null function"; a
 *  function with no blocks passes. Never modifies `f`. */
cbae_cir_verify_result_t cbae_cir_verify_function(const cbae_cir_function_t *f);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_VERIFIER_H */
