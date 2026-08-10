/**
 * @file cir_verifier.h
 * @brief Structural correctness checks for a lifted CIR function.
 *
 * SCOPE: structural, not a full SSA dominance proof. Checks every
 * operand references a value the function actually defined, every
 * phi's incoming-block list matches its block's real predecessor set,
 * and every branch/jump target is a real block. Verifying a use's
 * defining block genuinely DOMINATES the use needs a dominator tree --
 * Phase 5 infrastructure, deferred there rather than duplicated here.
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
    char message[CIR_VERIFY_MSG_MAX];
} cbae_cir_verify_result_t;

cbae_cir_verify_result_t cbae_cir_verify_function(const cbae_cir_function_t *f);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_VERIFIER_H */
