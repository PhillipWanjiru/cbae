/**
 * @file cir_ssa.h
 * @brief SSA construction -- resolves every CIR_VAL_REG_ENTRY placeholder
 *        the lifter left behind into real definitions or phi nodes.
 */
#ifndef CBAE_CIR_SSA_H
#define CBAE_CIR_SSA_H

#include "cir_function.h"
#include "cbae/cbae_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convert a lifted (non-SSA) CIR function into proper SSA form: every
 * CIR_VAL_REG_ENTRY placeholder left by the lifter is resolved to
 * either a direct link to its actual defining value, or a newly
 * created and fully-filled phi node at a join point. After this call
 * succeeds, no instruction in `func` should reference a
 * CIR_VAL_REG_ENTRY value anywhere -- the verifier checks for this.
 *
 * ALGORITHM: Braun, Buchwald, Hack et al.'s direct SSA construction
 * (2013) -- recursive value lookup with lazy phi creation and
 * memoization to break cycles on loop back-edges. Simplified from
 * their original incremental/streaming design because CBAE's CFG is
 * always FULLY built before this runs: there is no "sealed vs
 * unsealed block" bookkeeping needed at all, since every predecessor
 * is guaranteed to already exist and be fully lifted.
 *
 * Deliberately does NOT perform trivial-phi pruning (collapsing a phi
 * with only one distinct non-self operand into that operand directly)
 * -- this produces correct but not minimal SSA. Phase 4 prioritises
 * construction correctness over minimality; a later cleanup pass can
 * prune trivial phis if a future phase's analysis benefits from it.
 *
 * Idempotent: a function with no remaining CIR_VAL_REG_ENTRY operands
 * (e.g. calling this twice) is a safe no-op.
 */
cbae_err_t cbae_cir_construct_ssa(cbae_cir_function_t *func);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_SSA_H */
