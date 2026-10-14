/**
 * @file ssa_verifier.h
 * @brief SSA verification: every use of a value is dominated by its definition.
 *
 * cbae_cir_verify_function() (Phase 4) checks STRUCTURE: ids, operands that are
 * the function's own values, results that belong to their instructions, phis that
 * match the predecessor set, edges recorded on both sides. It cannot say whether a
 * value is available where it is used -- that needs the dominator relation, which
 * is Phase 5, and cir_verifier.h left it to this module. cbae_ssa_verify_function()
 * runs the structural check first and then these rules:
 *
 *   1. OPERAND  An operand defined by instruction D must be available at the
 *               using instruction U: D's block strictly dominates U's block,
 *               or D is in the same block and comes EARLIER (an instruction
 *               that uses its own result is a violation).
 *   2. PHI      A phi incoming (value v, predecessor block P) is a use at the
 *               END of P, not in the phi's own block: v's defining block must
 *               dominate P, and may BE P whatever the position. This is what
 *               lets a loop phi take a value defined later in the loop body.
 *   3. DEFINED  An instruction result that is used must have a definition to
 *               be available from: v->u.def_insn names an instruction whose
 *               result is v itself, and that instruction sits in a block of
 *               the function. (An instruction that was removed from its block,
 *               or replaced by one with a new result, leaves the old value
 *               behind for its users to find.)
 *   Constants and parameters are available from function entry everywhere.
 *
 * UNREACHABLE BLOCKS. Dominance is defined relative to the entry, so it says
 * nothing about code the entry cannot reach: every use in such a block is
 * exempt (vacuously dominated, as in LLVM's verifier), and so is a phi
 * incoming from an unreachable predecessor. The converse is NOT exempt: a
 * value DEFINED in an unreachable block and used in a reachable one has no
 * execution that defines it, and is reported. Reachability is that of the
 * recorded successor lists, which is also what the dominator tree uses.
 *
 * REPORTING. The first violation is reported, scanning blocks in id order,
 * instructions in block order, and within an instruction its operands (or its
 * phi incomings) in index order; the message starts "block<B> insn#<I>:". The
 * result has the same type as the structural verifier's, and a structural
 * failure is returned as is.
 *
 * COST: one use-def index, one dominator computation over the reachable
 * blocks and one scan of every operand -- no per-use graph search.
 */
#ifndef CBAE_SSA_VERIFIER_H
#define CBAE_SSA_VERIFIER_H

#include "cir/cir_function.h"
#include "cir/cir_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Structural check, then SSA dominance. `ok` is true only if both pass. A NULL
 *  function is reported as "null function". A function with no blocks passes.
 *  Never modifies `f`. */
cbae_cir_verify_result_t cbae_ssa_verify_function(const cbae_cir_function_t *f);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_SSA_VERIFIER_H */
