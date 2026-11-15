/**
 * @file const_prop.h
 * @brief Constant propagation over SSA: which values are the same number every
 *        time they are computed, and which blocks execution can reach once
 *        branches on constant conditions are resolved (sparse conditional
 *        constant propagation, without memory or ranges).
 *
 * THE QUESTION
 *   For an SSA value: is it, on every execution that defines it, one particular
 *   number? Which? And can control ever reach the block that defines it?
 *
 * LATTICE, per value
 *   UNREACHED   top      no execution from the entry ever defines it (the block that
 *                        defines it cannot be entered)
 *   CONSTANT c           every time it is defined it equals c; c is held at the value's
 *                        own width, zero-extended (0 .. 2^width - 1). A signed reading
 *                        is the caller's: sign-extend from cir_type_bits().
 *   VARYING     bottom   anything else, including "not known"
 *   Parameters are VARYING (including the lifter's conflated register "other"),
 *   constants are CONSTANT, an instruction result starts UNREACHED and falls.
 *
 * WHAT FOLDS (every other instruction with a result is VARYING)
 *   ADD SUB MUL AND OR XOR NOT NEG   when no operand is narrower than the result.
 *                        The low bits of these depend only on the low bits of the
 *                        operands, so how a narrow operand might be extended does not
 *                        matter; the result is computed at 64 bits and truncated.
 *   COPY                 when the operand is at least as wide as the result (a
 *                        truncation or a plain copy).
 *   SHL SHR SAR          only at 64 bits: result and shifted value 64 bits wide, the
 *                        count at least 8 bits wide; the count is taken modulo 64.
 *   PHI                  the meet over the incoming edges that can execute; an
 *                        incoming value narrower than the phi makes it VARYING.
 *   Also, whatever the other operand is (even VARYING or not yet known):
 *       x XOR x, x SUB x  (the same SSA value twice, unless it is "other")  -> 0
 *       x AND 0, x MUL 0                                                    -> 0
 *       x OR all-ones (at the result's width)                               -> all-ones
 *       0 SHL/SHR/SAR n                                                     -> 0
 *   "other" is excluded from the first rule because every read of it may be a
 *   different number (alias_analysis.h, A-017): `ecx - edx` lifted to
 *   other - other is not zero.
 *
 * WHAT IS NEVER FOLDED, and why
 *   Mixed widths. CIR does not say how a narrow value is extended when it feeds a
 *   wider operation (zero? sign? unspecified high bits?), so an operation that needs
 *   such an extension has no value this pass can claim; the test interpreter runs it
 *   under both readings (zero and sign) and the claims must hold under both.
 *   CMP, TEST. The condition code is not recorded in CIR, so the result is an
 *   unknown bit even when both operands are known; a branch on a comparison never
 *   folds. Only a condition built from constants does (a constant i1, or e.g.
 *   AND(cmp, 0)).
 *   LOAD, CALL, API_CALL, DIV, LEA, every Phase 6 opcode: VARYING. Memory is not
 *   modelled here; a pass that wants "the constant a store left in a stack slot"
 *   asks reaching_stores.h for the store and this pass for the stored value, and
 *   decides whether the address can be device memory (a load from MMIO is not
 *   what was stored).
 *
 * WHAT THIS IS NOT: value-set analysis (VSA)
 *   One number per value, no more. "Either 0x10 or 0x20" (a phi of two constants),
 *   an index known to be below a bound, a strided interval, a pointer known to be
 *   "base + something in [0, 64)" are all VARYING here. Those need a value-set
 *   domain (and, for bounds, comparisons that carry their predicate, which CIR does
 *   not yet record); a jump table's size cannot be recovered from this pass. The
 *   gap is deliberate: a constant is the one fact every later pass can rely on
 *   without a domain of its own.
 *
 * CONDITIONAL PART
 *   A BRANCH whose condition is an i1 CONSTANT executes only the selected edge;
 *   an UNREACHED condition (not yet known) executes none yet; any other executes
 *   both. A block ends in JUMP, in a call's fallthrough, or in RETURN: every
 *   successor edge executes. Only the LAST instruction of a block is a terminator.
 *   A block no executable edge enters is not executable and its values are UNREACHED.
 *   The conditional part is what makes a phi ignore an incoming value from an edge
 *   that cannot be taken.
 *   LIFTED CODE: the lifter does not record which flags a Jcc tests, and where no
 *   CMP/TEST precedes the Jcc in its own block (the second branch of `cmp; je; jg`)
 *   it makes up the constant true as the condition. This pass then takes that at
 *   its word and folds the branch: on gcc's `sw` at -O1 it reports two blocks that
 *   can run as not executable (tests/unit/test_compiled_code.c; audit ledger A-024).
 *   The pass is right about the CIR it is given; "not executable" on lifted code is
 *   not to be trusted until the lifter models flags and records predicates.
 *
 * SOUNDNESS CLAIM (checked against real executions by test_const_prop_soundness)
 *   For every execution: an instruction that defines a value the analysis calls
 *   CONSTANT c defines exactly c every time; no instruction defines a value called
 *   UNREACHED; control never enters a block, or takes an edge, that is called not
 *   executable. The claim assumes valid SSA (every use dominated by its definition,
 *   ssa_verifier.h): in invalid code a value can stay UNREACHED although it is used.
 *
 * COST
 *   Each value falls at most twice (UNREACHED -> CONSTANT -> VARYING) and every fall
 *   revisits the value's users: linear in instructions plus uses. Heap arrays of
 *   one byte and one word per value, one byte per block and edge slot.
 *
 * OWNERSHIP
 *   The result borrows the use-def index, which must outlive it, and owns its
 *   arrays; release with cbae_const_prop_destroy().
 */
#ifndef CBAE_CONST_PROP_H
#define CBAE_CONST_PROP_H

#include "dataflow/use_def.h"
#include "cbae/cbae_error.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_cp_kind {
    CBAE_CP_UNREACHED = 0,
    CBAE_CP_CONSTANT,
    CBAE_CP_VARYING
} cbae_cp_kind_t;

typedef struct cbae_cp_value {
    cbae_cp_kind_t kind;
    uint64_t       value;      /* CONSTANT only: at the value's own width, zero-extended; else 0 */
} cbae_cp_value_t;

struct cbae_cp_impl;

typedef struct cbae_const_prop {
    const cbae_use_def_t *ud;          /* borrowed */
    struct cbae_cp_impl  *impl;        /* private  */
} cbae_const_prop_t;

/** Run the analysis on the function indexed by `ud` (valid SSA assumed).
 *  CBAE_ERR_INVALID for null arguments or a function without blocks,
 *  CBAE_ERR_OOM on allocation failure. On failure `out` holds nothing to destroy. */
cbae_err_t cbae_const_prop_run(const cbae_use_def_t *ud, cbae_const_prop_t *out);
void       cbae_const_prop_destroy(cbae_const_prop_t *cp);

/** The lattice value of `v`. A constant or parameter is answered directly; a value
 *  that is not an instruction result of the indexed function is VARYING. */
cbae_cp_value_t cbae_const_prop_value(const cbae_const_prop_t *cp, const cbae_cir_value_t *v);

/** True and *out = the constant if `v` is CONSTANT. `out` may be NULL. */
bool cbae_const_prop_is_constant(const cbae_const_prop_t *cp, const cbae_cir_value_t *v, uint64_t *out);

/** Can control reach block `block_id`? False for an unknown block id. */
bool cbae_const_prop_block_executable(const cbae_const_prop_t *cp, uint32_t block_id);

/** Can control go from block `from` to block `to`? False unless `to` is one of
 *  `from`'s successors, `from` is executable, and the edge is not folded away. */
bool cbae_const_prop_edge_executable(const cbae_const_prop_t *cp, uint32_t from, uint32_t to);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CONST_PROP_H */
