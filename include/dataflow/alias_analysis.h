/**
 * @file alias_analysis.h
 * @brief Basic sound alias analysis for CIR memory accesses.
 *
 * THE QUESTION
 *   Given two memory accesses, each an address value plus a size in bytes,
 *   do the byte ranges they touch overlap?
 *
 *     CBAE_ALIAS_NO    the ranges are disjoint, on every execution
 *     CBAE_ALIAS_MUST  the ranges are identical (same start, same size), on
 *                      every execution
 *     CBAE_ALIAS_MAY   neither could be proved. This includes accesses that
 *                      certainly overlap without being identical (offset 0
 *                      size 8 against offset 4 size 8): "MAY" means "not
 *                      provably disjoint and not provably identical".
 *
 *   "On every execution" is meant literally: for every run of the function
 *   and every pair of dynamic executions of the two accesses, including two
 *   different iterations of one loop. NO and MUST are claims, and they are
 *   never made unless they can be proved; everything else is MAY.
 *
 * HOW IT WORKS
 *   1. DECOMPOSE. Each address value is rewritten as a linear form
 *
 *         offset + coeff0*atom0 + coeff1*atom1 + ...        (mod 2^64)
 *
 *      by expanding ADD, SUB, NEG, COPY, MUL by a constant and SHL by a
 *      constant. Arithmetic wraps at 64 bits exactly as address arithmetic
 *      does. An ATOM is a value that cannot be expanded further: a
 *      parameter, a load or call result, the result of any other opcode, an
 *      unresolved phi. Constants fold into the offset. Only 64-bit results
 *      are expanded; a narrower ADD wraps at its own width and is an atom.
 *
 *      The lifter emits [base + index*scale + disp] as
 *      ADD(ADD(base, MUL(index, scale)), disp) with a fresh MUL each time,
 *      so two accesses to the same element hold different SSA values that
 *      decompose to the same form. That is the point of working with forms.
 *
 *   2. COMPARE. Two accesses whose forms have the same atoms with the same
 *      coefficients differ by a CONSTANT, so their relationship follows from
 *      the two offsets and the two sizes alone. Anything else is MAY.
 *
 *   3. STABILITY. The cancellation in step 2 is only valid if each atom has
 *      ONE value for the whole activation. An SSA value is not that in
 *      general: a loop re-executes its definition, so two uses of the same
 *      SSA value in different iterations see different numbers (i+0 and i+8
 *      in iteration 1 and 2 collide). An atom is STABLE when it is
 *        - a parameter (other than the "other" register, see below), or
 *        - the result of an instruction in a block that lies on no CFG
 *          cycle, which therefore executes at most once per activation.
 *      If any atom of either form is unstable the answer is MAY, even for
 *      two uses of the very same SSA value.
 *
 *   4. REDUNDANT PHIS. The SSA constructor does not prune trivial phis, so
 *      a loop-invariant register such as a base pointer comes out as
 *      p = phi(p0, p), an atom that looks loop-variant but is just p0.
 *      Without help every access in every loop would be MAY. So at context
 *      build time each phi whose incoming values all have the same linear
 *      form F (ignoring incomings that are the phi itself) is recorded as
 *      equal to F, iterating to a fixed point so that nested loops and
 *      chains resolve. This is valid in dominance-correct SSA: the first
 *      time the phi runs it must take F, and afterwards it takes F or its
 *      own earlier value, which is F. An incoming that is the phi plus a
 *      non-zero constant (an induction variable) keeps the phi an atom.
 *
 * WHAT IT DOES NOT DO
 *   - No assumptions about the program: a pointer parameter may point into
 *     the stack, into a global, or at another pointer parameter's object.
 *     Different atoms are therefore MAY, and so is the stack against a
 *     global. There is no points-to analysis and no type information.
 *   - No loop reasoning: induction variables, loop-invariant (but not
 *     phi-copied) values and recurrences are unstable atoms, hence MAY.
 *   - Not flow-sensitive: it never asks what memory contains.
 *
 * PRECONDITIONS AND FIDELITY
 *   The function must be valid SSA: every use is dominated by its
 *   definition (see ssa_verifier.h). Results are sound with respect to the
 *   CIR as lifted. Where CIR is a loose model of the machine, the answers
 *   inherit that looseness (every access is 64 bits; segment overrides are
 *   dropped). One protection is built in: narrow registers all lift to the
 *   single parameter "other", which stands for many different registers, so
 *   it is never treated as a stable value.
 *
 * OWNERSHIP
 *   The context borrows the use-def index, which must outlive it. It owns
 *   its own arrays; release with cbae_alias_ctx_destroy().
 */
#ifndef CBAE_ALIAS_ANALYSIS_H
#define CBAE_ALIAS_ANALYSIS_H

#include "dataflow/use_def.h"
#include "cbae/cbae_error.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_alias_result {
    CBAE_ALIAS_NO   = 0,
    CBAE_ALIAS_MAY  = 1,
    CBAE_ALIAS_MUST = 2
} cbae_alias_result_t;

/** A size of 0 means "unknown size": every query involving it is MAY. */
#define CBAE_ALIAS_UNKNOWN_SIZE 0u

/** Accesses larger than this are not reasoned about (MAY). It keeps all
 *  range arithmetic comfortably inside 64 bits. */
#define CBAE_ALIAS_MAX_ACCESS_SIZE 0x40000000u

/** An address with more distinct atoms than this is treated as one opaque
 *  atom (itself), which is sound but compares equal to nothing else. */
#define CBAE_ALIAS_MAX_TERMS 4

/** Work limits. Reaching one never makes an answer wrong, only less precise:
 *  the value where expansion stopped simply becomes an atom, and a phi left
 *  unresolved is an atom too. They bound the cost of a hostile function.
 *    EXPAND_BUDGET   instructions visited while decomposing one address
 *    EXPAND_DEPTH    nesting depth of one expansion (an instruction at a
 *                    greater depth than this is not looked through)
 *    RESOLVE_PASSES  passes of redundant-phi resolution; real code needs about
 *                    the loop-nest depth */
#define CBAE_ALIAS_EXPAND_BUDGET   4096u
#define CBAE_ALIAS_EXPAND_DEPTH     512u
#define CBAE_ALIAS_RESOLVE_PASSES    32u

typedef struct cbae_addr_term {
    const cbae_cir_value_t *value;     /* an atom                                */
    int64_t                 coeff;     /* never 0                                */
} cbae_addr_term_t;

/** offset + sum(coeff_i * value_i), arithmetic mod 2^64. term_count == 0
 *  means an absolute address. Terms are sorted by value id. */
typedef struct cbae_addr_info {
    int64_t          offset;
    uint32_t         term_count;
    cbae_addr_term_t terms[CBAE_ALIAS_MAX_TERMS];
} cbae_addr_info_t;

typedef struct cbae_alias_ctx {
    const cbae_use_def_t *ud;              /* borrowed                          */
    uint32_t              block_count;
    bool                 *block_on_cycle;  /* [block_count]                     */

    /* Redundant-phi table (private to alias_analysis.c). */
    uint32_t                       phi_count;
    uint32_t                      *phi_slot_by_value;  /* [ud->value_count]     */
    const cbae_cir_instruction_t **phi_insn;           /* [phi_count]           */
    bool                          *phi_resolved;       /* [phi_count]           */
    cbae_addr_info_t              *phi_form;           /* [phi_count]           */
} cbae_alias_ctx_t;

/** Analyse the function indexed by `ud`: find which blocks lie on a CFG
 *  cycle and resolve redundant phis. */
cbae_err_t cbae_alias_ctx_build(const cbae_use_def_t *ud, cbae_alias_ctx_t *out);
void       cbae_alias_ctx_destroy(cbae_alias_ctx_t *ctx);

/** Linear form of an address value. Returns false (and a zeroed `out`) for
 *  NULL. Never otherwise fails: anything it cannot expand is an atom. */
bool cbae_alias_decompose(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *addr,
                          cbae_addr_info_t *out);

/** The query on already-decomposed addresses. */
cbae_alias_result_t cbae_alias_query_info(const cbae_alias_ctx_t *ctx,
                                          const cbae_addr_info_t *a, uint32_t size_a,
                                          const cbae_addr_info_t *b, uint32_t size_b);

/** Decompose both addresses and query. NULL addresses give MAY. */
cbae_alias_result_t cbae_alias_query(const cbae_alias_ctx_t *ctx,
                                     const cbae_cir_value_t *a, uint32_t size_a,
                                     const cbae_cir_value_t *b, uint32_t size_b);

/** True if `v` has a single value for the whole activation (see STABILITY). */
bool cbae_alias_value_is_stable(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *v);

/** True if `block_id` lies on a CFG cycle. */
bool cbae_alias_block_on_cycle(const cbae_alias_ctx_t *ctx, uint32_t block_id);

/** If `insn` is a LOAD or STORE: its address operand and access size in
 *  bytes (CBAE_ALIAS_UNKNOWN_SIZE if the accessed type has no size).
 *  Returns false for any other instruction. */
bool cbae_alias_mem_access(const cbae_cir_instruction_t *insn,
                           const cbae_cir_value_t **addr, uint32_t *size);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_ALIAS_ANALYSIS_H */
