/**
 * @file dataflow_engine.h
 * @brief Generic iterative worklist dataflow solver over a CIR function's
 *        basic-block CFG, forward or backward.
 *
 * The engine owns ONLY the iteration scheme. Everything about the
 * analysis itself -- what a "value" is, how two values merge at a join,
 * what a block does to a value -- is supplied by the caller through
 * cbae_dataflow_ops_t. Values are opaque `void *`.
 *
 * EQUATIONS SOLVED
 *   FORWARD :  IN[b]  = meet( OUT[p]  for every predecessor p of b )
 *              OUT[b] = transfer( b, IN[b] )
 *   BACKWARD:  OUT[b] = meet( IN[s]   for every successor  s of b )
 *              IN[b]  = transfer( b, OUT[b] )
 *
 * BOUNDARY CONDITION
 *   A block with no predecessors (forward) or no successors (backward)
 *   has nothing to meet; its input is init_value() itself. meet() is
 *   NEVER called with fewer than two real operands.
 *
 *   init_value() therefore plays two roles at once -- the optimistic
 *   starting value of every block's transfer-side slot, AND the
 *   boundary value -- so it MUST be the identity element of meet()
 *   (the lattice top: the empty set for a union/"may" analysis).
 *   Analyses whose boundary differs from the meet identity (e.g.
 *   available expressions, where the entry boundary is "nothing
 *   available" but the optimistic start is "everything available") are
 *   outside this engine's contract. None of the Phase 5 analyses is of
 *   that kind.
 *
 * MEMORY MODEL
 *   Every value lives in the caller-supplied arena and is NEVER freed
 *   while the solver runs; each visit of a block allocates its meet and
 *   transfer results fresh. Values are IMMUTABLE once returned by a
 *   callback: the engine aliases one value into several slots (a block
 *   with a single predecessor shares that predecessor's OUT pointer as
 *   its own IN), so a callback must never modify an input in place.
 *   A callback that cannot allocate returns NULL; the solver then
 *   returns CBAE_ERR_OOM. Size the arena for
 *   (block visits) x (value size) -- the whole result is released by
 *   destroying/resetting the arena, so there is no per-result destroy
 *   function.
 *
 * TERMINATION
 *   Guaranteed when transfer() is monotone and the value lattice has
 *   finite height (every bitset analysis qualifies). As a guard against
 *   a caller that violates this, the solver aborts with
 *   CBAE_ERR_OVERFLOW after CBAE_DATAFLOW_VISIT_BUDGET_PER_BLOCK x
 *   block_count block visits instead of looping forever.
 *
 * ORDER
 *   Blocks are processed from a LIFO stack primed so that block 0 pops
 *   first (forward) or the highest block id pops first (backward), and
 *   re-queued whenever a value they depend on changes. The visit order
 *   affects only speed, never the result.
 */
#ifndef CBAE_DATAFLOW_ENGINE_H
#define CBAE_DATAFLOW_ENGINE_H

#include "cir/cir_function.h"
#include "cbae/cbae_error.h"
#include "platform/memory.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Safety valve, see TERMINATION above. */
#define CBAE_DATAFLOW_VISIT_BUDGET_PER_BLOCK 65536u

typedef enum cbae_dataflow_direction {
    CBAE_DATAFLOW_FORWARD,
    CBAE_DATAFLOW_BACKWARD
} cbae_dataflow_direction_t;

typedef struct cbae_dataflow_ops {
    /** The meet identity; also the boundary value (see above).
     *  Returns NULL only on allocation failure. */
    void *(*init_value)(cbae_arena_t *arena, void *userdata);

    /** Combine two values at a join point into a NEW value. Must be
     *  commutative, associative and idempotent. Must not modify a or b.
     *  Returns NULL only on allocation failure. */
    void *(*meet)(cbae_arena_t *arena, void *a, void *b, void *userdata);

    /** The block's effect: given IN (forward) or OUT (backward), return
     *  the block's OUT (forward) or IN (backward) as a NEW value. Must
     *  be monotone. Must not modify `in_or_out`.
     *  Returns NULL only on allocation failure. */
    void *(*transfer)(cbae_arena_t *arena, uint32_t block_id,
                      void *in_or_out, void *userdata);

    /** True if the two values are semantically equal (not merely the
     *  same pointer). Drives the fixed-point test. */
    bool (*equals)(void *a, void *b, void *userdata);
} cbae_dataflow_ops_t;

/** Per-block fixed-point values, indexed by block id. Arrays and the
 *  values they point to are arena-owned. Every entry is non-NULL on
 *  CBAE_OK return. */
typedef struct cbae_dataflow_result {
    uint32_t block_count;
    void   **in_values;     /* [block_id] -> value at block entry */
    void   **out_values;    /* [block_id] -> value at block exit  */
} cbae_dataflow_result_t;

/** Solve the analysis described by `ops` over `func` to a fixed point.
 *  All blocks are processed, including any not reachable from entry.
 *  `userdata` is passed verbatim to every callback. */
cbae_err_t cbae_dataflow_run(const cbae_cir_function_t *func,
                             cbae_dataflow_direction_t direction,
                             const cbae_dataflow_ops_t *ops,
                             void *userdata,
                             cbae_arena_t *arena,
                             cbae_dataflow_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DATAFLOW_ENGINE_H */
