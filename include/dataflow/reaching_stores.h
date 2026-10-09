/**
 * @file reaching_stores.h
 * @brief Reaching stores: which writes can supply the bytes a LOAD reads.
 *
 * THE QUESTION
 *   For a LOAD, which earlier writes to memory may be the LAST writer of at
 *   least one byte the load reads, and may some of those bytes still hold the
 *   content they had when the function was entered ("initial" content)?
 *   Three things follow from the answer:
 *     - a load whose only reaching write is one STORE that writes exactly the
 *       bytes the load reads gets that store's value (store-to-load
 *       forwarding, cbae_reaching_stores_forwardable);
 *     - a load with no reaching write and no initial content is unreachable;
 *     - a load whose reaching set contains a CALL cannot be forwarded across
 *       it, and says so.
 *
 * DEFINITIONS
 *   A write to memory is one of two kinds of DEFINITION:
 *     STORE    a CIR_OP_STORE with an address and a value. It writes exactly
 *              cir_type_bytes(value type) bytes at that address.
 *     BARRIER  an instruction that may write memory in a way CIR does not
 *              describe. A barrier may write ANY bytes, or none.
 *   The classification is DEFAULT-DENY (cbae_rs_classify_opcode): the opcodes
 *   below are known never to write memory; every other opcode is a barrier
 *   unless it is a STORE. A new opcode therefore makes results less precise,
 *   never wrong.
 *       never write memory: LOAD LEA MMIO_READ PORT_READ MSR_READ
 *                           PCI_CONFIG_READ ADD SUB MUL DIV AND OR XOR NOT
 *                           NEG SHL SHR SAR CMP TEST COPY PHI BRANCH JUMP
 *                           RETURN
 *       barriers include:   CALL API_CALL PUSH POP MMIO_WRITE PORT_WRITE
 *                           MSR_WRITE PCI_CONFIG_WRITE and every Phase 6
 *                           semantic opcode (a port or MMIO write can start a
 *                           DMA transfer)
 *   A CIR_OP_STORE with a missing operand cannot be said to write anywhere in
 *   particular and is a barrier too.
 *
 * HOW IT WORKS
 *   1. RAW DATAFLOW. A forward may-analysis over the generic engine, one bit
 *      per definition ("this write may still be the last writer of some byte
 *      here"). A STORE KILLS an earlier store only when the alias analysis
 *      proves the two write IDENTICAL byte ranges on every execution (MUST).
 *      Nothing else kills anything: a partly overlapping store leaves part of
 *      the earlier store visible, and a barrier may not have touched the
 *      bytes, so both stay possible.
 *
 *   2. CLASSES. Accesses whose address is STABLE (alias_analysis.h) and whose
 *      (offset, atoms, size) are identical form a class: they touch the same
 *      bytes on every execution. Two more bits per class refine step 1 where
 *      raw bits would make forwarding useless in real code:
 *        E  "initial content is still possible"   set at entry, cleared by a
 *           store of the class
 *        F  "a barrier ran after the last store of the class" set by every
 *           barrier, cleared by a store of the class
 *      Without them `call f; mov [rsp+8],rax; mov rbx,[rsp+8]` would report
 *      the call as a possible writer of the bytes the store has just
 *      overwritten, and no value stored after a call could ever be
 *      forwarded.
 *
 *   3. QUERY (cbae_reaching_stores_for_load). Start from the solved set at the
 *      top of the load's block and walk the instructions before the load:
 *        - a store of the load's own class covers every byte the load reads,
 *          so everything before it is discarded (and initial content is gone);
 *        - a store is dropped when a later store of ITS class precedes the
 *          load in the same block;
 *        - a store the alias analysis proves disjoint (NO) is dropped;
 *        - a barrier from an earlier block is kept only if the F bit of the
 *          load's class is set, or the load has no class.
 *      The answer is in definition order (block id, then position).
 *
 *   4. REFINEMENT. The solved bits say "reaches along SOME path" and, for
 *      barriers, only "some barrier ran since the class's last store". When the
 *      load's class is stored to somewhere, a definition from an earlier block
 *      that can reach the load only by passing such a store is not the last
 *      writer of anything the load reads. So the query also walks BACKWARDS
 *      over the CFG from the load's block, stopping at stores of the load's
 *      class, and keeps only definitions the walk meets. For a load with a
 *      stable address a barrier is then in the answer exactly when some path
 *      from it to the load contains no store of the load's bytes. The walk is
 *      bounded by CBAE_RS_WALK_BUDGET; past it the query returns the unrefined
 *      set.
 *
 * WHAT IT DOES NOT DO (each makes answers less precise, never unsound)
 *   - A store of an earlier block is dropped when EVERY path from it to the load
 *     passes a store of the load's bytes, but the two tests (survives its own
 *     class's later stores; avoids the load's class's stores) look at different
 *     paths, so a store that escapes the first on one path and the second on
 *     another stays in the answer. Stores through pointers the analysis cannot
 *     compare with a stack slot (a parameter might point into the stack) stay in
 *     the reaching set of every later load of that slot, as they must.
 *   - A wider store that covers a narrower one does not kill it (containment
 *     is MAY in the alias analysis).
 *   - A CALL kills nothing and there are no callee summaries: any call is a
 *     barrier. Whether a call can reach a given object is a Phase 6 question.
 *   - Only the function's own instructions write. Another thread, an
 *     interrupt handler or a device (DMA) is not modelled, and neither is
 *     volatile access: a load from device memory returns whatever the device
 *     says, not what was stored. Phase 6 reclassifies MMIO accesses; until
 *     then a caller must not forward values on addresses that may be MMIO.
 *   - Initial content is the content at function entry, per class. A load
 *     with no class (unstable or unknown address) always reports it possible.
 *   - Blocks not reachable from the entry have empty answers, and what they
 *     write reaches nothing (it is not carried into the blocks they branch to).
 *   - Results inherit the fidelity of the CIR (alias_analysis.h): every
 *     lifted access is 64 bits wide whatever the machine access was.
 *
 * SOUNDNESS CLAIM (checked against real executions by test_reaching_soundness)
 *   For every execution, every dynamic LOAD and every byte it reads: if that
 *   byte was last written by instruction w, then w is in the load's reaching
 *   set; if it was never written, may_be_initial is true. Independently, at
 *   every instruction, every instruction that is the last writer of any byte
 *   satisfies cbae_reaching_stores_may_reach.
 *
 * COST AND LIMITS
 *   State is one bit vector per block of (definitions + classes) bits. A
 *   function whose block count times bit count exceeds
 *   CBAE_RS_MAX_STATE_BITS is rejected with CBAE_ERR_OVERFLOW; callers treat
 *   that as "everything may reach". A query costs the instructions before the
 *   load in its block plus one pass over the block's state, plus, when it
 *   refines, at most CBAE_RS_WALK_BUDGET steps.
 *
 * OWNERSHIP
 *   The result borrows the use-def index and the alias context, which must
 *   outlive it, and owns its arrays; release with cbae_reaching_stores_destroy().
 *   Pointers it hands out stay valid until then.
 */
#ifndef CBAE_REACHING_STORES_H
#define CBAE_REACHING_STORES_H

#include "dataflow/alias_analysis.h"
#include "dataflow/use_def.h"
#include "cir/cir_opcodes.h"
#include "cbae/cbae_error.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Upper bound on (block count) x (bits per block state). Beyond it the
 *  analysis returns CBAE_ERR_OVERFLOW rather than allocate without limit. */
#define CBAE_RS_MAX_STATE_BITS (1u << 27)

/** Work limit of the refining walk in cbae_reaching_stores_for_load: blocks
 *  and definitions visited, per query. Past it the query returns the
 *  unrefined (still sound) set. */
#define CBAE_RS_WALK_BUDGET (1u << 16)

/** What an opcode does to memory. */
typedef enum cbae_rs_opclass {
    CBAE_RS_OP_READONLY = 0,   /* never writes memory                                  */
    CBAE_RS_OP_STORE,          /* CIR_OP_STORE: writes a known range if well formed    */
    CBAE_RS_OP_BARRIER         /* may write memory in a way CIR does not describe      */
} cbae_rs_opclass_t;

/** Default-deny: only the opcodes listed in the file comment are READONLY. */
cbae_rs_opclass_t cbae_rs_classify_opcode(cbae_cir_opcode_t op);

/** One write to memory. */
typedef struct cbae_rs_def {
    const cbae_cir_instruction_t *insn;
    uint32_t                      block_id;    /* block that contains insn            */
    bool                          is_barrier;  /* false: a STORE with address+value   */
} cbae_rs_def_t;

struct cbae_rs_impl;

typedef struct cbae_reaching_stores {
    const cbae_use_def_t   *ud;                /* borrowed                            */
    const cbae_alias_ctx_t *alias;             /* borrowed                            */
    struct cbae_rs_impl    *impl;              /* private                             */
} cbae_reaching_stores_t;

/** Solve reaching stores for the function indexed by `ud`. `alias` must have
 *  been built from the same `ud`. Fails with CBAE_ERR_INVALID for null or
 *  mismatched arguments or a function without blocks, CBAE_ERR_OVERFLOW if
 *  the state would exceed CBAE_RS_MAX_STATE_BITS, CBAE_ERR_OOM on allocation
 *  failure. On failure `out` holds nothing to destroy. */
cbae_err_t cbae_reaching_stores_build(const cbae_use_def_t *ud,
                                      const cbae_alias_ctx_t *alias,
                                      cbae_reaching_stores_t *out);
void       cbae_reaching_stores_destroy(cbae_reaching_stores_t *rs);

/** The definitions, numbered by block id and then position in the block. */
uint32_t             cbae_reaching_stores_def_count(const cbae_reaching_stores_t *rs);
const cbae_rs_def_t *cbae_reaching_stores_def(const cbae_reaching_stores_t *rs, uint32_t index);

/** The definition `insn` is, or NULL if it is not a write to memory (or is not
 *  an instruction of the indexed function). */
const cbae_rs_def_t *cbae_reaching_stores_def_of(const cbae_reaching_stores_t *rs,
                                                 const cbae_cir_instruction_t *insn);

/** The writes that may be the last writer of a byte `load` reads, in
 *  definition order. At most `capacity` pointers are stored in `out` (which
 *  may be NULL when capacity is 0); *count receives the TOTAL, which may
 *  exceed capacity. *may_be_initial receives whether some byte read may still
 *  hold its function-entry content. Either output pointer may be NULL.
 *  A load that no path from entry reaches gets count 0 and false.
 *  CBAE_ERR_INVALID if `load` is not a LOAD of the indexed function,
 *  CBAE_ERR_OOM if the query's scratch space cannot be allocated. */
cbae_err_t cbae_reaching_stores_for_load(const cbae_reaching_stores_t *rs,
                                         const cbae_cir_instruction_t *load,
                                         const cbae_rs_def_t **out, uint32_t capacity,
                                         uint32_t *count, bool *may_be_initial);

/** True if `load` reads exactly the bytes one STORE wrote and nothing else
 *  can have changed them: the reaching set is that single store, the two
 *  ranges are identical (alias MUST), and initial content is impossible.
 *  Then the load's value is the stored value, bit for bit. *store receives
 *  the store (may be NULL). False on any error or doubt. */
bool cbae_reaching_stores_forwardable(const cbae_reaching_stores_t *rs,
                                      const cbae_cir_instruction_t *load,
                                      const cbae_cir_instruction_t **store);

/** The raw dataflow fact: may `def` still be the last writer of some byte at
 *  the point just BEFORE `at` executes? `def` must be a write to memory (see
 *  cbae_reaching_stores_def_of); false otherwise, and false when no path from
 *  the entry reaches `at`. Useful to any pass that needs the unrefined result;
 *  for_load is the precise one for loads. */
bool cbae_reaching_stores_may_reach(const cbae_reaching_stores_t *rs,
                                    const cbae_cir_instruction_t *at,
                                    const cbae_cir_instruction_t *def);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_REACHING_STORES_H */
