/**
 * @file cir_opcodes.h
 * @brief The complete CIR operation vocabulary. Read this file before
 *        touching any lifter or analysis pass -- everything downstream
 *        is built on what this enum can express.
 *
 * TWO TIERS, ONE ENUM:
 *
 *   SYNTACTIC opcodes (LOAD, STORE, ADD, CALL, BRANCH, ...) are what
 *   Phase 4's lifter actually emits. They are directly derivable from
 *   an x86-64 instruction's own bytes -- no cross-referencing needed.
 *
 *   SEMANTIC opcodes (DMA_ALLOC, IRQ_REGISTER, SPINLOCK_ACQUIRE, ...)
 *   describe driver-domain hardware operations. Phase 4's lifter NEVER
 *   emits these directly -- it cannot know from a `call` instruction's
 *   bytes alone that the callee is a DMA allocator. They exist here so
 *   the type system can express the end state; Phase 6's API
 *   recognition pass is what actually rewrites a CIR_OP_CALL node
 *   (seeded with a resolved name like "ExAllocatePoolWithTag" by
 *   cir_lifter_call.c) into the matching semantic opcode once it
 *   pattern-matches that name against the kernel API database.
 *
 * This split is deliberate: a lifter that "guesses" semantics from
 * syntax alone would be unreliable. A lifter that only records what
 * is structurally true, leaving semantic labeling to a dedicated later
 * pass with its own database and confidence scoring, is both more
 * honest and more correct.
 */
#ifndef CBAE_CIR_OPCODES_H
#define CBAE_CIR_OPCODES_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_cir_opcode {
    CIR_OP_INVALID = 0,

    /* ── Memory operations ──────────────────────────────────────────── */
    CIR_OP_LOAD,             /* generic memory load                       */
    CIR_OP_STORE,            /* generic memory store                      */
    CIR_OP_LEA,              /* address computation, no memory access     */
    CIR_OP_MMIO_READ,        /* memory-mapped I/O register read  (Ph6)    */
    CIR_OP_MMIO_WRITE,       /* memory-mapped I/O register write (Ph6)    */

    /* ── I/O port & MSR operations (syntactically unambiguous) ───────── */
    CIR_OP_PORT_READ,        /* IN                                        */
    CIR_OP_PORT_WRITE,       /* OUT                                       */
    CIR_OP_MSR_READ,         /* RDMSR                                     */
    CIR_OP_MSR_WRITE,        /* WRMSR                                     */

    /* ── Arithmetic / logic ───────────────────────────────────────────── */
    CIR_OP_ADD, CIR_OP_SUB, CIR_OP_MUL, CIR_OP_DIV,
    CIR_OP_AND, CIR_OP_OR,  CIR_OP_XOR, CIR_OP_NOT, CIR_OP_NEG,
    CIR_OP_SHL, CIR_OP_SHR, CIR_OP_SAR,

    /* ── Comparison ────────────────────────────────────────────────────
     * Produce an i1-typed SSA result consumed directly by CIR_OP_BRANCH.
     * x86 EFLAGS is never modelled as a mutable "variable" in CIR --
     * every comparison result flows as an ordinary SSA value instead. */
    CIR_OP_CMP,
    CIR_OP_TEST,

    /* ── Data movement ─────────────────────────────────────────────────── */
    CIR_OP_COPY,             /* register-to-register move / SSA copy      */

    /* ── Control flow ──────────────────────────────────────────────────── */
    CIR_OP_BRANCH,           /* cond, true_block, false_block             */
    CIR_OP_JUMP,              /* unconditional jump to a block             */
    CIR_OP_CALL,               /* generic call, may carry a resolved name   */
    CIR_OP_RETURN,

    /* ── Stack ──────────────────────────────────────────────────────────── */
    CIR_OP_PUSH, CIR_OP_POP,

    /* ── SSA-specific ──────────────────────────────────────────────────── */
    CIR_OP_PHI,               /* SSA merge point at a join block           */

    /* ── Synchronization  (Phase 6 reclassification target) ─────────────── */
    CIR_OP_SPINLOCK_ACQUIRE,
    CIR_OP_SPINLOCK_RELEASE,
    CIR_OP_MUTEX_LOCK,
    CIR_OP_MUTEX_UNLOCK,
    CIR_OP_WAIT,

    /* ── Interrupt management  (Phase 6 reclassification target) ────────── */
    CIR_OP_IRQ_REGISTER,
    CIR_OP_IRQ_UNREGISTER,
    CIR_OP_IRQ_HANDLER_ENTRY,
    CIR_OP_IRQ_HANDLER_EXIT,
    CIR_OP_DPC_CALL,

    /* ── DMA management  (Phase 6 reclassification target) ──────────────── */
    CIR_OP_DMA_ALLOC,
    CIR_OP_DMA_FREE,
    CIR_OP_DMA_MAP,
    CIR_OP_DMA_SYNC,

    /* ── PCI configuration space  (Phase 6 reclassification target) ─────── */
    CIR_OP_PCI_CONFIG_READ,
    CIR_OP_PCI_CONFIG_WRITE,

    /* ── Power management  (Phase 6 reclassification target) ────────────── */
    CIR_OP_POWER_STATE_ENTER,
    CIR_OP_POWER_STATE_EXIT,

    /* ── Kernel API fallback  (unrecognized call, post Phase 6 lookup) ───── */
    CIR_OP_API_CALL,

    CIR_OP_COUNT   /* sentinel -- total opcode count, not a real opcode   */
} cbae_cir_opcode_t;

/** Human-readable mnemonic for printing/debugging (e.g. "load", "phi"). */
const char *cbae_cir_opcode_str(cbae_cir_opcode_t op);

/** True for the syntactic opcodes Phase 4's lifter can emit directly. */
bool cbae_cir_opcode_is_syntactic(cbae_cir_opcode_t op);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_OPCODES_H */
