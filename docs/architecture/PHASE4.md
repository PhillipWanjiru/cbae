# Phase 4 — CIR Design & Lifting

## Status: Complete — 15/15 tests passing, 0 memory errors under Valgrind

## Layer stack addition

```
cbae_cir        (CIR type system, builder, lifter, SSA construction, verifier, serializer)
     |
cbae_disasm     (Phase 3: Capstone disassembly, CFG, call graph)
     |
cbae_loader     (Phase 2: binary_image, PE32+/ELF64 parsers)
     |
cbae_platform   (Phase 1: arena, hashmap, vector, string_pool, logging, error)
```

## Two architectural decisions made explicit before any code was written

**1. Syntactic lifting now, semantic reclassification later.** `cir_opcodes.h`
defines ~50 opcodes in two tiers: syntactic opcodes (LOAD, STORE, ADD, CALL,
BRANCH, ...) that the lifter emits directly from instruction bytes, and
semantic opcodes (DMA_ALLOC, IRQ_REGISTER, SPINLOCK_ACQUIRE, ...) that exist
in the type system for Phase 6's API recognition pass to rewrite a
`CIR_OP_CALL` into, once it pattern-matches a resolved name against the
kernel API database. The lifter never guesses semantics from syntax alone.

**2. Braun et al. SSA construction, not Cytron + dominance frontiers.**
Building a throwaway dominator-tree implementation just to bootstrap SSA
in Phase 4 would have been wasted work duplicating Phase 5's real
`dominator_tree.c` (Lengauer-Tarjan). Braun, Buchwald, Hack et al.'s 2013
algorithm builds SSA directly via recursive value lookup with lazy phi
creation and cycle-breaking memoization — no separate dominance pass
needed. Simplified further here because CBAE's CFG is always fully built
before SSA construction runs (no "sealed/unsealed block" bookkeeping from
the original incremental-construction design is needed).

## The bug that mattered most in this phase

Splitting lifting (Stage 3, producing non-SSA CIR with `CIR_VAL_REG_ENTRY`
placeholders for cross-block reads) from SSA construction (Stage 4, a
post-hoc resolution pass) loses information a single interleaved pass
would naturally have: **"what should a placeholder created within this
block resolve to" and "what does this block contribute to a successor's
phi" are different questions.** The first must never look at the block's
own writes (the placeholder exists precisely because none had happened
yet at that point); the second must always check them first. Conflating
these into one function produces a loop induction variable's phi that
resolves to itself instead of to the loop body's actual computation —
structurally plausible, silently wrong SSA.

This was caught by hand-tracing a loop scenario byte-by-byte *before*
writing `test_ssa_construction.c`, not by a failing test. The fix:

- `cbae_cir_block_t` gained `final_reg_state[]`, persisting each block's
  ending register values (what the lifter's per-block `reg_map` held at
  the end of lifting that block).
- `cir_ssa_constructor.c` splits into two functions: `resolve_entry_value`
  (never checks `final_reg_state`, goes straight to predecessor logic)
  and `read_predecessor_value` (checks `final_reg_state` *before* the
  cycle-breaking memoization cache, since a real local write can never
  itself be part of an unresolved cycle).

A second, related gap surfaced from the same reasoning: the lifter only
created CIR-level block edges when dispatching JCC/JMP instructions —
CALL-ending blocks and blocks ending via pure structural convergence
(Phase 3's mid-block split, with no branch instruction at the transition
point at all) never got their edges created, which would have silently
broken predecessor tracking for exactly the loop test's entry block.
Fixed by making `cbae_cir_block_add_edge` idempotent and adding a
dispatcher-level sweep that uniformly covers every case.

Verified correct via the printed CIR for a real loop:
```
%v7 = phi i64 [0, block0], [%v4, block2]
%v4 = add i64 %v7, 1
```
— the phi correctly merges the entry constant with `add`'s actual
result from the back edge, never referencing itself.

## Components

| File | Responsibility |
|---|---|
| `cir_opcodes.c/h` | ~50-opcode vocabulary, syntactic/semantic split |
| `cir_type.c/h` | Minimal int-width + pointer type system |
| `cir_value/instruction/block/function/module.h` | SSA data model |
| `cir_builder.c/h` | Programmatic construction API; arena-backed growable instruction arrays |
| `cir_lifter.c` + `cir_lifter_internal.h` | Dispatcher, shared register-map helpers, operand-to-CIR-value conversion (including correct RIP-relative math) |
| `cir_lifter_memory.c` | MOV/LEA/PUSH/POP; reg-to-reg moves emit no instruction (idiomatic SSA) |
| `cir_lifter_io.c` | IN/OUT/RDMSR/WRMSR — syntactically unambiguous |
| `cir_lifter_call.c` | CALL with name seeded from Phase 3's call graph; honestly does not guess argument count |
| `cir_lifter_arithmetic.c` | ADD/SUB/.../CMP/TEST; CMP-to-BRANCH relay via a reserved reg_map slot |
| `cir_lifter_branch.c` | Jcc/JMP/RET, reusing Phase 3's already-computed successor edges |
| `cir_ssa_constructor.c` | Braun et al. SSA construction (see above) |
| `cir_printer.c/h` | Human-readable CIR dump |
| `cir_verifier.c/h` | Structural correctness (placeholder-free, phi/predecessor consistency, valid branch targets) — dominance verification deferred to Phase 5 |
| `cir_serializer.c/h` | Native-layout binary round-trip (three-pass deserialization for cross-referenced values/instructions/blocks) |

## Known, documented simplifications

- Every register tracked as a single 64-bit SSA variable — no sub-register
  (EAX vs RAX) aliasing precision. `CBAE_REG_OTHER` (Phase 3's catch-all
  for narrow register forms) is deliberately never cached/tracked, to
  avoid incorrectly aliasing unrelated narrow registers together.
- No trivial-phi pruning — produces correct but non-minimal SSA. A
  genuinely loop-invariant register (e.g. RSP, untouched inside a loop
  body) legitimately gets a self-referential phi; this is valid,
  expected output, not a bug (confirmed via the full-pipeline test's
  printed CIR).
- Call argument extraction deferred to Phase 6 (needs calling-convention
  + real signature awareness once an API is recognized).
