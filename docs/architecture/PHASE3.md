# Phase 3 — Disassembly & CFG

## Layer stack addition

```
cbae_disasm     (Capstone wrapper, CFG builder, call graph, function/SEH discovery)
     |
cbae_loader     (Phase 2: binary_image, PE32+/ELF64 parsers)
     |
cbae_platform   (Phase 1: arena, hashmap, vector, string_pool, logging, error)
```

## Components

| File | Responsibility |
|---|---|
| `disassembler.c` | Capstone engine lifecycle; single-instruction decode via `cs_disasm_iter` with a reusable scratch buffer |
| `instruction_lifter.c` | Capstone `cs_insn` → `cbae_instruction_t`; coarse instruction classification |
| `operand_decoder.c` | Capstone `cs_x86_op` → `cbae_operand_t`; register/immediate/memory operand bridging |
| `cfg_builder.c` | Recursive-descent CFG construction with mid-block splitting on convergence |
| `cfg_edge_classifier.c` | Fallthrough / branch-taken / back-edge classification |
| `call_graph_builder.c` | Scans CALL-ending blocks; direct, IAT-import, and unresolved-indirect classification |
| `indirect_call_resolver.c` | Single-block backward pattern matching to resolve `call reg` where the register was loaded by an immediately-preceding `mov reg,imm64` or `lea reg,[rip+disp]` |
| `function_boundary_finder.c` | Function discovery: entry point → symbol table → PE `.pdata` RUNTIME_FUNCTION table → prologue byte-pattern scan (in priority order) |
| `seh_handler_detector.c` | PE `.pdata` UNWIND_INFO flag parsing to detect `__try`/`__except` usage |

## Key design decisions

**Mid-block splitting via arena pointer-slicing.** When a later-processed
worklist entry targets an address strictly inside an already-built
block, `split_block_at()` creates a new tail block whose `instructions`
pointer is a slice into the SAME arena-backed array the original block
owns — no copying. Safe because arena memory never moves and is never
freed piecemeal.

**Reverse enqueue ordering.** Successors are enqueued in reverse storage
order so fallthrough targets (pushed last) pop first from the LIFO
worklist. This makes straight-line code get decoded before its branch
target is processed, which is what causes the split path above to
actually trigger on typical if/else convergence patterns.

**CALL always ends a basic block**, with a `CBAE_EDGE_CALL_RETURN`
successor to the return site — not folded into the caller's straight-line
flow. This gives a clean per-call-site block boundary for later CIR
lifting.

**Indirect call resolution is deliberately scoped** to single-block,
single-hop backward pattern matching. Full dataflow-based resolution
(cross-block constant propagation, WDF dispatch table modelling) is
explicitly deferred to Phase 5/6.

**`.pdata` RUNTIME_FUNCTION parsing is treated as ground truth**, not a
heuristic — every x86-64 Windows function with a non-trivial prologue
has a compiler-generated entry here, required for SEH/unwinding to work
at all. The prologue byte-scan (source 4) exists only to fill gaps for
leaf functions with no unwind data.

## Bug found during verification

`mov reg, imm64` (opcode `B8+r` with `REX.W`) decodes to Capstone's
distinct `X86_INS_MOVABS` instruction id, not `X86_INS_MOV`. The
instruction classifier's switch statement didn't originally account
for this — caught by an actual test run against the real installed
Capstone 4.0.2 library (both `test_disassembler` and
`test_indirect_resolver` failed identically, pointing at the same root
cause). Fixed by adding `X86_INS_MOVABS` to the `CBAE_ICLASS_MOV` case.
