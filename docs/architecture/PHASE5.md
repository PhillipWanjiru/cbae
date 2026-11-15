# Phase 5 — Dataflow Infrastructure

## Status: Complete — 29/29 tests passing (Debug and Release), 0 errors under Valgrind and under ASan + UBSan + LeakSanitizer

## Layer stack addition

```
cbae_dataflow   (dominators, post-dominators, dataflow engine, use-def chains,
     |           alias analysis, reaching stores, constant propagation, SSA verifier)
cbae_cir        (Phase 4: CIR, builder, lifter, SSA construction, verifier, serializer)
     |
cbae_disasm     (Phase 3: Capstone disassembly, CFG, call graph)
     |
cbae_loader     (Phase 2: binary_image, PE32+/ELF64 parsers)
     |
cbae_platform   (Phase 1: arena, hashmap, vector, string_pool, logging, error)
```

## What it provides

| Module | The question it answers | Main entry points |
|---|---|---|
| `dominator_tree.c/h` | Which blocks must run before this one? | `cbae_dom_tree_build`, `_idom`, `_dominates` (O(1)), `cbae_dom_frontier_compute` |
| `post_dominator_tree.c/h` | Which blocks must run after it? | `cbae_pdom_tree_build`, `_ipdom`, `_post_dominates` (O(1)) |
| `dataflow_engine.c/h` | Solve a forward or backward bit-vector style analysis to a fixed point | `cbae_dataflow_run` with four callbacks (`init_value`, `meet`, `transfer`, `equals`) |
| `use_def.c/h` | Where is this value used? Which block and position holds this instruction? | `cbae_use_def_build`, `_uses`, `_block_of`, `_pos_of` |
| `alias_analysis.c/h` | Do these two memory accesses overlap: never (NO), identically (MUST), unknown (MAY)? | `cbae_alias_ctx_build`, `cbae_alias_query` |
| `reaching_stores.c/h` | Which writes may supply the bytes this load reads? Is the load just its store's value? | `cbae_reaching_stores_build`, `_for_load`, `_forwardable`, `_may_reach` |
| `const_prop.c/h` | Is this value always the same number? Can control ever reach this block? | `cbae_const_prop_run`, `_value`, `_block_executable`, `_edge_executable` |
| `ssa_verifier.c/h` | Is every use of a value dominated by its definition? | `cbae_ssa_verify_function` |

Internal to the library (`src/dataflow/`, not in `include/`): `dom_core.c` (the one dominator
implementation), `graph_scc.c` (iterative Tarjan), `cfg_graph.c` (a CIR function's CFG as CSR
adjacency).

Every analysis after `use_def` takes the same `const cbae_use_def_t *` index and borrows it, so
the index is built once per function and the caller keeps it alive.

## Decisions made explicit

**1. Cooper-Harvey-Kennedy dominators, not Lengauer-Tarjan.** `PHASE4.md` anticipated
Lengauer-Tarjan. The analyses here run on one function's CFG at a time (a few hundred blocks at
most), where the O(n²) worst case of the iterative algorithm never shows and Lengauer-Tarjan's
link-eval forest is one of the easiest algorithms to mis-code. CHK is short enough to check line
by line, and its output is compared with a brute-force definition in the tests.

**2. One dominator implementation.** `dom_core.c` serves the dominator tree, the post-dominator
tree (dominance on the reversed CFG, rooted at a virtual exit) and the SSA verifier (dominance on
the reachable part of a possibly broken function). A bug can live in one place, and the
cross-checks cover all three.

**3. Sound, or say "don't know".** Each analysis claims something only when it can prove it:
alias NO and MUST are claims and everything else is MAY; reaching stores classifies opcodes
default-deny (an opcode it does not know is a barrier that may write anything); constant
propagation never reports a constant it cannot prove at the value's own width. A new opcode
therefore makes answers less precise, never wrong. Every claim is checked against real executions
(see below).

**4. The verifier is not the analysis.** The production dominator tree refuses a function with a
block the entry cannot reach, because such a block has no dominator. That is right for an
analysis and wrong for a verifier, whose job is to look at functions that may be broken. The SSA
verifier therefore computes dominance for itself, over the reachable blocks only, with the shared
core.

**5. Code the entry cannot reach is exempt, not a loophole.** Every use inside such a block is
exempt from the dominance rule (as in LLVM's verifier), and so is a phi incoming from an
unreachable predecessor. The converse is not exempt: a value defined in unreachable code and used
from reachable code has no execution that defines it, and is reported.

## Changes to earlier phases' code

- `cir_verifier.c` rewritten (A-022). The Phase 4 verifier had never been run on a bad function
  and was weaker than its documentation. It now applies seven rules in linear time, each with a
  negative test: block slots, ids and the entry's predecessors; value and instruction ids;
  operand slots; results; phi shape and position; branch targets; edges recorded once on both
  sides. See the top of `cir_verifier.c` for the list and the order they are checked in.
- `cir_ssa_constructor.c`, one bug (A-023): the constructor counted a block's instructions once
  and then walked that many positions, but resolving a read in a join block inserts phis at the
  front of the same block, so its last instructions slid past the end of the walk and kept
  unresolved placeholders. 13 of 40 functions compiled by gcc came out wrong; no hand-assembled
  test had an unresolved read among the last instructions of a join block.
- `pe_loader.c` (Phase 2), alignment (A-028): the import, export and relocation tables, the import
  hint and the PE signature were read through pointers cast into the mapped file, which need not be
  aligned for their type; the reads are now `memcpy`-based (`rd16`, `rd32`, `rd64`) and nothing else
  about the loader changed. Found by the ASan + UBSan run of the whole suite.
- `instruction_lifter.c` (Phase 3) and `cir_serializer.c` (Phase 4), A-011: `strncpy` replaced by
  `snprintf` at the two sites gcc warned about in the Release build. The destination was already
  zeroed, so the bytes written are the same; the Release build now has no warnings.

## What testing found

Every one of these was invisible to the example-based tests that existed when the code was
written.

| ID | Defect | Found by | Pinned by |
|---|---|---|---|
| A-015 | a narrow constant folded as its int64 field | random soundness test, seed 4 | `t_narrow_constants` |
| A-016 | a phi narrower than 64 bits resolved to its incoming form | random soundness test, seed 11 | `t_narrow_phi` |
| A-017 | `ecx*4 - edx*4` cancelled: all narrow registers are one SSA value (A-002) | random soundness test, seed 16, after the generator learnt the lifter's conflation | `t_other_conflation` |
| A-020 | reaching stores answered for blocks it had documented as empty | a surviving mutant that only an unreachable block could expose | `t_unreachable` |
| A-021 | constant propagation's result depended on evaluation order (BOTTOM tested before TOP) | the order-reversed reference solver | `t_order_independence` |
| A-022 | the structural verifier accepted functions with a predecessor on the entry, NULL slots, repeated ids, misplaced phis | writing its first negative tests | `test_cir_verifier.c` |
| A-023 | SSA construction left register reads unresolved at the end of a loop header | the SSA verifier run over gcc output | `t_loop_reads_several_live_in_registers`, `test_compiled_code.c` |
| A-028 | the PE loader read its tables through misaligned pointers | the ASan + UBSan run of the whole suite | `test_pe_loader` under UBSan |

The same run found three defects in tests (A-029): the new `test_compiled_code` evaluated every
analysis it built twice (its check macro used its condition twice) and leaked the first result;
`test_alias_soundness` computed `INT64_MAX + 1` in the code that forges wrong claims;
`test_pe_loader` stored through misaligned pointers. No library result was affected. A sanitizer
build of the whole suite is now part of the definition of done.

## How it was tested

1. **Hand-derived expectations.** Each test builds the function whose answer was worked out on
   paper first, so the construction is spelled out value by value.
2. **Brute-force oracles that share no code with the implementation.** Dominance is "B cannot be
   reached from the entry once A is removed"; post-dominance is the same towards the exits;
   strongly connected components use a transitive closure; the frontier uses its definition.
3. **A random valid-SSA program generator and a concrete interpreter** (`cir_random.h`). The
   alias, reaching-stores and constant-propagation claims are compared with what thousands of real
   executions do, and each soundness test also forges wrong claims that it must catch, which
   shows the check can fail.
4. **Differential fuzzing of the verifiers** against independent oracles: random edge lists, random
   phis, and random rewirings of random functions, comparing the verdict and the whole message.
5. **Compiled code.** `tests/unit/compiled_corpus.h` holds 32 distinct functions that gcc emitted
   for 8 small C functions at -O0, -O1, -O2, -O3 and -Os. `test_ssa_verifier` lifts each and
   verifies it; `test_compiled_code` runs every analysis on each and checks dominators,
   post-dominators and frontiers against the brute-force oracles, SSA dominance against the
   production dominator tree, and the use lists, alias symmetry, reaching-stores and
   constant-propagation invariants.
6. **Mutation testing** of the analyses and both verifiers: a mutant is a one-line change to the
   source (a bound moved by one, a check removed, an argument swapped), and a test suite that
   cannot tell it from the original is not testing that line. Mutants that survived were either
   explained (an equivalent mutant: a change that cannot alter any result) or answered with a new
   test.
7. **Valgrind `--leak-check=full` and an ASan + UBSan build** (`-fno-sanitize-recover=all`) on
   every test.

## Results

| Check | Result |
|---|---|
| ctest, Debug | 29/29 (15 from Phases 1 to 4, 14 from Phase 5) |
| ctest, Release | 29/29, no compiler warnings |
| Valgrind `--leak-check=full`, all 29 tests | exit 0 on every one: no errors, no leaks |
| ASan + UBSan + LeakSanitizer, all 29 tests | clean |
| Mutation, `alias_analysis.c` | 91 mutants, 89 killed, 2 equivalent |
| Mutation, `reaching_stores.c` | 61 mutants, 59 killed, 2 equivalent |
| Mutation, `const_prop.c` | 290 mutants, 256 killed by the tests, 16 more by a new test and the sanitizers, 1 dead line removed, 17 equivalent |
| Mutation, `cir_verifier.c` | 90 mutants, 84 killed (77 by the tests, 4 of them after new tests for gaps the campaign showed; 7 more only under the sanitizers: 3 out-of-bounds reads, 4 leaks), 6 equivalent |
| Mutation, `ssa_verifier.c` | 63 mutants, 56 killed (50 by the tests, 6 leaks only under the sanitizers), 7 equivalent |
| Soundness, alias analysis | 1,500 random functions, 6,000 runs, 134,354 memory accesses executed; 10,615 pairs seen overlapping (the analysis had said MAY for 7,707 and MUST for 2,908, never NO); every NO and MUST claim checked on the runs that exercised it (13,292 and 55,566 cases); 5 forged claims, each caught |
| Soundness, reaching stores | 1,500 random functions, 6,000 runs, 74,422 load executions and 464,089 bytes read; 4,542,972 raw dataflow checks; 5,026 forwarded executions; 9 forged claims, each caught |
| Soundness, constant propagation | 1,500 random functions, 6,000 runs (half with sign-extending narrow values), 1,079,980 definitions executed, 305,071 of them of values called constant; 137,208 edges taken, 28,276 of them out of folded branches; an order-reversed reference solver agreed on 157,856 values; 6 forged claims, each caught |
| Compiled code | 32 functions, 202 blocks, 1,506 dominance pairs and 1,506 post-dominance pairs against brute force, 1,224 uses, 857 alias pairs, 49 loads |

## What Phase 5 does not establish

**The analyses are sound for the CIR they are given. They cannot make that CIR faithful to the
machine code.** Running them on gcc's output shows the lifter's gaps plainly: of the 32 functions,
31 contain an instruction that is dropped, conflated or lifted wrongly (narrow registers, ALU and
compare instructions with a memory operand, instructions the lifter has no case for), and a
conditional jump whose flags were set in another block gets a made-up constant-true condition
that constant propagation then folds (A-024). `docs/audit/LEDGER.md` lists these findings (A-001
to A-008, A-018, A-024 to A-027) with the evidence. They are the work of the next step, a Phase 4.5
audit that comes before Phase 6.

Precision limits, where the answer is sound but less sharp than the truth, are P-001 to P-005 in
the ledger. The ones to know: an address built from a loop-carried value never compares equal to
another access to "the same" address; every call is a barrier with no summary; constant
propagation tracks one number per value (no ranges, no memory).

Neither verifier checks operand types, operand counts per opcode or that a block ends in a
terminator that agrees with its successor list (A-025).

## Files

| File | Responsibility |
|---|---|
| `include/dataflow/*.h`, `src/dataflow/*.c` | the modules in the table above; every header opens with the question, the definitions, the guarantees and the cost |
| `src/dataflow/dom_core.c/h` | CHK dominators on a CSR graph; reverse postorder; tree children and intervals |
| `src/dataflow/graph_scc.c/h` | iterative Tarjan; `graph_scc_on_cycle`; sink components for the post-dominator tree |
| `tests/unit/cir_random.h` | random valid-SSA generator and concrete interpreter, shared by the three soundness tests |
| `tests/unit/cir_test_util.h`, `lift_helpers.h`, `dom_reference.h` | hand-building small functions; raw bytes to SSA-form CIR; the brute-force dominator reference |
| `tests/unit/compiled_corpus.h` | gcc output as test data, with the source, the commands and the toolchain |
| `tests/unit/test_*.c` | one test program per module, plus `test_alias_soundness`, `test_reaching_soundness`, `test_const_prop_soundness`, `test_compiled_code`, `test_graph_scc` |
