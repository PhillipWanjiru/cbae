# CBAE audit ledger

Findings noted while building Phase 5, kept here so the Phase 4.5 audit starts
from a written list rather than from memory. Nothing in this file has been
fixed yet unless its status says so.

Severity: HIGH = wrong results for real driver code; MED = wrong or fragile in
some cases; LOW = hygiene. "Verified" means reproduced by running the code,
not only read.

## Findings

| ID | Where | Finding | Sev | Status |
|----|-------|---------|-----|--------|
| A-001 | Phase 4 lifter | ALU/CMP with a memory operand is lifted wrongly: `add rax,[rbx]` becomes `add rax,rbx`; `cmp [rbx+8],0` compares the address; `add [rbx],5` is dropped. Verified on printed CIR. | HIGH | open |
| A-002 | Phase 4 lifter | Narrow registers (eax/ax/al...) all map to `CBAE_REG_OTHER`: reads become the single parameter "other", writes are dropped. Verified. | HIGH | open |
| A-003 | Phase 4 lifter | Unmodeled instructions emit nothing, so results stay stale: adc, cmovcc, cqo/idiv, one-operand mul, xchg, ror, rep stos, lock xadd. Verified. | HIGH | open |
| A-004 | Phase 4 lifter | Three-operand `imul` is lifted wrongly. Verified. | MED | open |
| A-005 | Phase 4 lifter | `fs:`/`gs:` segment overrides are dropped (`gs:[0x188]` is how Windows x64 drivers reach the current thread). Verified. | HIGH | open |
| A-006 | Phase 4 lifter | Access widths are not modeled; every LOAD/STORE is i64. Vector and string moves wider than 8 bytes therefore look 8 bytes wide, which makes "no overlap" answers unsound for them. | HIGH | open |
| A-007 | Phase 4 lifter | CALL defines RAX but does not clobber the other volatile registers, so values survive calls they would not survive on the machine. | HIGH | open |
| A-008 | Phase 4 lifter | EFLAGS is never modeled and the Jcc condition code is not recorded: branch semantics are lost. | HIGH | open |
| A-009 | `cir_ssa_constructor.c:112-121` | `cbae_cir_phi_create()` result is used without a NULL check, and the `phi_add_incoming` and hashmap-insert results are ignored. When the function arena is spent the builder returns NULL (seen in a test), so SSA construction would dereference NULL instead of returning an error. | MED | open |
| A-010 | `cir_builder.c:272` | `cbae_cir_phi_create()` takes an instruction id before its allocations are checked; a failure leaves a gap and no rollback. | LOW | open |
| A-011 | Release build | `-Wstringop-truncation` at `src/disasm/instruction_lifter.c:77` and `src/cir/cir_serializer.c:102`: check for a missing terminating NUL. Both were false positives (the destination was zeroed first) but the code now says so: `snprintf` replaces `strncpy` at both sites, same bytes written. The Release build now has no warnings. | LOW | fixed (Phase 5) |
| A-012 | `cir_verifier.c` | Structural verifier does not check: block 0 has no predecessors; NULL operand slots; operand/result width agreement for binary ops. Dominance is not checked at all (the SSA verifier is a Phase 5 deliverable). Phase 5 closed the first two and added the dominance check (A-022, `ssa_verifier.c`); operand widths are still not checked (A-025). | MED | fixed (Phase 5) except widths (A-025) |
| A-013 | Arena sizing | Arenas have fixed capacity and return NULL when spent. Audit how the lifter and engine size a function's arena for large functions, and that exhaustion surfaces as an error everywhere, never as a crash (see A-009). | MED | open |
| A-014 | `alias_analysis.c` | Precision gap, not a bug: a cluster of phis that refer only to each other and are invariant as a group, with no phi referring to itself (possible with irreducible control flow), stays unresolved (MAY). | LOW | documented |
| A-015 | `alias_analysis.c` | Soundness bug in Phase 5 code: a narrow constant (i32 -1, an i16 70000 that does not fit its type) was folded as its int64 field. CIR does not define how a narrow value extends when it feeds a 64-bit operation. Found by `test_alias_soundness.c` on random function seed 4 (value defined 0x1170, form evaluated 0x11170). Fix: only 64-bit constants fold; a narrow constant is an opaque, stable atom. Regression test `t_narrow_constants`. | MED | fixed (Phase 5) |
| A-016 | `alias_analysis.c`, `cir_ssa_constructor.c:112` | Soundness bug in Phase 5 code: a phi narrower than 64 bits was resolved to its incoming form although it truncates its incomings. Found by the random test (seed 11). Fix: only 64-bit phis resolve. Regression test `t_narrow_phi`. Related fact for the audit: the SSA constructor makes every phi i64 whatever the widths of its incoming values. | MED | fixed (Phase 5); constructor behaviour open |
| A-017 | `alias_analysis.c` (root cause A-002) | Soundness bug in Phase 5 code: all narrow registers are one SSA value, `other`, so `ecx*4 - edx*4` cancelled to 0 and two different addresses were reported identical. Found by the random test (seed 16) after the generator learnt the lifter's conflation. Fix: an instruction that reads `other` is an atom (its result is one value per execution); a phi of `other` never resolves to it. Regression test `t_other_conflation`. Every later pass must treat `other` as unknown and never equal to itself. | HIGH | fixed in the analysis; root cause open (A-002) |
| A-018 | Phase 4 lifter (`cir_lifter_memory.c`) | `push qword [rbx]` stores the ADDRESS rbx instead of the loaded value; `pop qword [rbx]` discards the value and stores nothing (only rsp changes). Same root as A-001: a MEM operand converts to its address. Verified on printed CIR. | HIGH | open |
| A-019 | `cir_lifter_memory.c` header, `cir_opcodes.h` | The header says LEA lifts to `CIR_OP_LEA`; the lifter never emits it (LEA yields the bare address expression), so `CIR_OP_LEA` is unused. Check which other "syntactic" opcodes are never emitted (DIV, PUSH, POP, MMIO...) and remove or implement them. | LOW | open |
| A-020 | `reaching_stores.c` (Phase 5) | The header promised that blocks the entry cannot reach have empty answers, but the code still returned the writes that precede a load inside such a block, and let an unreachable block's writes flow into the reachable block it branches to (over-approximation, not unsoundness). Found while explaining a surviving mutant (`forwardable-accepts-barrier`, which only an unreachable block could expose). Fix: a block whose IN lacks the entry-reaches bit passes nothing on, `for_load` returns 0/false for it, `may_reach` is false in it. Tests `t_unreachable` (three cases). | LOW | fixed (Phase 5) |
| A-021 | `const_prop.c` (Phase 5) | Order-dependence bug in Phase 5 code: the binary transfer function tested BOTTOM before TOP, so `x*0` or `x&0` with x VARYING and the zero operand not yet evaluated gave VARYING, while with the zero known the result is the constant 0. A stored value only ever falls, so the lower answer stuck and the result depended on the order values were evaluated in. Found by the order-reversed reference in `test_const_prop_soundness.c`. Fix: TOP is tested first. Regression `t_order_independence`. | MED | fixed (Phase 5) |
| A-022 | `cir_verifier.c` (Phase 4) | The structural verifier had never been run on a bad function (every test fed it valid ones) and was weaker than its documentation. It did not check that block 0 has no predecessors, NULL operand slots, id uniqueness and range, phi position, count and capacity, or an edge listed twice; its phi and edge checks were quadratic; its comment claimed "type consistency", which it never checked. Fixed in Phase 5: rewritten as seven rules in linear time, each with a negative test, plus differential tests against independent oracles (30,000 random edge lists and 30,000 random phis). Mutation-tested (see PHASE5.md). | MED | fixed (Phase 5) |
| A-023 | `cir_ssa_constructor.c` (Phase 4) | The constructor counted a block's instructions once and then walked that many positions. Resolving a read in a join block inserts phis at the FRONT of that same block, so its last instructions slid past the end of the walk and kept unresolved `REG_ENTRY` placeholders; the comment above the loop claimed this could not happen. Found by running the new SSA verifier over gcc output: 13 of the 40 compiled functions (5 of 8 at -O0) came out with unresolved operands, e.g. `cmp <unresolved:rdi@block3>, %v9` in a loop. No hand-assembled test had an unresolved read among the last instructions of a join block. Fix: the live instruction count is read on every step. Regression `t_loop_reads_several_live_in_registers`; `test_compiled_code` now runs 32 gcc functions through every analysis. | HIGH | fixed (Phase 5) |
| A-024 | Phase 4 lifter (`cir_lifter_branch.c`), seen through `const_prop.c` | A Jcc with no CMP/TEST earlier in its OWN block gets the constant true as its condition. That is the second branch of every `cmp; je A; jg B` and every branch whose flags were set in another block: gcc's `sw` at -O1 lifts to `branch 1, block6, block2`. Constant propagation takes the constant at its word and folds the branch, so two blocks that can run are reported not executable. The pass is right about the CIR it is given; the CIR is wrong. Same root as A-008. The fix is in the lifter: flags as values that flow across blocks, and the predicate recorded. Until then "not executable" on lifted code is not to be trusted (stated in `const_prop.h`). | HIGH | open (Phase 4.5) |
| A-025 | `cir_verifier.c`, `ssa_verifier.c`, Phase 4 lifter | Neither verifier checks operand types or counts per opcode, or that an operand's width matches its result's. Neither can require that a block ends in a terminator that agrees with its successor list, because the lifter emits no instruction for a fallthrough (block8 of `sw` at -O1 is empty and has one successor) and drops, without saying so, a Jcc whose successor count is not 2 and an indirect Jmp. The rule has to be decided together with the lifter. | MED | open (Phase 4.5) |
| A-026 | `cir_ssa_constructor.c` | The constructor never removes trivial phis (every incoming value the same, or the phi itself): `phi [rax, rax, rax, rax]` and `phi [rdi, itself]` appear all through lifted code (180 phis in the 202 blocks of the corpus). The REG_ENTRY placeholders it replaces also stay in the function's value table. Costs precision and clarity downstream, not correctness; the alias analysis already resolves redundant phis for itself. Braun's trivial-phi removal is the remedy. | LOW | open |
| A-027 | CIR design | A block has at most two successors (`CIR_BLOCK_MAX_SUCCESSORS`), so there is no multiway branch: Phase 3 records no successors for an indirect jmp, and whatever lies behind a jump table is unreachable in CIR. Phase 6 needs a switch terminator (case list) before it can recover jump tables. | MED | open (before Phase 6) |
| A-028 | `pe_loader.c` (Phase 2) | Misaligned reads of the mapped file: the import lookup table was read through a `const uint64_t *`, the export arrays through `uint32_t *` and `uint16_t *`, the relocation entries through `uint16_t *`, and the import hint and the PE signature through casts. A PE puts its tables at whatever offset the linker (or a hostile file) chose, and dereferencing a misaligned pointer is undefined behaviour even where x86 tolerates it. Found by the ASan + UBSan run of the whole suite (`test_pe_loader` first stored through misaligned pointers itself; after that was fixed, the loader's own read at `pe_loader.c:129` was reported). Fix: `rd16`, `rd32`, `rd64` read with memcpy; behaviour is otherwise unchanged. | LOW | fixed (Phase 5) |
| A-029 | Test code | Three defects in tests, all found by the sanitizer run, none affecting a library result: `test_compiled_code.c`'s `EXPECT` evaluated its condition twice, so every analysis built inside one was built twice and the first result leaked (the new test had never been run under Valgrind); `test_alias_soundness.c`'s forge code computed `INT64_MAX + 1`; `test_pe_loader.c` stored 64-bit values through misaligned pointers. All fixed. A sanitizer build of the whole suite is now part of the definition of done for a phase. | LOW | fixed (Phase 5) |
| A-030 | `pe_loader.c` (Phase 2); `elf_loader.c` not yet read for this | The loader trusts the file. Found by READING, not yet reproduced (to be reproduced with malformed inputs in Phase 4.5): `rptr` checks that the START of a table lies inside the file, not that what is read from it fits; the import lookup table is walked to a zero entry with no end bound; export names and ordinals are read for `nnames` entries, and `funcs[ords[i]]` is indexed by an ordinal taken from the file with no bound; debug-directory entries and the relocation walk (`end = rd + dir->sz`) are not clamped to the file; the optional header is read without checking that it fits. A truncated or hostile `.sys` can read past the mapping or produce garbage symbols. CBAE exists to analyse untrusted drivers, so this is the first thing the loader audit should settle: one bounds-checked reader used by every table walk, then fuzzing both loaders under ASan. | MED | open (Phase 4.5) |

### Evidence from the compiled-code corpus

`tests/unit/compiled_corpus.h` holds gcc output: 8 small C functions at -O0, -O1, -O2, -O3 and -Os, 32 distinct functions, 538 instructions, 86 of them conditional jumps. By a static count of what the lifter does with each instruction, 31 of the 32 functions contain at least one that is dropped, conflated or lifted wrongly: 10 instructions have no lifter support at all (cqo 4, cmovle 3, cmovge 2, movsx 1: A-003); 56 use a narrow register (xor 25, mov 22, test 7, and 2: A-002); 31 are arithmetic or compares with a memory operand: 11 write to memory (dropped), 11 are a cmp or test of memory (the address is compared) and 9 read memory as the source (the address is used) (A-001). The one clean function is the smallest. Two examples read off the printed CIR:

- `sw` at -O1: all four `mov eax, imm32` that set the return value are dropped (A-002), so the phi at the shared return merges the entry value of rax four times, and the second branch of `cmp; je; jg` has the constant true as its condition (A-024).
- `sum_to` at -O0: `add [rbp-8], rax` and `add [rbp-16], 1` vanish (A-001), so the loop accumulates nothing, and `cmp rax, [rbp-24]` compares rax with the address rbp-24.

Phase 5's analyses are checked against the CIR they are given; they cannot make that CIR faithful. This is why Phase 4.5 comes before Phase 6.

## Precision items (the analyses are sound; these are answers less sharp than the truth)

| ID | Where | Item | Status |
|----|-------|------|--------|
| P-001 | `alias_analysis.c`, `reaching_stores.c` | An address built from a loop-carried value (a phi on a cycle) is never provably the same as another access to "the same" address, so a store and a reload through a loop pointer never forward and never kill. Fix would be intra-block, time-consistent alias queries (two uses of one value between the same two redefinitions are equal). Needed by Phase 6 for loops over arrays of structures. | open |
| P-002 | `reaching_stores.c` | Every CALL is a barrier with no summary, so in call-heavy code most answers are dominated by calls. Random executions cannot measure the loss (a call's real writes are few), the hand-derived tests show it is exact for what CIR can say. Phase 6 should add summaries for the kernel APIs whose effect is known (the `windows_kernel_api.sql` / `linux_kernel_api.sql` tables) and an escape analysis for stack slots whose address is never passed out. | open |
| P-003 | `alias_analysis.c`, `reaching_stores.c` | A wider store covering a narrower load (or the reverse) is MAY, never "contains". Moot until the lifter models access widths (A-006): today every lifted access is 64 bits. | open (blocked on A-006) |
| P-004 | `reaching_stores.c` | Joint-path over-approximation: a store that escapes its own class's later stores on one path and the load class's stores on another stays in the answer. Pinned exactly by `t_documented_limits`. | documented |
| P-005 | `const_prop.c` | One constant per value, nothing finer: a phi of two different constants, a bounded index and a strided pointer are all VARYING (a value-set domain is the remedy); operations that mix widths are never folded because CIR does not say how a narrow value extends (A-016); loads and calls are VARYING, since memory is not modelled here (reaching stores plus the stored value is the hook for a pass that wants it); a CMP never folds because CIR records no predicate (A-008). | documented |

Equivalent mutants kept on purpose: in `cbae_reaching_stores_forwardable` the
"single definition is not a barrier" and "alias MUST" tests cannot fail once
`n == 1 && !initial` (the only way to exclude initial content is a store of
the load's own class, which is then the single definition). They stay because
the documented contract is the conjunction; the comment in the source says so.

Equivalent mutants in the two verifiers (13 of 153; each shown by reading to be unable to change a
verdict or a message; the other 140 are killed, 13 of them only under the sanitizers):

- `first-violation-overwritten`, in both files: `set_error` and `fail` return early when a
  violation is already recorded. Every caller already stops once `ok` is false, so the guard is
  never reached; it keeps new code from overwriting the first message. Each layer of "the first
  violation wins" is redundant alone; with the guard, the loop conditions and the early returns
  removed together the tests fail on a changed message, so the property itself is tested.
- `entry-structure-failure-continues`, `entry-instructions-after-id-failure`,
  `entry-edges-after-instruction-failure` (`cir_verifier.c`): the stage guards in
  `cbae_cir_verify_function` only save work, because every stage's loops stop on `!ok`.
- `r7-count-compare-less`: `npred != from_succ[b]` against `npred < from_succ[b]`. By the time of the
  comparison the predecessor list has been checked entry by entry to be a subset of the blocks that
  list `b` as a successor, so `npred <= from_succ[b]` always and the two tests agree.
- `r7-alloc-size-without-fallback`: `calloc(0, n)` returns a non-NULL pointer on glibc and under ASan.
  The `n ? n : 1` is for a C library whose `calloc(0, n)` returns NULL.
- `dominates-enter-strict`, `dominates-leave-strict` (`ssa_verifier.c`): the interval numbers come
  from one timer shared by enter and leave, so all are distinct, and `dominates` is called only for
  two different blocks (the same-block case is decided before it); `<=` and `<` agree.
- four `perf-*-loop-continues-after-failure` (`ssa_verifier.c`): the scan loops stop at the first
  violation to save time; letting them go on changes the cost only, because `fail` ignores later
  violations.

## Strengths to credit in the audit report

Noted as found, with the evidence, so the report names specifics.

- Arena discipline throughout: no per-object frees to get wrong; every
  failure path in the builder returns NULL instead of corrupting state.
- The CIR invariants are written down and enforced by a verifier
  (`blocks[i]->id == i`, edge/phi consistency, unique ids), which is what let
  Phase 5 analyses assume a clean graph.
- Braun SSA construction and Cooper-Harvey-Kennedy dominators are the right
  algorithm choices for lifted code: simple, fast, and testable against
  brute-force references.
- The lifter's synthetic entry block when the function entry is a branch
  target kept block 0 predecessor-free, which every later analysis relies on.
- Test discipline: hand-derived expectations, brute-force cross-checks on
  random graphs, Valgrind, and mutation testing that found real gaps.
- The random-program soundness harness (`cir_random.h`: valid-SSA generator
  plus a concrete interpreter) found three real soundness bugs (A-015..A-017)
  that hand-written tests and 93 killed mutants had not, and will be reused to
  test the lifter itself against Unicorn in Phase 4.5.
- Real compiler output as a test input: the first run of the SSA verifier over gcc's code found the constructor bug A-023 within minutes, and the same corpus now runs every analysis against brute-force dominance, post-dominance and frontier definitions (`test_compiled_code.c`). The Phase 4 tests had a green record on hand-assembled code for a bug that 13 of 40 real functions exposed.
- The same harness, extended with per-byte last-writer tracking, checks reaching
  stores against 1,500 random functions (74,000 load executions, 4.5 million
  raw-dataflow checks, 5,000 forwarded executions) with nine forged claims that
  must each be caught. A 61-mutant campaign on `reaching_stores.c` was killed
  except two proved-equivalent defensive checks, and exposed the A-020
  doc/code mismatch.
