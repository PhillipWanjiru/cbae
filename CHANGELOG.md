# Changelog

One entry per delivery, newest first. Each delivery is one commit; the dates are those of the newest file in it.
The phase plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Phase 4.5 — audit of Phases 1–4 (in progress)

### Checkpoint 1 — second run on the author's machine: the thread-pool test again (2026-11-18)

The author's run of `fcbde1a` on DELTA-FORCE (Debug, GCC 15.2.0, Capstone 5.0.7) passed 43 of 44 tests, and the push worked. The
failure was `test_thread_pool` ("1 threads, expected 2"): a flaw of the test, in part introduced by the A-056 change. The
library was not at fault. Evidence is in `docs/audit/evidence/`.

- **A-057** — the test took its thread-count baseline while a thread that had already been joined could still be listed in
  `/proc/self/task`, which is possible for as long as the kernel takes to finish with it. `tools/slow_reap.py` (new) reproduces
  that on demand: the version you ran fails with the exited threads kept listed for 0 to 100 ms, the new one passes. The test
  now takes one baseline for the whole program, after the warm-up thread has left `/proc` (waited for by its thread id), and
  checks after every test that the threads are back to it. `tests/run_gates.sh` now also runs the test under the tool (Debug
  and TSan gates; skipped where tracing is not allowed).
- **A-058** — the whole tree was built and tested against Capstone 5.0.7 in the sandbox for the first time (until now only
  4.0.2): Debug 44/44. Capstone 5's header trips `-Wpedantic` unless it is in a system directory, which would fail the
  zero-warning Release gate for a Capstone installed elsewhere; the SQLite and Capstone include directories are now
  `SYSTEM`.
- **A-050** (lenient integration tests), first half: `test_loader_to_disasm` now checks the address, length, bytes, mnemonic,
  class and operands of every instruction and the block's bounds and flags; it also passes with Capstone 5.0.7. The structural
  comparison of the serializer test moved to `tests/unit/cir_compare.h`. The disassembler-to-CIR test is still to do.
- Mutation campaigns of the dominance code (373 mutants) are running; results are not recorded yet.

### Checkpoint 1 — first run on the author's machine: two test fixes (2026-11-16)

The author's first run of the repository on DELTA-FORCE (Debug, GCC 15.2.0, Capstone 5.0.7, SQLite 3.46.1) passed 43 of 44
tests, and the first TSan run of the new tests failed one. Both were problems of the tests and the build; the library was not
at fault. Each was reproduced first and the evidence is in `docs/audit/evidence/`.

- **A-055** — `test_elf_real` hit its 30 s limit on a machine about 1.9 times slower than the sandbox. The limits are now hang
  guards with a wide margin (300 s Debug and Release, 900 s ASan, 1200 s TSan; `-DCBAE_TEST_TIMEOUT=<seconds>` sets one). SHA-256,
  85% of that test's time, is compiled with `-O2` in a Debug build: test_elf_real takes 8.5 s instead of 16 s in Debug and
  34.5 s instead of 70 s under ASan, and the whole Debug suite runs in about half the time.
- **A-056** — `test_thread_pool` counts the threads of the process and failed under TSan, whose runtime starts a thread of its
  own at the first `pthread_create`. The test now starts and joins one thread before its first count. No library code changed.
- The CMake summary line lists all seven layers.
- Mutation modules for the dominance code (`mutants_dom_core.py`, `mutants_dominator_tree.py`, `mutants_post_dominator_tree.py`,
  `mutants_ssa_verifier_dominance.py`: 373 mutants), written and validated; the campaigns are still to be run.
- Three redundant conditions removed from the dominator code, each implied by what follows it (`n == 0` in
  `dom_core_compute`; `block_count == 0` in the tree and the frontier destroy functions).
- Sandbox, all five gates on this tree: Debug, Release (no warnings), ASan + UBSan + LeakSanitizer, TSan and Valgrind pass,
  44/44 tests each.

### Checkpoint 1 — implemented, verification under way (2026-11-15)

Audit of Phases 1–2 and of the Phase 4–5 code they touch. Each item starts with a test that fails on the original code.
Suite: 44 test programs, all passing under Debug, Release (no warnings) and ASan + UBSan + LeakSanitizer.

- **Platform** — arena, vector, hashmap, string pool, logging, thread pool, configuration, error API and file I/O reviewed
  and tested against hostile input and allocation failure (audit items A-031 to A-042). SHA-256 and SipHash added.
- **Loaders** — PE32+ and ELF64 loaders rewritten around bounds-checked spans, with hostile-input, boundary and
  real-binary tests (A-030, A-036 to A-038, A-047).
- **Database layer** — connection, schema, query and transaction code hardened and tested (A-043).
- **CIR builder and serializer** — every argument checked, every allocation failure reported, serializer input never
  trusted (A-045, A-046); mutation campaigns of 192 and 302 mutants.
- **Dominators** — out-of-memory handling and size limits in the dominator, post-dominator and frontier code, an
  exactly-validating tree numbering, and a frontier computation that no longer re-walks shared dominator chains
  (A-048, A-049).
- **Test infrastructure** — allocation-failure injection and out-of-memory sweep helpers, `tests/run_gates.sh` (five
  gates in one command), and the mutation-testing runner in `tools/mutation/`.
- Evidence for each item is in `docs/audit/evidence/`; the ledger rows for the new items are still to be written.

## Phase 5 — Dataflow infrastructure (complete, 2026-10-14)

29/29 tests; clean under Valgrind and under ASan + UBSan + LeakSanitizer.

- Constant propagation with conditional branches, and an SSA dominance verifier.
- The structural verifier of Phase 4 rewritten: seven rules, linear time, each with a negative test.
- Tests that compile C with gcc at -O0 to -O3 and -Os and analyse the result; soundness tests that run thousands of random
  programs in a concrete interpreter.
- Bugs found by those tests and fixed: A-015 to A-017, A-020 to A-023 (including a Phase 4 SSA-construction bug that
  left register reads unresolved in 13 of 40 gcc-compiled functions) and A-028 (misaligned reads in the PE loader).
- `docs/architecture/PHASE5.md`.

### Checkpoints

| Date | Checkpoint |
|---|---|
| 2026-10-09 | 9 — reaching stores, with soundness tests |
| 2026-10-06 | 8 — alias analysis soundness tests (random programs against a concrete interpreter) and the analysis changes they led to |
| 2026-10-05 | 7 — alias analysis; shared CFG graph helper; audit ledger started |
| 2026-10-04 | 6 — strongly connected components for post-dominators (infinite loops) |
| 2026-10-04 | 5 — use-def chains |
| 2026-10-03 | 4 — lifter and SSA-constructor changes |
| 2026-10-03 | 3 — post-dominator tree; one shared Cooper–Harvey–Kennedy core; brute-force reference for the tests |
| 2026-10-03 | 2 — forward/backward dataflow engine |
| 2026-09-28 | 1 — dominator tree |

## Phase 4 — CIR design and lifting (complete, 2026-09-24)

- CIR: types, values, instructions, blocks, functions, modules; a vocabulary of about 50 opcodes in two tiers
  (syntactic, and semantic opcodes reserved for Phase 6); builder API; printer.
- Five lifter modules (arithmetic, branch, call, I/O, memory) turning Phase 3's instructions into CIR.
- SSA construction after Braun et al.; structural verifier; native binary serializer.
- `docs/architecture/PHASE4.md`, including the account of the loop-phi bug found by hand-tracing before any test.

### Checkpoints

| Date | Checkpoint |
|---|---|
| 2026-09-11 | 6 — SSA construction tests |
| 2026-09-09 | 5 — builder and lifter fixes |
| 2026-08-29 | 4 — SSA construction |
| 2026-08-20 | 3 — lifter tests |
| 2026-08-14 | 2 — the five lifter modules |
| 2026-08-10 | 1 — CIR core and builder |

## Phase 3 — Disassembly and CFG (complete, 2026-07-19)

Capstone-based disassembler, basic blocks and CFG builder with edge classification, function-boundary finder, call-graph
builder, indirect-call resolver, SEH handler detector. `docs/architecture/PHASE3.md`.

## Phases 1–2 — Foundation, platform and loaders (complete, 2026-07-12)

- Platform: arena, vector, hashmap, string pool, logging, thread pool, file I/O, Linux and Windows shims.
- Engine (configuration, lifecycle, errors) and a SQLite layer (connection, two migrations, queries, transactions).
- PE32+ and ELF64 loaders producing one binary-image structure.
- Rust crates `cbae_batchd` (batch daemon) and `cbae_ipc` (typed IPC), described in `docs/architecture/RUST_INTEGRATION.md`.
