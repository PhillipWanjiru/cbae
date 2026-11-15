# Changelog

One entry per delivery, newest first. Each delivery is one commit; the dates are those of the newest file in it.
The phase plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Phase 4.5 — audit of Phases 1–4 (in progress)

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
