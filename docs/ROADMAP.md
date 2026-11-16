# Roadmap

CBAE is built in ten phases, in order. A phase is complete when its tests pass on the author's machine and under the
sanitizer and Valgrind gates (`tests/run_gates.sh`).

## Where the project stands

**Phases 1–5 of 10 are complete. Phase 4.5 — an audit of Phases 1–4 that sits between Phase 5 and Phase 6 — is in
progress (checkpoint 1 of 5). Phases 6–10 are not started.**

By phase count that is 5 of 10 done. Phases differ a lot in size, so this is the only measure given here.

| Phase | Component | Status |
|---|---|---|
| 1 | Foundation & Platform (arena, vector, hashmap, strings, logging, thread pool, SQLite layer, engine) | complete |
| 2 | Binary Loaders (PE32+, ELF64) | complete |
| 3 | Disassembly & CFG (Capstone, basic blocks, call graph, function boundaries) | complete |
| 4 | CIR Design & Lifting (IR, builder, lifters, SSA construction, verifier, serializer) | complete |
| 5 | Dataflow Infrastructure (dominators, dataflow engine, use-def, alias, reaching stores, constants, SSA verifier) | complete |
| 4.5 | Audit of Phases 1–4: fix what is wrong, remove stubs, refactor and optimise | **in progress** |
| 6 | Semantic Analysis Passes (seven passes over CIR; API recognition first) | not started |
| 7 | Decompiler (CIR to compilable C; C++) | not started |
| 8 | Driver DNA Fingerprinting (512-dimension behavioural feature vector) | not started |
| 9 | Translation Engine (cross-OS API substitution, Windows ⇄ Linux) | not started |
| 10 | Capture, Batch, CLI & Integration (behavioural capture in a VM, batch processing, command line) | not started |

Test programs: 29 at the end of Phase 5, 44 now (the audit added test programs for hostile input, real binaries,
out-of-memory handling and API contracts).

## Phase 4.5 — the audit

Goals: correct what is wrong (the first example: ALU and compare instructions with a memory operand are lifted
incorrectly), remove stubs unless a later phase fills them, credit what was done well, and refactor and optimise each phase
to the best that is achievable for its setting. Findings are recorded in [audit/LEDGER.md](audit/LEDGER.md).

Method for every item: write the failing test first and show it fail on the original code; fix; check with independent
oracles; mutation-test the fix; keep the evidence in `docs/audit/evidence/`.

| Checkpoint | Scope | Status |
|---|---|---|
| 1 | Phases 1–2 (platform, database, loaders), CIR serializer and builder, dominator out-of-memory handling | implemented; 44/44 tests pass under all five gates (Debug, Release, ASan/UBSan, TSan, Valgrind); the first run on the author's machine found two test-only problems, fixed (A-055, A-056); still to do: mutation campaigns for the dominance code and the vector and hashmap, A-050, ledger rows |
| 2 | Phase 3: CBAE-owned instruction model, function-boundary finder scored against the unwind table, ELF relocation application, call-graph import, CFG builder hardening | not started |
| 3 | CIR vocabulary and verifier: flags, condition codes, comparisons, extensions, select, switch, wider integers; typed phis; serializer v2; simplifier; iterative SSA | not started |
| 4 | New lifter (memory operands, narrow registers, unmodelled instructions, flags), differential tests against native execution, larger compiled corpus | not started |
| 5 | Profile-driven optimisation, closing the ledger, mutation campaigns and out-of-memory sweeps for the Phase 5 analyses, `PHASE4.5.md` | not started |

A checkpoint is done when its failing-first tests exist, the whole suite is green under all five gates, the mutation
campaigns for the changed code are accounted for (every survivor is either killed by a new test or shown to be
equivalent), and the docs and ledger say only what was measured.

## Before Phase 6

- Populate the kernel-API tables of the knowledge database: about 800 Windows entries (`windows_kernel_api.sql`) and
  about 600 Linux entries (`linux_kernel_api.sql`).

## Later phases

- Phase 10 needs QEMU virtual-machine snapshots (Windows 11 and Ubuntu 24.04 targets).
- Loading drivers on a real machine needs an EV code-signing certificate (Windows) and Machine Owner Key enrolment (Linux).
