# CBAE — CDIS Binary Analysis Engine

CBAE reads x86-64 device-driver binaries (Windows PE32+ `.sys`, Linux ELF64 `.ko`), disassembles them, lifts them to its own
intermediate representation (CIR) and analyses that representation. It is written in C and is the analysis core of **CDIS**,
the Cross-Platform Driver Intelligence System.

**Status:** Phases 1–5 complete · Phase 4.5 (audit of Phases 1–4) in progress · Phases 6–10 not started.
Details and progress: [docs/ROADMAP.md](docs/ROADMAP.md).

## Pipeline

```
.sys / .ko file
  → loader      PE32+ / ELF64 → binary image (sections, symbols, imports, relocations)     Phase 2
  → disasm      Capstone decoding, basic blocks, CFG, call graph                           Phase 3
  → cir         lifting to CIR, SSA construction, verifier, serializer                     Phase 4
  → dataflow    dominators, use-def chains, alias analysis, reaching stores, constants     Phase 5
  → semantic passes · decompiler · fingerprinting · translation · CLI                      Phases 6–10 (planned)
```

Underneath sit `platform` (arena, vector, hashmap, string pool, logging, errors, thread pool), `db` (SQLite) and `engine`
(configuration, lifecycle): Phase 1.

## Build and test

Requirements: a C11 compiler, CMake ≥ 3.20, SQLite3 and Capstone development files.

```bash
sudo apt install build-essential cmake libsqlite3-dev libcapstone-dev    # Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

`tests/run_gates.sh` runs the whole suite in every configuration — `debug`, `release` (fails on any compiler warning),
`asan` (AddressSanitizer + UBSan + LeakSanitizer), `tsan`, `valgrind`:

```bash
tests/run_gates.sh                # all five
tests/run_gates.sh debug asan     # a selection
```

## Repository layout

| Path | Contents |
|---|---|
| `include/`, `src/` | the library, one directory per layer: `platform` `db` `engine` `loader` `disasm` `cir` `dataflow` |
| `tests/` | unit, soundness, hostile-input and out-of-memory tests; real compiled fixtures; `run_gates.sh` |
| `tools/mutation/` | mutation-testing runner and the mutant lists |
| `docs/architecture/` | architecture and one document per phase |
| `docs/audit/` | the Phase 4.5 audit ledger and its evidence |
| `rust/` | batch daemon and IPC crates (optional, `-DWITH_RUST=ON`) |
| `config/` | default configuration |

## Documentation

- [docs/ROADMAP.md](docs/ROADMAP.md) — the ten phases, what is done, what is next
- [CHANGELOG.md](CHANGELOG.md) — what each delivery added
- [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) — layers and data flow
- [docs/audit/LEDGER.md](docs/audit/LEDGER.md) — findings of the audit, with status
- [docs/HANDOFF.md](docs/HANDOFF.md) — the working state, conventions and next steps, for anyone (or any Claude session) taking the project over

## History

Every commit is one delivery of the project, in order: Phases 1–2, Phase 3, each checkpoint of Phases 4 and 5, then the
Phase 4.5 work. Tags `phase-1-2`, `phase-3`, `phase-4`, `phase-5` mark the completed phases. Earlier copies of the project
are kept on the branches `archive/*`.

## Author

Phillip Wanjiru (PhillipWanjiru). No licence has been chosen yet: all rights reserved until one is added.
