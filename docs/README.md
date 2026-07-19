# CBAE — CDIS Binary Analysis Engine

## Status: Phase 3 complete (11/11 tests passing, 0 memory errors under Valgrind)

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
ctest --output-on-failure
```

Requires: `libsqlite3-dev`, `libcapstone-dev`, `cmake`.

To also build the Rust crates (batch daemon + IPC layer):

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWITH_RUST=ON
make -j$(nproc)
```

## Phase status

| Phase | Component | Status |
|---|---|---|
| 1 | Foundation & Platform | ✅ Complete — 5/5 tests passing |
| 2 | Binary Loaders (PE32+, ELF64) | ✅ Complete — 2/2 tests passing |
| 3 | Disassembly & CFG | ✅ Complete — 4/4 tests passing |
| 4 | CIR Design & Lifting | ⬜ Not started |
| 5 | Dataflow Infrastructure | ⬜ Not started |
| 6 | Semantic Analysis Passes | ⬜ Not started |
| 7 | Decompiler | ⬜ Not started |
| 8 | Driver DNA Fingerprinting | ⬜ Not started |
| 9 | Translation Engine | ⬜ Not started |
| 10 | Capture, Batch, CLI & Integration | ⬜ Not started |

**All 11 tests pass under Valgrind `--leak-check=full` with zero memory
errors and zero leaks**, including the most complex logic in the
codebase so far: the arena pointer-slicing mid-block CFG split.

## Phase 3 summary

Capstone-backed x86-64 disassembly, recursive-descent CFG construction
with mid-block splitting on convergence, inter-procedural call graph
with IAT-relative import resolution, single-block backward pattern
matching for register-indirect calls, and PE `.pdata`-based function
boundary + SEH detection.

One real bug was found and fixed during verification: `mov reg, imm64`
decodes to Capstone's distinct `X86_INS_MOVABS` id, not `X86_INS_MOV`
— the instruction classifier didn't account for this until an actual
test run against the real Capstone 4.0.2 library caught it.

See `docs/architecture/PHASE3.md` for full component documentation.
