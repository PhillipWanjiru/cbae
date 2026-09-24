# CBAE — CDIS Binary Analysis Engine

## Status: Phase 4 complete (15/15 tests passing, 0 memory errors under Valgrind)

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
ctest --output-on-failure
```

Requires: `libsqlite3-dev`, `libcapstone-dev`, `cmake`.

## Phase status

| Phase | Component | Status |
|---|---|---|
| 1 | Foundation & Platform | ✅ Complete — 5/5 tests |
| 2 | Binary Loaders (PE32+, ELF64) | ✅ Complete — 2/2 tests |
| 3 | Disassembly & CFG | ✅ Complete — 4/4 tests |
| 4 | CIR Design & Lifting | ✅ Complete — 4/4 tests |
| 5 | Dataflow Infrastructure | ⬜ Not started |
| 6 | Semantic Analysis Passes | ⬜ Not started |
| 7 | Decompiler | ⬜ Not started |
| 8 | Driver DNA Fingerprinting | ⬜ Not started |
| 9 | Translation Engine | ⬜ Not started |
| 10 | Capture, Batch, CLI & Integration | ⬜ Not started |

**All 15 tests pass under Valgrind `--leak-check=full` with zero memory
errors and zero leaks**, spanning every phase from the foundational
allocators through full x86-64 SSA construction.

## Phase 4 summary

CIR (~50-opcode two-tier vocabulary: syntactic + Phase-6-reserved
semantic), a builder API, a five-module lifter converting Phase 3's
disassembled instructions into non-SSA CIR, Braun-et-al. SSA
construction, a structural verifier, and a native binary serializer.

One significant algorithmic bug was found and fixed during verification
— caught by hand-tracing a loop scenario before any test was written,
not by a failing test: splitting lifting from SSA construction into two
passes silently lost the distinction between "what should an unresolved
placeholder created in this block resolve to" and "what does this block
contribute to a successor's phi," which would have produced a loop
induction variable whose phi resolves to itself rather than to the loop
body's actual computation. See `docs/architecture/PHASE4.md` for the
full account and the fix.

See `docs/architecture/PHASE4.md` for complete Phase 4 documentation.
