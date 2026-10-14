# CBAE — CDIS Binary Analysis Engine

## Status: Phase 5 complete (29/29 tests passing, 0 errors under Valgrind and under ASan + UBSan + LeakSanitizer)

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
| 5 | Dataflow Infrastructure | ✅ Complete — 14/14 tests |
| 6 | Semantic Analysis Passes | ⬜ Not started |
| 7 | Decompiler | ⬜ Not started |
| 8 | Driver DNA Fingerprinting | ⬜ Not started |
| 9 | Translation Engine | ⬜ Not started |
| 10 | Capture, Batch, CLI & Integration | ⬜ Not started |

**All 29 tests pass under Valgrind `--leak-check=full` with zero memory
errors and zero leaks, and under an ASan + UBSan + LeakSanitizer build**,
spanning every phase from the foundational allocators through the dataflow
analyses. Debug and Release builds both pass, and the Release build has no
compiler warnings.

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

## Phase 5 summary

Dominator and post-dominator trees (Cooper-Harvey-Kennedy, one shared
implementation), a forward/backward dataflow engine, use-def chains, alias
analysis, reaching stores, constant propagation with conditional branches, and
an SSA dominance verifier, in the new library `cbae_dataflow`. The structural
verifier of Phase 4 was rewritten (seven rules, linear time, each with a
negative test).

Each analysis answers only what it can prove and says "don't know" otherwise.
The claims are checked against brute-force definitions, against thousands of
random programs run by a concrete interpreter (each soundness test also forges
wrong claims that it must catch), against gcc output at -O0 to -O3 and -Os,
and by mutation testing: 595 mutants of the analyses and both verifiers, of
which 560 are killed, 34 are shown to be equivalent to the original, and one
was a dead line that is now removed.

Testing found what the example-based tests had not: soundness bugs in the new
analyses (A-015 to A-017, A-021), an answer for blocks the header promised
were empty (A-020), a verifier weaker than its documentation (A-022), a bug in
Phase 4's SSA construction that left register reads unresolved in 13 of 40
functions compiled by gcc (A-023), and, from the sanitizer run, misaligned
reads in the PE loader (A-028).

**What Phase 5 does not establish.** The analyses are sound for the CIR they
are given; they cannot make that CIR faithful to the machine code. On gcc's
output, 31 of the 32 functions in the corpus contain an instruction the lifter
drops, conflates or lifts wrongly (narrow registers, ALU and compare
instructions with a memory operand, instructions it has no case for, branch
conditions it makes up). The audit of Phases 1 to 4, with these as its first
items, is the next step and comes before Phase 6.

See `docs/architecture/PHASE5.md` for complete Phase 5 documentation and
`docs/audit/LEDGER.md` for the findings list.
