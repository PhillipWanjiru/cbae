# CBAE — CDIS Binary Analysis Engine

## Status: Phase 2 complete (7/7 tests passing)

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
ctest --output-on-failure
```

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
| 3 | Disassembly & CFG | ⬜ Not started |
| 4 | CIR Design & Lifting | ⬜ Not started |
| 5 | Dataflow Infrastructure | ⬜ Not started |
| 6 | Semantic Analysis Passes | ⬜ Not started |
| 7 | Decompiler | ⬜ Not started |
| 8 | Driver DNA Fingerprinting | ⬜ Not started |
| 9 | Translation Engine | ⬜ Not started |
| 10 | Capture, Batch, CLI & Integration | ⬜ Not started |

See `docs/architecture/RUST_INTEGRATION.md` for details on where and why
Rust is used in this project.
