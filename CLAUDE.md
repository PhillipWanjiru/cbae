# CLAUDE.md

CBAE is a C (gnu11) engine that analyses x86-64 device-driver binaries. Start with `docs/HANDOFF.md` (state, conventions,
next steps), then `docs/ROADMAP.md` and `docs/audit/LEDGER.md`.

## Commands

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
tests/run_gates.sh [debug release asan tsan valgrind]     # a checkpoint needs all five
```

## Rules

- Follow the author's preferences in `docs/HANDOFF.md` section 2: exact specifications, direct, minimal preamble, real
  compiled and tested results before anything is archived.
- Say which phase the project is in and how far there is to go.
- Failing test first, shown to fail on the original code; then the fix; then evidence in `docs/audit/evidence/`.
- Check every allocation and every container insert; report errors with `CBAE_RETURN_ERR` / `CBAE_CHECK`.
- The Release build must have zero warnings.
- Run mutation campaigns on a copy of the tree, never on the working tree.
- After writing a file, check `grep -nP '[^\x00-\x7F]' FILE`: some tools convert backslash-u escapes into characters.
- Update `docs/HANDOFF.md`, `docs/ROADMAP.md` and `CHANGELOG.md` at every delivery.
- Commits are authored as the repository owner (`PhillipWanjiru`).
