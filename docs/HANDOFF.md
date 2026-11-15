# Hand-off

For whoever continues this project: the author, or a new Claude session on another account. Read this first, then
[ROADMAP.md](ROADMAP.md) and [audit/LEDGER.md](audit/LEDGER.md). Keep this file current at every checkpoint.
Last updated: 2026-11-15.

## 1. The project

CBAE (CDIS Binary Analysis Engine) is a domain-specific x86-64 binary analysis engine written in C: it reads Windows
`.sys` and Linux `.ko` drivers, disassembles them, lifts them to its own IR (CIR) and analyses that. It is the backbone of
CDIS (Cross-Platform Driver Intelligence System), the larger production system the author is building from scratch.
Design documents: `docs/architecture/`. The ten phases are in [ROADMAP.md](ROADMAP.md).

## 2. The author and how the author works

Phillip Wanjiru (GitHub `PhillipWanjiru`, handle DELTA OPERATOR 771). Builds large, original, production-quality software
from scratch. Standing preferences:

- Exact specifications: no additions, no embellishments.
- Direct and execution-oriented, minimal preamble.
- Incremental delivery, file by file where that helps.
- Real compiled and tested results before anything is archived.
- Say plainly which phase the project is in and how much is left.
- In audits, give credit to the good work as well as the defects.

Working practice that has held up: when a sensible default exists, take it, say so, and let the author veto it.
Every delivery is a zip plus a block of shell commands for the author's machine (unzip, configure, build, run the tests).

## 3. Machines

| | Author's machine (DELTA-FORCE) | Claude's sandbox (varies by session) |
|---|---|---|
| OS | Linux | Ubuntu 24.04 |
| Compiler | GCC 15.2.0 | gcc 13.3, clang 18 |
| Capstone | 5.0.7 | 4.0.2 |
| CMake | 4.2.3 | 3.28.3 |
| Other | `build-essential cmake libsqlite3-dev libcapstone-dev` | SQLite 3.45.1, binutils 2.42, valgrind, gdb; 2 cores, 8 GiB; runs as root |

The code must build on both Capstone versions. As root, tests that rely on file-permission errors are unreliable. The
sandbox VM restarts without warning: background jobs die, files under the home directory survive.

## 4. State on 2026-11-15

**Phases 1–5 are complete and were verified by the author on DELTA-FORCE** (Phase 5: 29/29 tests). **Phase 4.5, the audit,
is in progress.** Phases 6–10 are not started.

Checkpoint 1 of Phase 4.5 is implemented. Measured in the sandbox on the tree in this repository: 44/44 tests pass under
Debug, Release (zero warnings) and ASan + UBSan + LeakSanitizer. **Not yet re-run:** the TSan and Valgrind gates since the
new tests were added, and the author's own build of this version.

Audit items worked on in checkpoint 1 (IDs are not contiguous; A-044 and A-053 are not recorded). The ledger
(`docs/audit/LEDGER.md`) holds A-001 to A-030 only; rows for the rest are still to be written from re-measured facts.

| ID | Subject | ID | Subject |
|---|---|---|---|
| A-030 | PE loader trusts its input | A-042 | logging |
| A-031 | string pool | A-043 | database layer |
| A-032 | configuration | A-045 | CIR serializer |
| A-033 | thread pool | A-046 | CIR builder |
| A-034 | error API | A-047 | PE loader (rework) |
| A-035 | arena | A-048, A-049 | dominator / post-dominator / frontier out-of-memory and limits |
| A-036 – A-038 | ELF loader | A-050 | lenient tests that accept wrong results |
| A-039 | file I/O | A-051 | SSA construction to be made iterative (open, Checkpoint 3) |
| A-040 | vector | A-052 | PE section-length consumers (open, Checkpoint 2) |
| A-041 | hashmap | A-054 | out-of-memory sweeps for the Phase 5 analyses (open) |

### Remaining in checkpoint 1, in order

1. Mutation campaigns for the dominance code: write `tools/mutation/mutants_dom_core.py`, `mutants_dominator_tree.py`,
   `mutants_post_dominator_tree.py` (tests: `test_dominance_oom`, `test_dominance_contracts`, `test_dominator_tree`,
   `test_post_dominator_tree`, `test_ssa_verifier`, `test_graph_scc`, `test_alias_analysis`, `test_compiled_code`), run, and
   classify every survivor. Analysis already done: of the six arena checks in each tree builder only the last (`children`)
   can matter, because a failed arena allocation consumes nothing and the last request is the largest (the other five are
   equivalent mutants); the bound on `a` in `dominates` is equivalent by arena layout; mutants that remove the
   `DOM_MAX_NODES` limit inside `dom_csr_build` must not be run in the ASan tree (they would allocate gigabytes).
2. A-050: tighten the lenient assertions in `tests/unit/test_disasm_to_cir.c` and `tests/unit/test_loader_to_disasm.c`.
3. Vector and hashmap mutation modules and campaigns.
4. Run `tests/run_gates.sh` for all five gates, then a clean full re-run of the serializer campaign (302 mutants).
5. Write the ledger rows (A-031 to A-054) and `docs/architecture/PHASE4.5.md`; delete `tools/mutation/__pycache__`.
   Mutants already classified as equivalent, for the rows: logging L04 L07 L31 L64 L75; thread pool T10 T29; PE P04 P16
   P50 P157 P164; database C15 C48 C50 X01 X13 X24 X31 S21 S26 Q36; builder B38 B124 (B47 is killed only by Valgrind);
   serializer 16 equivalents and one unreachable (Z191). Mutation logs are in `docs/audit/evidence/mutation/`.

### Checkpoints 2–5

2. **Phase 3**: a CBAE-owned instruction model; rewrite the function-boundary finder and score it against the unwind
   table (also fixes A-052, PE section-length consumers); apply ELF relocations;
   call-graph import from relocations and symbols (`sym_index` indexes `img->symbols`); harden the CFG builder, including
   unchecked `cbae_vector_push` and `cbae_hashmap_insert` results.
3. **CIR vocabulary**: FLAGS, COND, comparison predicates, zext/sext/trunc, select, switch, indirect jump, unreachable, i128;
   remove unused LEA and TEST; `cir_type_i(bits)` currently maps unsupported widths to I64 silently. Typed phis and
   trivial-phi removal; verifier rules (the SSA verifier result carries no error code; allocation failure is reported as
   `ok=false` with text, consider adding a code); serializer v2; dead-code and simplifier passes; iterative SSA (A-051).
4. **Lifter**: loads for memory operands (the ALU/CMP bug, A-001), narrow registers, unmodelled instructions, flags; checks
   every builder result; a builder constructor for placeholder values. Differential tests against native execution; a
   larger gcc corpus.
5. **Optimisation and close-out**: profile-driven. Known case: `dom_core_compute` is quadratic on a chain of blocks that
   all jump to one shared join (about 0.15 s at 8,000 blocks and 0.95 s at 20,000); options are Semi-NCA or
   Lengauer–Tarjan, decide from the corpus profile. Close the ledger; mutation campaigns and out-of-memory sweeps for the
   Phase 5 analyses; `PHASE4.5.md`.

Long-term, before Phase 6: populate `windows_kernel_api.sql` (about 800 entries) and `linux_kernel_api.sql` (about 600).
Phase 10: QEMU snapshots. Driver loading on real machines: EV code-signing certificate and MOK enrolment.

## 5. Code conventions

- Layers, each a static library: `platform` → `db` → `engine` → `loader` → `disasm` → `cir` → `dataflow`. A layer uses only
  the ones before it.
- Errors: `cbae_err_t` codes (OK 0, GENERIC -1, OOM -2, IO -3, INVALID -4, NOT_FOUND -5, PARSE -6, DB -7, OVERFLOW -8,
  UNSUPPORTED -9, BUSY -10, TIMEOUT -11, THREAD -12). Use `CBAE_RETURN_ERR(code, fmt, ...)`, `CBAE_SET_ERR`, `CBAE_CHECK(expr)`.
  Every allocation and every container insert is checked; a failed operation leaves its output empty and frees what it took.
- `cbae_vector_t {data, elem_size, count, capacity}`: a failed init leaves it all zero, which is the destroyed state
  (destroy is idempotent, push on it returns INVALID, `cbae_vector_at` returns NULL beyond `count`).
- Arena (`platform/memory.h`): bump allocator, zero-filled, exhaustion is `CBAE_ERR_OOM`; a failed allocation does not
  consume space.
- Build flags: `-Wall -Wextra -Wpedantic -fno-strict-aliasing`, `-std=gnu11`. The Release gate fails on any warning. Tests
  are built with `-UNDEBUG` so `assert` stays active. Binaries land in `build/bin`; run tests from `build/tests`.
  Test timeouts: 30 s Debug, 120 s ASan, 400 s TSan.
- Test helpers in `tests/unit/`: `alloc_inject.h` (include first; one per executable), `oom_sweep.h` (fail every allocation
  in turn, or every arena size), `cir_test_util.h`, `cir_random.h`, `dom_reference.h` (brute-force dominators),
  `pe_builder.h` / `elf_builder.h` and the `*_random.h` generators.

## 6. Method

- Failing first: write the test, show it fail on the original code, then fix. Evidence goes in `docs/audit/evidence/`.
- Independent oracles: brute-force definitions or a concrete interpreter that share no code with the code under test.
- Mutation testing: `tools/mutation/mutants_NAME.py` lists `(name, text occurring exactly once, replacement)`. Run on a copy of
  the tree, never the working tree:
  `CBAE_GATES_DIR=<copy>/gates MUT_TIMEOUT=60 python3 -I tools/mutation/run_mut.py NAME [TAGS...]`
  (needs a configured ASan tree at `<copy>/gates/asan`). A survivor is killed by a new test, or classified
  `(equivalent: why)`, `(unreachable: why)` or `(unrunnable: why)`. If a run is interrupted the source may be left
  mutated: check with `git diff`.
- Gates: `tests/run_gates.sh [debug release asan tsan valgrind]`. A checkpoint is done when all five pass and the docs say
  only what was measured.

## 7. Gotchas

- After editing `tests/CMakeLists.txt` run `cmake -S . -B build` again.
- `test_dominance_oom` needs the linker `--wrap` options already set in `tests/CMakeLists.txt`.
- Some editing tools turn a backslash followed by `u` and four hex digits into the character itself. After writing a file,
  check `grep -nP '[^\x00-\x7F]' FILE`; only comment dividers and the existing em dashes belong.
- Keep tool output small and work sequentially; long sessions run out of context. Update this file and `CHANGELOG.md`
  at every delivery so a restart loses nothing.
- Earlier definitions of "done" mentioned a libsqlite3 stress run; no such runner is in this repository. Ask the author
  whether it is still wanted.

## 8. Resuming in a new session

1. Get the code: the repository zip the author attaches (it contains `.git`), or
   `git clone https://github.com/PhillipWanjiru/cbae.git`.
2. Read `README.md`, this file, `docs/ROADMAP.md`, `docs/audit/LEDGER.md`.
3. Build and run `tests/run_gates.sh debug` to confirm the starting point (expect 44/44).
4. Continue with section 4, "Remaining in checkpoint 1".

A prompt to paste into the new session:

> I am continuing the CBAE project (C, x86-64 driver binary analysis). The repository is
> https://github.com/PhillipWanjiru/cbae. Read `CLAUDE.md`, `docs/HANDOFF.md`, `docs/ROADMAP.md` and `docs/audit/LEDGER.md`
> first, run `tests/run_gates.sh debug` to confirm the state, then continue Phase 4.5 where the hand-off says. Tell me which
> phase we are in and how far we have to go as you work.

## 9. Repository and delivery

- GitHub: https://github.com/PhillipWanjiru/cbae. `main` holds one commit per delivery, from Phases 1–2 on; tags
  `phase-1-2`, `phase-3`, `phase-4`, `phase-5` mark finished phases; branches `archive/*` hold the author's earlier Desktop
  copies. Commits are authored as `PhillipWanjiru`.
- Commit at every checkpoint with a message like `Phase 4.5 checkpoint 2: ...`, add a row to `CHANGELOG.md` and update
  section 4 of this file and `docs/ROADMAP.md` in the same commit.
- If the session cannot push, deliver the whole repository folder as a zip, `.git` included. The author unzips it and runs
  `git push`; because it continues the same history, the push is a plain fast-forward.
