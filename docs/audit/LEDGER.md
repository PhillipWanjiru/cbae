# CBAE audit ledger

Findings noted while building Phase 5, kept here so the Phase 4.5 audit starts
from a written list rather than from memory. Nothing in this file has been
fixed yet unless its status says so.

Severity: HIGH = wrong results for real driver code; MED = wrong or fragile in
some cases; LOW = hygiene. "Verified" means reproduced by running the code,
not only read.

## Findings

| ID | Where | Finding | Sev | Status |
|----|-------|---------|-----|--------|
| A-001 | Phase 4 lifter | ALU/CMP with a memory operand is lifted wrongly: `add rax,[rbx]` becomes `add rax,rbx`; `cmp [rbx+8],0` compares the address; `add [rbx],5` is dropped. Verified on printed CIR. | HIGH | open |
| A-002 | Phase 4 lifter | Narrow registers (eax/ax/al...) all map to `CBAE_REG_OTHER`: reads become the single parameter "other", writes are dropped. Verified. | HIGH | open |
| A-003 | Phase 4 lifter | Unmodeled instructions emit nothing, so results stay stale: adc, cmovcc, cqo/idiv, one-operand mul, xchg, ror, rep stos, lock xadd. Verified. | HIGH | open |
| A-004 | Phase 4 lifter | Three-operand `imul` is lifted wrongly. Verified. | MED | open |
| A-005 | Phase 4 lifter | `fs:`/`gs:` segment overrides are dropped (`gs:[0x188]` is how Windows x64 drivers reach the current thread). Verified. | HIGH | open |
| A-006 | Phase 4 lifter | Access widths are not modeled; every LOAD/STORE is i64. Vector and string moves wider than 8 bytes therefore look 8 bytes wide, which makes "no overlap" answers unsound for them. | HIGH | open |
| A-007 | Phase 4 lifter | CALL defines RAX but does not clobber the other volatile registers, so values survive calls they would not survive on the machine. | HIGH | open |
| A-008 | Phase 4 lifter | EFLAGS is never modeled and the Jcc condition code is not recorded: branch semantics are lost. | HIGH | open |
| A-009 | `cir_ssa_constructor.c:112-121` | `cbae_cir_phi_create()` result is used without a NULL check, and the `phi_add_incoming` and hashmap-insert results are ignored. When the function arena is spent the builder returns NULL (seen in a test), so SSA construction would dereference NULL instead of returning an error. | MED | open |
| A-010 | `cir_builder.c:272` | `cbae_cir_phi_create()` takes an instruction id before its allocations are checked; a failure leaves a gap and no rollback. | LOW | open |
| A-011 | Release build | `-Wstringop-truncation` at `src/disasm/instruction_lifter.c:77` and `src/cir/cir_serializer.c:102`: check for a missing terminating NUL. | LOW | open |
| A-012 | `cir_verifier.c` | Structural verifier does not check: block 0 has no predecessors; NULL operand slots; operand/result width agreement for binary ops. Dominance is not checked at all (the SSA verifier is a Phase 5 deliverable). | MED | Phase 5 (partly) |
| A-013 | Arena sizing | Arenas have fixed capacity and return NULL when spent. Audit how the lifter and engine size a function's arena for large functions, and that exhaustion surfaces as an error everywhere, never as a crash (see A-009). | MED | open |
| A-014 | `alias_analysis.c` | Precision gap, not a bug: a cluster of phis that refer only to each other and are invariant as a group, with no phi referring to itself (possible with irreducible control flow), stays unresolved (MAY). | LOW | documented |

## Strengths to credit in the audit report

Noted as found, with the evidence, so the report names specifics.

- Arena discipline throughout: no per-object frees to get wrong; every
  failure path in the builder returns NULL instead of corrupting state.
- The CIR invariants are written down and enforced by a verifier
  (`blocks[i]->id == i`, edge/phi consistency, unique ids), which is what let
  Phase 5 analyses assume a clean graph.
- Braun SSA construction and Cooper-Harvey-Kennedy dominators are the right
  algorithm choices for lifted code: simple, fast, and testable against
  brute-force references.
- The lifter's synthetic entry block when the function entry is a branch
  target kept block 0 predecessor-free, which every later analysis relies on.
- Test discipline: hand-derived expectations, brute-force cross-checks on
  random graphs, Valgrind, and mutation testing that found real gaps.
