# CBAE Architecture

## Layer stack (C core)

```
cbae_platform   (arena, hashmap, vector, string_pool, logging, error)
     |
cbae_db         (SQLite connection, schema migrations, queries, transactions)
     |
cbae_engine     (config loading, lifecycle)
     |
cbae_loader     (PE32+ parser, ELF64 parser -> cbae_binary_image_t)
```

## Rust layer (parallel to the C core, linked in via FFI)

```
rust/cbae_batchd   Batch processing daemon — job queue + worker pool
rust/cbae_ipc      Typed IPC protocol — daemon <-> GUI messages
```

See RUST_INTEGRATION.md for the full rationale.

## Data flow (Phase 2 complete)

```
.sys / .ko file on disk
    |
    v
cbae_pe_load() / cbae_elf_load()
    |
    v
cbae_binary_image_t
  - sections[]     (memory-mapped, zero-copy)
  - symbols[]
  - imports[]
  - relocations[]
  - 4 hashmap indexes for O(1) lookup
    |
    v
(Phase 3: disassembler consumes this to build CFGs)
```
