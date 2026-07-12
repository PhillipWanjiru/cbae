# Rust Integration in CBAE

## Where Rust lives

```
rust/
├── Cargo.toml          workspace manifest
├── cbae_batchd/        batch processing daemon
│   └── src/
│       ├── lib.rs
│       ├── job.rs      Job struct + JobStage enum
│       ├── queue.rs    SQLite-backed persistent job queue
│       ├── worker.rs   worker thread — pulls and executes jobs
│       ├── scheduler.rs manages the worker pool
│       └── ffi.rs      C-compatible FFI exported via cbindgen
└── cbae_ipc/           IPC message layer (daemon ↔ GUI)
    └── src/
        ├── lib.rs
        ├── message.rs  GuiMsg + DaemonMsg typed enums
        ├── socket.rs   length-prefixed framing over Unix socket
        └── ffi.rs      C FFI surface
```

## Why these two components were chosen for Rust

### cbae_batchd — the batch processor

The C implementation (src/batch/*.c) would require:
- A mutex-protected job queue shared across N worker threads
- Condition variables for work signalling
- Reference counting on job structs passed between threads
- Manual memory management of work items

Every one of these is a potential data race or use-after-free.
The batch processor runs as root. A memory corruption bug here
is a privilege escalation vulnerability.

Rust's ownership model makes data races a **compile-time error**.
The crossbeam-channel crate provides a lock-free MPMC queue.
The same logic written in Rust is provably race-free.

### cbae_ipc — the IPC parser

IPC message parsing is a classic attack surface. The GUI process
(Electron, runs as the user) sends messages to the daemon (runs as root).
A malformed message exploiting a buffer overflow in a C parser
would give an attacker root access.

Rust's serde + serde_json parse messages into typed Rust enums.
Any message that parses is structurally valid by construction.
A malformed message returns an Err — no memory corruption possible.

## Integration with CMake

```bash
# Build without Rust (default):
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# Build WITH Rust:
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWITH_RUST=ON
make -j$(nproc)
```

The Rust crates compile to static libraries:
- libcbae_batchd.a
- libcbae_ipc.a

These are linked into cbae_engine via CMake IMPORTED targets.
The C engine calls them via the FFI functions in ffi.rs,
which cbindgen can auto-generate headers for.

## The boundary between C and Rust

```
C (cbae_engine) calls:
  cbae_scheduler_create(db_path, num_workers) -> *CScheduler
  cbae_scheduler_submit(sched, binary_id, path, priority) -> job_id
  cbae_scheduler_destroy(sched)

  cbae_ipc_error_msg(code, message) -> *char  (JSON string)
  cbae_ipc_parse_gui_msg(json)       -> 1/0
  cbae_ipc_free_string(ptr)

Rust handles everything below that boundary.
C never sees threads, channels, or message structs.
```
