//! cbae_ipc — Typed IPC protocol between the C daemon and the Electron GUI.
//!
//! WHY RUST:
//!   IPC message parsing is a classic attack surface.  A malformed JSON
//!   message from a compromised GUI process could exploit a buffer overflow
//!   in a hand-rolled C parser.  Rust's type system and serde guarantee
//!   that any message that parses is also structurally valid.
//!
//! PROTOCOL:
//!   Length-prefixed JSON over Unix domain socket (Linux) or
//!   named pipe (Windows).  Each message is:
//!     [4 bytes little-endian length][UTF-8 JSON payload]

pub mod message;
pub mod socket;
pub mod ffi;

pub use message::{DaemonMsg, GuiMsg};
