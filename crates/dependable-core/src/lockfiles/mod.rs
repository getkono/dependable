//! Lockfile parsers. V1 ships the `Cargo.lock` parser.

pub mod cargo_lock;

pub use cargo_lock::{LockfileData, apply_lockfile, parse_cargo_lock};
