//! Lockfile parsers and per-kind dispatch.

use crate::error::ParseError;
use crate::manifest::{LockfileKind, ManifestKind};

pub mod bun_lock;
pub mod bun_lock_graph;
pub mod cargo_lock;
pub mod cargo_lock_graph;
pub mod composer_lock;
pub mod composer_lock_graph;
pub mod dart_pubspec_lock;
pub mod mix_lock;
pub mod mix_lock_graph;
pub mod package_lock_graph;
pub mod package_lock_json;

pub use bun_lock::parse_bun_lock;
pub use bun_lock_graph::parse_bun_lock_graph;
pub use cargo_lock::{LockfileData, apply_lockfile, parse_cargo_lock};
pub use cargo_lock_graph::{LockedPackage, ResolvedLockfile, parse_cargo_lock_graph};
pub use composer_lock::parse_composer_lock;
pub use composer_lock_graph::parse_composer_lock_graph;
pub use dart_pubspec_lock::parse_dart_pubspec_lock;
pub use mix_lock::parse_mix_lock;
pub use mix_lock_graph::parse_mix_lock_graph;
pub use package_lock_graph::parse_package_lock_graph;
pub use package_lock_json::parse_package_lock;

/// Parse lockfile `content` with the parser for the file that was found.
///
/// Dispatching on the lockfile rather than on the manifest beside it is what
/// lets one ecosystem have several: a `package.json` says nothing about which
/// package manager wrote the lockfile next to it.
///
/// # Errors
/// Never fails on the kind itself — every [`LockfileKind`] has a parser. Returns
/// the parser's own error when the content does not read.
pub fn parse_lockfile_kind(kind: LockfileKind, content: &str) -> Result<LockfileData, ParseError> {
    match kind {
        LockfileKind::CargoLock => parse_cargo_lock(content),
        LockfileKind::PackageLockJson => parse_package_lock(content),
        LockfileKind::BunLock => parse_bun_lock(content),
        LockfileKind::ComposerLock => parse_composer_lock(content),
        LockfileKind::PubspecLock => parse_dart_pubspec_lock(content),
        LockfileKind::MixLock => parse_mix_lock(content),
    }
}

/// Parse lockfile `content` for a manifest `kind`, using its first lockfile.
///
/// Retained for callers that have a manifest and no particular lockfile in
/// hand. Prefer [`parse_lockfile_kind`] where the file is actually known.
///
/// # Errors
/// Returns [`ParseError::Unsupported`] for manifest kinds with no lockfile we
/// read (callers treat that as "no locked versions").
pub fn parse_lockfile(kind: ManifestKind, content: &str) -> Result<LockfileData, ParseError> {
    let Some(lockfile) = kind.lockfiles().first() else {
        return Err(ParseError::Unsupported(kind));
    };
    parse_lockfile_kind(*lockfile, content)
}
