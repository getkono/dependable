//! Lockfile parsers and per-kind dispatch.

use crate::error::ParseError;
use crate::manifest::ManifestKind;

pub mod cargo_lock;
pub mod composer_lock;
pub mod package_lock_json;

pub use cargo_lock::{LockfileData, apply_lockfile, parse_cargo_lock};
pub use composer_lock::parse_composer_lock;
pub use package_lock_json::parse_package_lock;

/// Parse lockfile `content` for a given manifest `kind`, dispatching to the right
/// parser. Returns [`ParseError::Unsupported`] for kinds whose lockfile parser
/// has not landed yet (callers treat that as "no locked versions").
pub fn parse_lockfile(kind: ManifestKind, content: &str) -> Result<LockfileData, ParseError> {
    match kind {
        ManifestKind::CargoToml => parse_cargo_lock(content),
        ManifestKind::PackageJson => parse_package_lock(content),
        ManifestKind::ComposerJson => parse_composer_lock(content),
        other => Err(ParseError::Unsupported(other)),
    }
}
