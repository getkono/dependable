//! Pure, IO-free parsing and version-checking core for `dependable`.
//!
//! Everything here takes `&str` input and returns plain data structures — no
//! filesystem, network, or async — which keeps the crate fully unit-testable
//! without mocking.

pub mod ecosystem;
pub mod error;
pub mod item;
pub mod lockfiles;
pub mod manifest;
pub mod parsers;
pub mod result;
pub mod semver;

pub use ecosystem::Ecosystem;
pub use error::ParseError;
pub use item::{Item, PackageSource};
pub use lockfiles::{LockfileData, apply_lockfile, parse_cargo_lock, parse_lockfile};
pub use manifest::{AlternateRegistryDecl, ManifestKind, ParsedManifest};
pub use parsers::{
    CargoTomlParser, GoModParser, Parser, PyprojectTomlParser, RequirementsTxtParser, parse,
};
pub use result::{CheckResult, DependencyStatus};
pub use semver::{Evaluation, UnstableFilter, check_version, is_prerelease, to_semver_constraint};
