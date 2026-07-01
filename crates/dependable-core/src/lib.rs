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
pub mod npmrc;
pub mod parsers;
pub mod result;
pub mod semver;

pub use ecosystem::Ecosystem;
pub use error::ParseError;
pub use item::{Item, PackageSource};
pub use lockfiles::{
    LockedPackage, LockfileData, ResolvedLockfile, apply_lockfile, parse_cargo_lock,
    parse_cargo_lock_graph, parse_composer_lock, parse_dart_pubspec_lock, parse_lockfile,
    parse_mix_lock, parse_package_lock,
};
pub use manifest::{AlternateRegistryDecl, ManifestKind, ParsedManifest};
pub use npmrc::{NpmrcConfig, parse_npmrc};
pub use parsers::{
    CargoTomlParser, ComposerJsonParser, CsprojParser, DenoJsonParser, GoModParser, MixExsParser,
    PackageJsonParser, Parser, PnpmWorkspaceParser, PubspecYamlParser, PyprojectTomlParser,
    RequirementsTxtParser, WorkspaceDecl, parse, parse_cargo_config, parse_package_name,
    parse_workspace,
};
pub use result::{CheckResult, DependencyStatus};
pub use semver::{Evaluation, UnstableFilter, check_version, is_prerelease, to_semver_constraint};
