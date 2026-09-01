//! Pure, IO-free parsing and version-checking core for `dependable`.
//!
//! Everything here takes `&str` input and returns plain data structures — no
//! filesystem, network, or async — which keeps the crate fully unit-testable
//! without mocking.

pub mod ecosystem;
pub mod error;
pub mod graph;
pub mod item;
pub mod lockfiles;
pub mod manifest;
pub mod npmrc;
pub mod parsers;
pub mod result;
pub mod semver;

pub use ecosystem::Ecosystem;
pub use error::ParseError;
pub use graph::{
    DependencyGraph, Node, NodeKind, PathPredicate, Placement, Tree, TreeNode, TreeOptions, Visit,
    Visitor, WalkOptions,
};
pub use item::{DependencyKind, Item, PackageSource};
pub use lockfiles::{
    LockedPackage, LockfileData, ResolvedLockfile, apply_lockfile, lockfile_items, parse_bun_lock,
    parse_bun_lock_graph, parse_cargo_lock, parse_cargo_lock_graph, parse_composer_lock,
    parse_composer_lock_graph, parse_dart_pubspec_lock, parse_lockfile, parse_lockfile_kind,
    parse_mix_lock, parse_mix_lock_graph, parse_package_lock, parse_package_lock_graph,
    parse_swift_package_resolved, swift_package_name, swift_package_name_variants,
    swift_package_resolved_items,
};
pub use manifest::{
    AlternateRegistryDecl, LockfileKind, ManifestKind, ParsedManifest, UNREADABLE_MANIFESTS,
    UnreadableLockfile, UnreadableManifest, WorkspaceRoots,
};
pub use npmrc::{NpmrcConfig, parse_npmrc};
pub use parsers::{
    AutoTargets, CargoPackageManifest, CargoTarget, CargoTargetKind, CargoTomlParser,
    CfgDependencyTable, ComposerJsonParser, CsprojParser, DenoJsonParser, DependencySection,
    GoModParser, GradleCatalogParser, MixExsParser, PackageField, PackageJsonParser,
    PackageSwiftParser, Parser, PnpmWorkspaceParser, PomXmlParser, ProjectMeta, ProjectRole,
    PubspecYamlParser, PyprojectTomlParser, RequirementsTxtParser, WorkspaceDecl, parse,
    parse_cargo_config, parse_package_manifest, parse_package_name, parse_project, parse_workspace,
    resolve_workspace_inheritance,
};
pub use result::{CheckResult, DependencyStatus};
pub use semver::{Evaluation, UnstableFilter, check_version, is_prerelease, to_semver_constraint};
