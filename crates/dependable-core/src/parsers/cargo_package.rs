//! Reader for a `Cargo.toml`'s **package declaration** — the build-time variation
//! surface, as opposed to the dependency list [`cargo_toml`](super::cargo_toml)
//! already collects.
//!
//! Three things live here that a dependency checker does not need but a build-aware
//! consumer does: the `[features]` table (and the implicit features that optional
//! dependencies create), the declared build targets, and the `cfg`-gated dependency
//! tables under `[target.'cfg(…)']`.
//!
//! Like the rest of `dependable-core` this is IO-free, which bounds what it can
//! answer. Cargo discovers targets from the filesystem (`src/lib.rs`, `src/bin/*.rs`,
//! `tests/*.rs`, `build.rs`, …) and resolves `field.workspace = true` against the
//! workspace root's manifest. Neither is possible from one `&str`, so this reader
//! reports what the manifest *declares* — [`CargoTarget`]s written out explicitly, and
//! inheritance markers ([`PackageField::Workspace`]) the caller resolves against
//! [`WorkspaceDecl::package_defaults`](super::cargo_workspace::WorkspaceDecl). The
//! [`auto_targets`](CargoPackageManifest::auto_targets) flags say whether Cargo's
//! own discovery is even enabled, so a caller with filesystem access knows when to run it.

use std::collections::BTreeMap;

use toml_edit::{ImDocument, Item as TomlItem, TableLike};

use super::cargo_toml::collect_dependencies;
use super::position::line_starts;
use crate::error::ParseError;
use crate::item::Item;

/// A `[package]` field that may be inherited from the workspace root.
///
/// Cargo lets `version`, `edition`, and `rust-version` (among others) be written as
/// `field.workspace = true`; resolving that needs the workspace manifest, which an
/// IO-free reader does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackageField {
    /// The value written literally in this manifest.
    Literal(String),
    /// `field.workspace = true` — resolve against the workspace root's
    /// `[workspace.package]` table.
    Workspace,
}

impl PackageField {
    /// The literal value, or `None` when the field is inherited.
    #[must_use]
    pub fn literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Workspace => None,
        }
    }

    /// Resolve against a workspace `[workspace.package]` table, returning the literal
    /// value when this field is not inherited.
    #[must_use]
    pub fn resolve<'a>(
        &'a self,
        defaults: &'a BTreeMap<String, String>,
        key: &str,
    ) -> Option<&'a str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Workspace => defaults.get(key).map(String::as_str),
        }
    }
}

/// The kind of a declared Cargo build target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CargoTargetKind {
    /// `[lib]`.
    Lib,
    /// `[[bin]]`.
    Bin,
    /// `[[test]]`.
    Test,
    /// `[[bench]]`.
    Bench,
    /// `[[example]]`.
    Example,
    /// The `[package] build` script, however it is written (`build = "…"`, the
    /// `build = true` shorthand for a root `build.rs`, or one entry of a
    /// `multiple-build-scripts` array).
    BuildScript,
}

impl CargoTargetKind {
    /// The manifest table name this kind is declared under (`"lib"`, `"bin"`, …).
    #[must_use]
    pub fn table_name(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Bin => "bin",
            Self::Test => "test",
            Self::Bench => "bench",
            Self::Example => "example",
            Self::BuildScript => "build",
        }
    }
}

/// One declared build target.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CargoTarget {
    /// Which kind of target this is.
    pub kind: CargoTargetKind,
    /// The target's `name`, when declared. A `[lib]` without one takes the package name.
    pub name: Option<String>,
    /// The target's `path`, when declared.
    pub path: Option<String>,
    /// `required-features` — the target is only built when all of these are enabled.
    pub required_features: Vec<String>,
}

/// Which dependency section a `cfg`-gated table belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DependencySection {
    /// `[dependencies]`.
    Normal,
    /// `[dev-dependencies]`.
    Dev,
    /// `[build-dependencies]`.
    Build,
}

/// One `[target.<predicate>.<section>]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CfgDependencyTable {
    /// The table key exactly as written: either a `cfg(…)` expression or a target
    /// triple such as `x86_64-pc-windows-msvc`. Not parsed — callers that understand
    /// `cfg` syntax evaluate it themselves.
    pub predicate: String,
    /// Which dependency section the table gates.
    pub section: DependencySection,
    /// The dependencies declared under it, parsed exactly as the top-level sections are.
    pub items: Vec<Item>,
}

/// Whether Cargo's filesystem target auto-discovery is enabled, per target kind.
///
/// All default to `true`, matching Cargo. A caller with filesystem access uses these to
/// decide whether to look for `src/lib.rs`, `src/bin/*.rs`, `tests/*.rs`, `build.rs`, and
/// so on. Every flag reads the same way: `true` means "Cargo will discover this kind from
/// the filesystem, so you should too".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AutoTargets {
    /// `autolib` — discover `src/lib.rs`.
    pub lib: bool,
    /// `autobins` — discover `src/main.rs` and `src/bin/`.
    pub bins: bool,
    /// `autotests` — discover `tests/`.
    pub tests: bool,
    /// `autobenches` — discover `benches/`.
    pub benches: bool,
    /// `autoexamples` — discover `examples/`.
    pub examples: bool,
    /// `build` — discover a `build.rs` at the package root. `true` only when the manifest
    /// writes no `build` key at all, which is the one case Cargo answers from the
    /// filesystem. Every explicit value settles the question in the manifest instead:
    /// `build = false` turns the script off outright, while `build = true`, `build = "…"`,
    /// and an array of paths name the scripts in
    /// [`targets`](CargoPackageManifest::targets). In all of them a caller must *not*
    /// discover, or it would attach a root `build.rs` Cargo never runs.
    pub build: bool,
}

impl Default for AutoTargets {
    fn default() -> Self {
        Self {
            lib: true,
            bins: true,
            tests: true,
            benches: true,
            examples: true,
            build: true,
        }
    }
}

/// A `Cargo.toml`'s package declaration: identity, features, targets, and `cfg`-gated
/// dependency tables.
///
/// Every field reflects only what the manifest declares — see the [module
/// docs](self) for what an IO-free reader cannot resolve.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CargoPackageManifest {
    /// `[package] name`. Absent for a virtual workspace manifest.
    pub name: Option<String>,
    /// `[package] version`, possibly inherited.
    pub version: Option<PackageField>,
    /// `[package] edition`, possibly inherited.
    pub edition: Option<PackageField>,
    /// `[package] rust-version`, possibly inherited.
    pub rust_version: Option<PackageField>,
    /// The `[features]` table: each feature mapped to the features and optional
    /// dependencies it enables, exactly as written (including `dep:` and `pkg/feat` forms).
    pub features: BTreeMap<String, Vec<String>>,
    /// Dependencies marked `optional = true` in a section that gives them an implicit
    /// feature — `dependencies` and `build-dependencies`, top-level or under a
    /// `[target.<predicate>.…]` table — sorted and deduplicated. Each one Cargo turns
    /// into an implicit feature of the same name unless some feature already refers to
    /// it as `dep:<name>`. `dev-dependencies` never contributes: Cargo rejects an
    /// optional dev-dependency outright.
    pub optional_dependencies: Vec<String>,
    /// Explicitly declared build targets, grouped by kind in [`CargoTargetKind`]
    /// declaration order and, within a kind, in manifest order.
    pub targets: Vec<CargoTarget>,
    /// Whether Cargo's own filesystem target discovery is enabled.
    pub auto_targets: AutoTargets,
    /// `[target.<predicate>.<section>]` tables: predicates in manifest order, and the
    /// three sections of one predicate always normal → dev → build.
    pub cfg_dependency_tables: Vec<CfgDependencyTable>,
}

impl CargoPackageManifest {
    /// The members of the `default` feature, or an empty slice when there is none.
    #[must_use]
    pub fn default_features(&self) -> &[String] {
        self.features.get("default").map_or(&[][..], Vec::as_slice)
    }

    /// Every feature name a consumer may enable: the declared features plus the
    /// implicit one each entry of [`optional_dependencies`](Self::optional_dependencies)
    /// creates.
    ///
    /// An optional dependency referred to as `dep:<name>` by some feature does *not*
    /// get an implicit feature, matching Cargo's rule.
    #[must_use]
    pub fn feature_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.features.keys().cloned().collect();
        for dep in &self.optional_dependencies {
            let claimed = self
                .features
                .values()
                .flatten()
                .any(|entry| entry.strip_prefix("dep:").is_some_and(|d| d == dep));
            if !claimed && !self.features.contains_key(dep) {
                names.push(dep.clone());
            }
        }
        names.sort();
        names.dedup();
        names
    }
}

/// Sections a target-gated table may declare, paired with their [`DependencySection`].
const TARGET_SECTIONS: &[(&str, DependencySection)] = &[
    ("dependencies", DependencySection::Normal),
    ("dev-dependencies", DependencySection::Dev),
    ("build-dependencies", DependencySection::Build),
];

/// Sections whose optional dependencies gain an implicit feature.
///
/// Deliberately *not* [`TARGET_SECTIONS`]: the two section sets answer different
/// questions. Every one of the three sections holds real dependencies, so
/// [`cfg_dependency_tables`] reads all of them — but Cargo refuses to load a manifest
/// with an optional dev-dependency at all ("dev-dependencies are not allowed to be
/// optional"), so only these two can ever produce a feature.
const IMPLICIT_FEATURE_SECTIONS: &[&str] = &["dependencies", "build-dependencies"];

/// Kinds declared as arrays of tables (`[[bin]]`), paired with their table name.
const ARRAY_TARGETS: &[(&str, CargoTargetKind)] = &[
    ("bin", CargoTargetKind::Bin),
    ("test", CargoTargetKind::Test),
    ("bench", CargoTargetKind::Bench),
    ("example", CargoTargetKind::Example),
];

/// Parse a `Cargo.toml`'s package declaration.
///
/// A virtual workspace manifest (no `[package]`) parses successfully into a value whose
/// `name` is `None` — it can still carry `[target.…]` tables, so this is not an error.
///
/// # Errors
/// [`ParseError`] if `content` is not valid TOML.
pub fn parse_package_manifest(content: &str) -> Result<CargoPackageManifest, ParseError> {
    let doc = ImDocument::parse(content.to_owned())?;
    let root = doc.as_table();
    let starts = line_starts(content);
    let package = root.get("package").and_then(TomlItem::as_table_like);

    Ok(CargoPackageManifest {
        name: package
            .and_then(|p| p.get("name"))
            .and_then(TomlItem::as_str)
            .map(str::to_owned),
        version: package.and_then(|p| package_field(p, "version")),
        edition: package.and_then(|p| package_field(p, "edition")),
        rust_version: package.and_then(|p| package_field(p, "rust-version")),
        features: features_table(root),
        optional_dependencies: optional_dependencies(root),
        targets: targets(root, package),
        auto_targets: auto_targets(package),
        cfg_dependency_tables: cfg_dependency_tables(root, &starts),
    })
}

/// Read one `[package]` field, distinguishing a literal from `field.workspace = true`.
fn package_field(package: &dyn TableLike, key: &str) -> Option<PackageField> {
    let item = package.get(key)?;
    if let Some(value) = item.as_str() {
        return Some(PackageField::Literal(value.to_owned()));
    }
    // `version.workspace = true` (or `= false`, which Cargo rejects — treat only
    // `true` as inheritance and ignore the rest).
    let inherits = item
        .as_table_like()
        .and_then(|t| t.get("workspace"))
        .and_then(TomlItem::as_bool)
        == Some(true);
    inherits.then_some(PackageField::Workspace)
}

/// Collect the `[features]` table.
fn features_table(root: &dyn TableLike) -> BTreeMap<String, Vec<String>> {
    let Some(table) = root.get("features").and_then(TomlItem::as_table_like) else {
        return BTreeMap::new();
    };
    table
        .iter()
        .map(|(name, item)| {
            let enables = item
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            (name.to_owned(), enables)
        })
        .collect()
}

/// Every dependency marked `optional = true` in a section that gives it an implicit
/// feature: [`IMPLICIT_FEATURE_SECTIONS`] at the top level, and the same sections under
/// every `[target.<predicate>.…]` table.
fn optional_dependencies(root: &dyn TableLike) -> Vec<String> {
    let mut optional = Vec::new();
    let mut collect = |table: &dyn TableLike| {
        for (name, item) in table.iter() {
            let is_optional = item
                .as_table_like()
                .and_then(|t| t.get("optional"))
                .and_then(TomlItem::as_bool)
                == Some(true);
            if is_optional {
                optional.push(name.to_owned());
            }
        }
    };

    for section in IMPLICIT_FEATURE_SECTIONS {
        if let Some(table) = root.get(section).and_then(TomlItem::as_table_like) {
            collect(table);
        }
    }

    // A `cfg`-gated optional dependency creates the same implicit feature its top-level
    // twin would; the predicate only gates whether the dependency is pulled in.
    if let Some(targets) = root.get("target").and_then(TomlItem::as_table_like) {
        for (_, item) in targets.iter() {
            let Some(entry) = item.as_table_like() else {
                continue;
            };
            for section in IMPLICIT_FEATURE_SECTIONS {
                if let Some(table) = entry.get(section).and_then(TomlItem::as_table_like) {
                    collect(table);
                }
            }
        }
    }

    optional.sort();
    optional.dedup();
    optional
}

/// Collect explicitly declared targets: `[lib]`, the `[[bin]]`-style arrays, and the
/// `[package] build` script.
fn targets(root: &dyn TableLike, package: Option<&dyn TableLike>) -> Vec<CargoTarget> {
    let mut targets = Vec::new();

    if let Some(lib) = root.get("lib").and_then(TomlItem::as_table_like) {
        targets.push(target_from(CargoTargetKind::Lib, lib));
    }

    for (key, kind) in ARRAY_TARGETS {
        let Some(item) = root.get(key) else { continue };
        // `[[bin]]` is an array of tables; a lone `[bin]` table is malformed but cheap
        // to accept, so both shapes are read.
        if let Some(array) = item.as_array_of_tables() {
            for table in array {
                targets.push(target_from(*kind, table));
            }
        } else if let Some(table) = item.as_table_like() {
            targets.push(target_from(*kind, table));
        }
    }

    // `build = "…"`, `build = true`, and the `multiple-build-scripts` array all declare
    // scripts — one target per path; `build = false` declares none and is reported
    // through [`AutoTargets::build`] instead.
    let scripts = package
        .and_then(|p| p.get("build"))
        .map(build_scripts)
        .unwrap_or_default();
    for path in scripts {
        targets.push(CargoTarget {
            kind: CargoTargetKind::BuildScript,
            name: None,
            path: Some(path),
            required_features: Vec::new(),
        });
    }

    targets
}

/// Every script path a `[package] build` value declares, in manifest order.
///
/// A string is the one path as written; `build = true` is Cargo's shorthand for a
/// `build.rs` at the package root, which it expands to the same declared target; an array
/// of paths is the `multiple-build-scripts` form, which declares one target each.
/// `build = false` declares none, and so does every remaining TOML type — Cargo refuses
/// to load a manifest whose `build` is an integer or a table (`invalid type: integer`,
/// `invalid type: map`), so there is nothing there for a caller to be told about.
fn build_scripts(build: &TomlItem) -> Vec<String> {
    if let Some(path) = build.as_str() {
        return vec![path.to_owned()];
    }
    if let Some(paths) = build.as_array() {
        return paths
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
    }
    if build.as_bool() == Some(true) {
        return vec!["build.rs".to_owned()];
    }
    Vec::new()
}

/// Read one target table's `name`, `path`, and `required-features`.
fn target_from(kind: CargoTargetKind, table: &dyn TableLike) -> CargoTarget {
    let string = |key| table.get(key).and_then(TomlItem::as_str).map(str::to_owned);
    let required_features = table
        .get("required-features")
        .and_then(TomlItem::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    CargoTarget {
        kind,
        name: string("name"),
        path: string("path"),
        required_features,
    }
}

/// Read the discovery flags — the `auto*` keys and `build` — each defaulting to Cargo's
/// `true`.
fn auto_targets(package: Option<&dyn TableLike>) -> AutoTargets {
    let flag = |key: &str| {
        package
            .and_then(|p| p.get(key))
            .and_then(TomlItem::as_bool)
            .unwrap_or(true)
    };
    AutoTargets {
        lib: flag("autolib"),
        bins: flag("autobins"),
        tests: flag("autotests"),
        benches: flag("autobenches"),
        examples: flag("autoexamples"),
        // `build` is the one key here that is not a discovery flag at all — it is the
        // script declaration — so it cannot use `flag`, which would read `build = true`
        // and a declared path alike as "discover". Only an absent key leaves anything to
        // discover; every explicit value either names the script or turns it off.
        build: package.is_none_or(|p| p.get("build").is_none()),
    }
}

/// Collect every `[target.<predicate>.<section>]` dependency table.
fn cfg_dependency_tables(root: &dyn TableLike, starts: &[usize]) -> Vec<CfgDependencyTable> {
    let Some(targets) = root.get("target").and_then(TomlItem::as_table_like) else {
        return Vec::new();
    };
    let mut tables = Vec::new();
    for (predicate, item) in targets.iter() {
        let Some(entry) = item.as_table_like() else {
            continue;
        };
        for (section, kind) in TARGET_SECTIONS {
            let Some(deps) = entry.get(section).and_then(TomlItem::as_table_like) else {
                continue;
            };
            let mut items = Vec::new();
            collect_dependencies(deps, starts, &mut items);
            tables.push(CfgDependencyTable {
                predicate: predicate.to_owned(),
                section: *kind,
                items,
            });
        }
    }
    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> CargoPackageManifest {
        parse_package_manifest(content).expect("valid TOML")
    }

    #[test]
    fn reads_package_identity_and_inheritance() {
        let manifest = parse(
            r#"
[package]
name = "karet-seam"
version.workspace = true
edition = "2024"
rust-version = "1.92"
"#,
        );
        assert_eq!(manifest.name.as_deref(), Some("karet-seam"));
        assert_eq!(manifest.version, Some(PackageField::Workspace));
        assert_eq!(
            manifest.edition.as_ref().and_then(PackageField::literal),
            Some("2024")
        );
        assert_eq!(
            manifest
                .rust_version
                .as_ref()
                .and_then(PackageField::literal),
            Some("1.92")
        );
    }

    #[test]
    fn inherited_field_resolves_against_workspace_defaults() {
        let manifest = parse("[package]\nname = \"x\"\nversion.workspace = true\n");
        let mut defaults = BTreeMap::new();
        defaults.insert("version".to_owned(), "0.5.0".to_owned());
        let version = manifest.version.expect("version present");
        assert_eq!(version.resolve(&defaults, "version"), Some("0.5.0"));
        assert_eq!(version.literal(), None);
    }

    #[test]
    fn virtual_manifest_has_no_package_name() {
        let manifest = parse("[workspace]\nmembers = [\"crates/*\"]\n");
        assert_eq!(manifest.name, None);
        assert!(manifest.features.is_empty());
        assert!(manifest.targets.is_empty());
        // No `[package]` table settles nothing, so every flag — `build` included — keeps
        // Cargo's default: a caller with the filesystem still decides.
        assert_eq!(manifest.auto_targets, AutoTargets::default());
    }

    #[test]
    fn reads_features_and_their_members() {
        let manifest = parse(
            r#"
[features]
default = ["view"]
view = ["dep:ratatui"]
all-languages = ["lang-rust", "lang-python"]
lang-rust = []
lang-python = []
"#,
        );
        assert_eq!(manifest.default_features(), ["view"]);
        assert_eq!(
            manifest.features.get("all-languages").map(Vec::as_slice),
            Some(&["lang-rust".to_owned(), "lang-python".to_owned()][..])
        );
        assert_eq!(manifest.features.get("lang-rust").map(Vec::len), Some(0));
    }

    #[test]
    fn default_features_is_empty_without_a_default_feature() {
        let manifest = parse("[features]\nview = []\n");
        assert!(manifest.default_features().is_empty());
    }

    #[test]
    fn optional_dependencies_become_implicit_features() {
        let manifest = parse(
            r#"
[dependencies]
serde = { version = "1", optional = true }
ratatui = { version = "0.30", optional = true }
thiserror = "2"

[features]
view = ["dep:ratatui"]
"#,
        );
        // `ratatui` is claimed by `dep:ratatui`, so only `serde` gains an implicit feature.
        assert_eq!(manifest.optional_dependencies, ["ratatui", "serde"]);
        assert_eq!(manifest.feature_names(), ["serde", "view"]);
    }

    #[test]
    fn optional_build_dependencies_count_but_dev_ones_do_not() {
        let manifest = parse(
            r#"
[dev-dependencies]
tempfile = { version = "3", optional = true }

[build-dependencies]
cc = { version = "1", optional = true }
"#,
        );
        // Cargo rejects an optional dev-dependency outright, so `tempfile` never becomes
        // a feature — only the build-dependency does.
        assert_eq!(manifest.optional_dependencies, ["cc"]);
        assert_eq!(manifest.feature_names(), ["cc"]);
    }

    #[test]
    fn cfg_gated_optional_dependency_becomes_an_implicit_feature() {
        let manifest = parse(
            r#"
[target.'cfg(unix)'.dependencies]
libc = { version = "0.2", optional = true }

[target.'cfg(windows)'.build-dependencies]
cc = { version = "1", optional = true }

[target.'cfg(windows)'.dev-dependencies]
tempfile = { version = "3", optional = true }
"#,
        );
        assert_eq!(manifest.optional_dependencies, ["cc", "libc"]);
        assert_eq!(manifest.feature_names(), ["cc", "libc"]);
    }

    #[test]
    fn dep_reference_suppresses_a_cfg_gated_implicit_feature() {
        let manifest = parse(
            r#"
[features]
unix-support = ["dep:libc"]

[target.'cfg(unix)'.dependencies]
libc = { version = "0.2", optional = true }
"#,
        );
        assert_eq!(manifest.optional_dependencies, ["libc"]);
        assert_eq!(manifest.feature_names(), ["unix-support"]);
    }

    #[test]
    fn reads_declared_targets_in_manifest_order() {
        let manifest = parse(
            r#"
[package]
name = "karet"
build = "build.rs"

[lib]
name = "karet_lib"
path = "src/lib.rs"

[[bin]]
name = "karet"
path = "src/main.rs"

[[bin]]
name = "karet-helper"
required-features = ["extras"]

[[example]]
name = "demo"

[[bench]]
name = "throughput"

[[test]]
name = "integration"
"#,
        );
        let kinds: Vec<_> = manifest.targets.iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            [
                CargoTargetKind::Lib,
                CargoTargetKind::Bin,
                CargoTargetKind::Bin,
                CargoTargetKind::Test,
                CargoTargetKind::Bench,
                CargoTargetKind::Example,
                CargoTargetKind::BuildScript,
            ]
        );
        let helper = manifest
            .targets
            .iter()
            .find(|t| t.name.as_deref() == Some("karet-helper"))
            .expect("helper bin");
        assert_eq!(helper.required_features, ["extras"]);
        let build = manifest
            .targets
            .iter()
            .find(|t| t.kind == CargoTargetKind::BuildScript)
            .expect("build script");
        assert_eq!(build.path.as_deref(), Some("build.rs"));
        // The script is declared, so there is nothing left for a caller to discover.
        assert!(!manifest.auto_targets.build);
    }

    #[test]
    fn build_false_declares_no_build_script_and_disables_discovery() {
        let manifest = parse("[package]\nname = \"x\"\nbuild = false\n");
        assert!(
            !manifest
                .targets
                .iter()
                .any(|t| t.kind == CargoTargetKind::BuildScript)
        );
        // Nothing is declared *and* Cargo runs no script, so a filesystem-aware caller
        // must not fall back to a `build.rs` still sitting on disk.
        assert!(!manifest.auto_targets.build);
    }

    #[test]
    fn build_discovery_is_enabled_only_when_the_key_is_absent() {
        let script_paths = |manifest: &CargoPackageManifest| -> Vec<Option<String>> {
            manifest
                .targets
                .iter()
                .filter(|t| t.kind == CargoTargetKind::BuildScript)
                .map(|t| t.path.clone())
                .collect()
        };

        // Absent key: Cargo looks for a root `build.rs` itself, so a caller should too.
        let absent = parse("[package]\nname = \"x\"\n");
        assert!(script_paths(&absent).is_empty());
        assert!(absent.auto_targets.build);

        // `build = false`: no script at all, nothing to discover.
        let disabled = parse("[package]\nname = \"x\"\nbuild = false\n");
        assert!(script_paths(&disabled).is_empty());
        assert!(!disabled.auto_targets.build);

        // `build = true`: Cargo's shorthand for a root `build.rs`, declared outright —
        // the target exists even when no `build.rs` is on disk, and discovery is moot.
        let shorthand = parse("[package]\nname = \"x\"\nbuild = true\n");
        assert_eq!(script_paths(&shorthand), [Some("build.rs".to_owned())]);
        assert!(!shorthand.auto_targets.build);

        // A named path: declared just the same, and discovery must stay off or a caller
        // would attach a root `build.rs` Cargo never runs.
        let named = parse("[package]\nname = \"x\"\nbuild = \"scripts/build.rs\"\n");
        assert_eq!(script_paths(&named), [Some("scripts/build.rs".to_owned())]);
        assert!(!named.auto_targets.build);

        // The `multiple-build-scripts` array: one target per path, in manifest order.
        let several = parse("[package]\nname = \"x\"\nbuild = [\"build.rs\", \"b2.rs\"]\n");
        assert_eq!(
            script_paths(&several),
            [Some("build.rs".to_owned()), Some("b2.rs".to_owned())]
        );
        assert!(!several.auto_targets.build);

        // Any other type declares nothing — Cargo refuses to load such a manifest at
        // all, so no caller ever sees the answer.
        let rejected = parse("[package]\nname = \"x\"\nbuild = 3\n");
        assert!(script_paths(&rejected).is_empty());
    }

    #[test]
    fn auto_target_flags_default_to_enabled_and_can_be_disabled() {
        assert_eq!(
            parse("[package]\nname = \"x\"\n").auto_targets,
            AutoTargets::default()
        );
        let manifest = parse(
            r#"
[package]
name = "x"
autobins = false
autotests = false
"#,
        );
        assert!(!manifest.auto_targets.bins);
        assert!(!manifest.auto_targets.tests);
        assert!(manifest.auto_targets.lib);
        assert!(manifest.auto_targets.benches);
        assert!(manifest.auto_targets.examples);
    }

    #[test]
    fn reads_cfg_gated_dependency_tables() {
        let manifest = parse(
            r#"
[target.'cfg(unix)'.dependencies]
nix = "0.29"

[target.'cfg(windows)'.dev-dependencies]
winapi = "0.3"

[target.x86_64-pc-windows-msvc.build-dependencies]
cc = "1.2"
"#,
        );
        assert_eq!(manifest.cfg_dependency_tables.len(), 3);
        let unix = manifest
            .cfg_dependency_tables
            .iter()
            .find(|t| t.predicate == "cfg(unix)")
            .expect("unix table");
        assert_eq!(unix.section, DependencySection::Normal);
        assert_eq!(unix.items.len(), 1);
        assert_eq!(unix.items[0].name, "nix");
        assert_eq!(unix.items[0].version_constraint, "0.29");

        let sections: Vec<_> = manifest
            .cfg_dependency_tables
            .iter()
            .map(|t| t.section)
            .collect();
        assert!(sections.contains(&DependencySection::Dev));
        assert!(sections.contains(&DependencySection::Build));

        let triple = manifest
            .cfg_dependency_tables
            .iter()
            .find(|t| t.predicate == "x86_64-pc-windows-msvc")
            .expect("triple table");
        assert_eq!(triple.items[0].name, "cc");
    }

    #[test]
    fn cfg_table_records_version_positions_for_fixes() {
        let content = "[target.'cfg(unix)'.dependencies]\nnix = \"0.29\"\n";
        let manifest = parse(content);
        let item = &manifest.cfg_dependency_tables[0].items[0];
        // Coordinates are zero-indexed, and the columns bracket the constraint
        // without its surrounding quotes.
        assert_eq!(item.version_line, 1);
        let line = content.lines().nth(1).expect("second line");
        assert_eq!(&line[item.version_col_start..item.version_col_end], "0.29");
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(parse_package_manifest("[package\nname = \"x\"").is_err());
    }

    #[test]
    fn table_name_round_trips_every_kind() {
        assert_eq!(CargoTargetKind::Lib.table_name(), "lib");
        assert_eq!(CargoTargetKind::Bin.table_name(), "bin");
        assert_eq!(CargoTargetKind::Test.table_name(), "test");
        assert_eq!(CargoTargetKind::Bench.table_name(), "bench");
        assert_eq!(CargoTargetKind::Example.table_name(), "example");
        assert_eq!(CargoTargetKind::BuildScript.table_name(), "build");
    }
}
