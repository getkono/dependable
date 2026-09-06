//! Manifest-level types: what kind of manifest, and the result of parsing one.

use std::path::Path;

use crate::ecosystem::Ecosystem;
use crate::item::Item;
use crate::parsers::parse_workspace;

/// The result of parsing a manifest: its kind and the dependencies it declares.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedManifest {
    /// The kind of manifest that was parsed.
    pub kind: ManifestKind,
    /// The dependencies declared in the manifest, in source order.
    pub items: Vec<Item>,
    /// Alternate registry declarations (Rust `[registries.*]`).
    pub alternate_registries: Vec<AlternateRegistryDecl>,
    /// What the parser saw and deliberately did not read, in the parser's own
    /// words, ready to print.
    ///
    /// Not errors and not warnings *about* the dependencies in
    /// [`items`](Self::items): each one names a construct this parser declines to
    /// interpret, so that a list which reads as complete and is not says so.
    /// A Maven `<profiles>` block holding dependencies is the motivating case —
    /// excluding conditional dependencies is defensible, printing
    /// `(0 dependencies)` for a POM that declares twelve of them is not.
    ///
    /// Empty for every parser that has nothing to declare, which is most of them.
    pub notices: Vec<String>,
}

/// A declared alternate registry (Rust only).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AlternateRegistryDecl {
    /// The registry alias used by `registry = "..."` entries.
    pub name: String,
    /// The sparse-index URL, if declared.
    pub index_url: Option<String>,
    /// An auth token for the registry, if declared.
    pub auth_token: Option<String>,
}

/// Distinguishes manifest files. Every variant has a parser; the mapping to
/// [`Ecosystem`] is many-to-one, since several manifest formats can belong to one
/// registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestKind {
    CargoToml,
    GoMod,
    PackageJson,
    DenoJson,
    PnpmWorkspaceYaml,
    ComposerJson,
    RequirementsTxt,
    PyprojectToml,
    PubspecYaml,
    MixExs,
    Csproj,
    GradleVersionCatalog,
    PomXml,
    /// SwiftPM's `Package.swift`.
    ///
    /// Its parser reads no dependencies at all, deliberately — the file is a Swift
    /// program, not data. The dependency list comes from its `Package.resolved`,
    /// which [`LockfileKind::is_dependency_source`] marks as a source of items
    /// rather than an annotation on them.
    PackageSwift,
}

impl ManifestKind {
    /// The ecosystem this manifest belongs to.
    #[must_use]
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            ManifestKind::CargoToml => Ecosystem::Rust,
            ManifestKind::GoMod => Ecosystem::Go,
            ManifestKind::PackageJson
            | ManifestKind::DenoJson
            | ManifestKind::PnpmWorkspaceYaml => Ecosystem::Npm,
            ManifestKind::ComposerJson => Ecosystem::Php,
            ManifestKind::RequirementsTxt | ManifestKind::PyprojectToml => Ecosystem::Python,
            ManifestKind::PubspecYaml => Ecosystem::Dart,
            ManifestKind::MixExs => Ecosystem::Elixir,
            ManifestKind::Csproj => Ecosystem::CSharp,
            ManifestKind::GradleVersionCatalog | ManifestKind::PomXml => Ecosystem::Jvm,
            ManifestKind::PackageSwift => Ecosystem::Swift,
        }
    }

    /// The sibling lockfiles this manifest kind may have, in precedence order.
    ///
    /// A manifest is not tied to one lockfile: a `package.json` is governed by
    /// whichever of several a package manager wrote, and the first one actually
    /// present wins. Ecosystems where only one exists simply list one.
    #[must_use]
    pub fn lockfiles(self) -> &'static [LockfileKind] {
        match self {
            ManifestKind::CargoToml => &[LockfileKind::CargoLock],
            // `package-lock.json` first: a repository carrying both has been
            // through a migration, and npm's is what every existing caller
            // already resolved to. A bun-only project has only `bun.lock`, so
            // the order costs it nothing.
            ManifestKind::PackageJson => &[LockfileKind::PackageLockJson, LockfileKind::BunLock],
            ManifestKind::ComposerJson => &[LockfileKind::ComposerLock],
            ManifestKind::PubspecYaml => &[LockfileKind::PubspecLock],
            ManifestKind::MixExs => &[LockfileKind::MixLock],
            // The only entry here that is not merely a source of resolved versions:
            // without it a Swift project has no dependency list at all.
            ManifestKind::PackageSwift => &[LockfileKind::PackageResolved],
            _ => &[],
        }
    }

    /// Lockfiles this ecosystem produces that we recognise but cannot read.
    ///
    /// Listed so their presence can be reported rather than mistaken for a
    /// missing lockfile.
    #[must_use]
    pub fn unreadable_lockfiles(self) -> &'static [UnreadableLockfile] {
        match self {
            ManifestKind::PackageJson => &[UnreadableLockfile {
                file_name: "bun.lockb",
                reason: "Bun's legacy binary lockfile, which cannot be read as text. \
                         Run `bun install --save-text-lockfile` to migrate it to bun.lock.",
            }],
            _ => &[],
        }
    }

    /// Manifest formats this ecosystem produces that we recognise but cannot read.
    ///
    /// The sibling of [`ManifestKind::unreadable_lockfiles`], for the same reason and
    /// with more at stake: an unread *lockfile* costs the resolved versions, while an
    /// unread *manifest* costs the dependencies themselves. A Gradle project whose
    /// dependencies are declared in `build.gradle.kts` and reported as three catalog
    /// entries has been told something false, and being told nothing was read is the
    /// only honest alternative.
    #[must_use]
    pub fn unreadable_manifests(self) -> &'static [UnreadableManifest] {
        match self {
            ManifestKind::GradleVersionCatalog => GRADLE_BUILD_SCRIPTS,
            _ => &[],
        }
    }

    /// Whether a sibling lockfile is read for this manifest kind.
    #[must_use]
    pub fn has_lockfile_support(self) -> bool {
        !self.lockfiles().is_empty()
    }

    /// Where a manifest of this kind looks for the manifest holding its central
    /// dependency declarations, or `None` for a kind that has no such indirection.
    ///
    /// `None` is the answer for every kind whose dependencies declare their own
    /// versions in place, and it is what lets a caller skip the upward walk
    /// entirely rather than walking a tree that can hold no answer.
    #[must_use]
    pub fn workspace_roots(self) -> Option<WorkspaceRoots> {
        match self {
            ManifestKind::CargoToml => Some(WorkspaceRoots {
                root_names: &["Cargo.toml"],
                root_kind: ManifestKind::CargoToml,
                self_governing: true,
            }),
            _ => None,
        }
    }

    /// Whether `content`, read as this kind, offers central dependency
    /// declarations — that is, whether it is a workspace root.
    ///
    /// This is the recognition half of [`ManifestKind::workspace_roots`]: a
    /// candidate found by name still has to say so in its content, because a
    /// `Cargo.toml` above a member is far more often just another package.
    #[must_use]
    pub fn declares_workspace(self, content: &str) -> bool {
        match self {
            ManifestKind::CargoToml => parse_workspace(content).is_some(),
            _ => false,
        }
    }

    /// Detect a manifest kind from a file path.
    ///
    /// Recognition is by file name. A kind being recognized here does not imply a
    /// parser exists for it yet — discovery surfaces the file and the higher
    /// layers skip it gracefully if its ecosystem is unsupported.
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        let kind = match name {
            "Cargo.toml" => ManifestKind::CargoToml,
            "go.mod" => ManifestKind::GoMod,
            "package.json" => ManifestKind::PackageJson,
            "deno.json" | "deno.jsonc" => ManifestKind::DenoJson,
            "pnpm-workspace.yaml" | "pnpm-workspace.yml" => ManifestKind::PnpmWorkspaceYaml,
            "composer.json" => ManifestKind::ComposerJson,
            "pyproject.toml" | "pixi.toml" => ManifestKind::PyprojectToml,
            "pubspec.yaml" => ManifestKind::PubspecYaml,
            "mix.exs" => ManifestKind::MixExs,
            "Directory.Packages.props" => ManifestKind::Csproj,
            "pom.xml" => ManifestKind::PomXml,
            "Package.swift" => ManifestKind::PackageSwift,
            // Gradle reads every `*.versions.toml` under `gradle/` as a catalog;
            // `libs` is only the conventional name of the default one.
            _ if name.ends_with(".versions.toml") => ManifestKind::GradleVersionCatalog,
            _ if is_requirements_file(name) => ManifestKind::RequirementsTxt,
            _ if name.ends_with(".csproj") => ManifestKind::Csproj,
            _ => return None,
        };
        Some(kind)
    }
}

/// Where a manifest kind's central dependency declarations live, and how the
/// manifest holding them is recognized.
///
/// The indirection is not Cargo-shaped in principle. A Cargo member's
/// `serde.workspace = true` resolving against a root's `[workspace.dependencies]`
/// is the same problem as a Gradle version-catalog `version.ref = "kotlin"`
/// resolving against `[versions]`: a dependency whose version literal is written
/// somewhere other than the dependency itself. Describing that per kind is what
/// keeps the walk that finds the root (`dependable_fetch::workspace_root_of`) out
/// of any single ecosystem's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceRoots {
    /// Candidate file names for a root, tried in order within each directory —
    /// the same precedence rule [`ManifestKind::lockfiles`] uses, so a root beside
    /// the manifest always beats one further up whichever name it goes by.
    pub root_names: &'static [&'static str],
    /// The kind a located root is parsed as. Not necessarily the kind that went
    /// looking: an ecosystem may keep its central declarations in a different file
    /// format from the manifests that inherit them.
    pub root_kind: ManifestKind,
    /// Whether a manifest may be its own root. Cargo's root-that-is-also-a-package
    /// writes `serde.workspace = true` against its own table, so walking past
    /// itself would leave exactly those entries unresolved; a kind whose central
    /// declarations always live in a separate file sets this `false`.
    pub self_governing: bool,
}

/// A lockfile format we recognise but cannot read, and what to do about it.
///
/// Recognising these is what separates "no lockfile here" from "a lockfile we
/// cannot use". The second is the more common state for a user to be in and the
/// one they can act on, and reporting it as the first is actively misleading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnreadableLockfile {
    /// The file name to look for.
    pub file_name: &'static str,
    /// Why it cannot be read, phrased for the person who has to fix it.
    pub reason: &'static str,
}

/// Where a Gradle build declares its subprojects.
///
/// This is the file that makes a directory below it *part of this build* rather
/// than a separate one, which is what lets a build root's catalog speak for a
/// subdirectory that has no catalog of its own.
const GRADLE_SETTINGS: &[&str] = &["settings.gradle.kts", "settings.gradle"];

/// Where a Gradle build root announces itself.
///
/// [`GRADLE_SETTINGS`] is the definition, and a catalog is included because a
/// single-project build has a catalog and often no settings file at all — it is
/// still a build root, and the walk out of a subdirectory must not cross it.
const GRADLE_BUILD_ROOTS: &[&str] = &[
    "settings.gradle.kts",
    "settings.gradle",
    "gradle/libs.versions.toml",
];

/// Gradle's build scripts, which are programs rather than data.
///
/// Both spellings, because a project may use either and neither is readable. The
/// catalog that supersedes them sits in a subdirectory, which is why supersession is
/// a relative path rather than a sibling name — and it sits in the **build root's**
/// subdirectory, which is why supersession is resolved by walking up to
/// `build_root_markers` rather than by looking beside the script.
const GRADLE_BUILD_SCRIPTS: &[UnreadableManifest] = &[
    UnreadableManifest {
        file_name: "build.gradle.kts",
        reason: "a Gradle build script, which cannot be read without executing it. \
                 Declare dependencies in `gradle/libs.versions.toml` to have them checked.",
        superseded_by: &["gradle/libs.versions.toml"],
        build_root_markers: GRADLE_BUILD_ROOTS,
        subproject_markers: GRADLE_SETTINGS,
        ecosystem: Ecosystem::Jvm,
    },
    UnreadableManifest {
        file_name: "build.gradle",
        reason: "a Gradle build script, which cannot be read without executing it. \
                 Declare dependencies in `gradle/libs.versions.toml` to have them checked.",
        superseded_by: &["gradle/libs.versions.toml"],
        build_root_markers: GRADLE_BUILD_ROOTS,
        subproject_markers: GRADLE_SETTINGS,
        ecosystem: Ecosystem::Jvm,
    },
];

/// Every manifest format recognised but unreadable, whichever ecosystem produces it.
///
/// What a directory scan looks for, since it is asking about files on disk rather
/// than about a manifest kind it has already identified. A kind's own entries are
/// reachable through [`ManifestKind::unreadable_manifests`]; a second ecosystem
/// adding a group here must add it to both.
pub const UNREADABLE_MANIFESTS: &[UnreadableManifest] = GRADLE_BUILD_SCRIPTS;

/// A manifest format we recognise but cannot read, and what to do about it.
///
/// The manifest-level counterpart of [`UnreadableLockfile`], with one field it does
/// not need: an unreadable manifest may have a readable *alternative* elsewhere in
/// the project, and where that alternative is present nothing was missed and there
/// is nothing to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnreadableManifest {
    /// The file name to look for.
    pub file_name: &'static str,
    /// Why it cannot be read, phrased for the person who has to fix it.
    pub reason: &'static str,
    /// Paths whose presence means the dependencies are declared somewhere readable
    /// after all, relative to the **build root** — not to the directory holding the
    /// unreadable file.
    ///
    /// The two are the same directory only in a single-module project. A Gradle
    /// catalog is build-root scoped: one `<root>/gradle/libs.versions.toml` serves
    /// every subproject, and a subproject has no `gradle/` directory of its own. A
    /// directory-local test therefore calls every module of a *correctly* configured
    /// multi-module build unread, and tells each of them to declare its dependencies
    /// in a catalog that already holds them.
    pub superseded_by: &'static [&'static str],
    /// File names that mark the build root `superseded_by` resolves against, tried
    /// in each directory on the way up from the unreadable file.
    ///
    /// The walk stops at the first directory holding one of these (or at the
    /// repository boundary), so supersession never resolves against an unrelated
    /// build further up the tree.
    pub build_root_markers: &'static [&'static str],
    /// File names an **ancestor** must hold for its readable alternative to cover
    /// this directory as well.
    ///
    /// A build root's catalog serves the subprojects that build root declares, and
    /// `settings.gradle*` is where they are declared. Without this test a
    /// single-project build at the repository root — a catalog, no settings file —
    /// silently absorbs any other build script anywhere beneath it, and the one
    /// script whose dependencies really are unread is the one nobody is told about.
    /// A readable alternative sitting *beside* the unreadable file needs no such
    /// evidence: it is the same directory.
    pub subproject_markers: &'static [&'static str],
    /// The ecosystem this manifest belongs to, so a scan can stay quiet about an
    /// ecosystem the user has turned off — a warning about an unread manifest is
    /// advice to enable something, and it is noise for someone who disabled it.
    pub ecosystem: Ecosystem,
}

/// A lockfile format we can read.
///
/// Separate from [`ManifestKind`] because the mapping is not one to one in
/// either direction: one manifest may be governed by any of several lockfiles,
/// and dispatching a parser on the manifest rather than on the file in front of
/// it is what made a second lockfile per ecosystem inexpressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LockfileKind {
    /// Cargo's `Cargo.lock`.
    CargoLock,
    /// npm's `package-lock.json`.
    PackageLockJson,
    /// Bun's text lockfile, `bun.lock`.
    ///
    /// Bun's older binary format, `bun.lockb`, is deliberately absent: it is not
    /// a text format and cannot be read. It is detected during discovery and
    /// reported, rather than being silently treated as a missing lockfile.
    BunLock,
    /// Composer's `composer.lock`.
    ComposerLock,
    /// Dart's `pubspec.lock`.
    PubspecLock,
    /// Mix's `mix.lock`.
    MixLock,
    /// SwiftPM's `Package.resolved`.
    ///
    /// The only kind here that is a *source* of dependencies rather than an
    /// annotation on them — see [`LockfileKind::is_dependency_source`].
    PackageResolved,
}

impl LockfileKind {
    /// The file name this kind is written to.
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            LockfileKind::CargoLock => "Cargo.lock",
            LockfileKind::PackageLockJson => "package-lock.json",
            LockfileKind::BunLock => "bun.lock",
            LockfileKind::ComposerLock => "composer.lock",
            LockfileKind::PubspecLock => "pubspec.lock",
            LockfileKind::MixLock => "mix.lock",
            LockfileKind::PackageResolved => "Package.resolved",
        }
    }

    /// Whether this lockfile *is* the dependency list rather than an annotation on
    /// one the manifest beside it already produced.
    ///
    /// False for every format whose manifest is readable data: there the lockfile
    /// only supplies resolved versions, and
    /// [`apply_lockfile`](crate::lockfiles::apply_lockfile) annotates existing items
    /// and never inserts. Swift is the exception — `Package.swift` is executable
    /// Swift and is deliberately not read — so `Package.resolved` is the only honest
    /// record of what the project depends on, and a caller has to take items *from*
    /// it. [`lockfile_items`](crate::lockfiles::lockfile_items) is that path.
    #[must_use]
    pub fn is_dependency_source(self) -> bool {
        matches!(self, LockfileKind::PackageResolved)
    }

    /// Recognise a lockfile by its file name.
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        [
            LockfileKind::CargoLock,
            LockfileKind::PackageLockJson,
            LockfileKind::BunLock,
            LockfileKind::ComposerLock,
            LockfileKind::PubspecLock,
            LockfileKind::MixLock,
            LockfileKind::PackageResolved,
        ]
        .into_iter()
        .find(|kind| kind.file_name() == name)
    }
}

/// Whether `name` is a Python requirements file (`requirements.txt`,
/// `requirements-dev.txt`, `requirements.in`, …).
fn is_requirements_file(name: &str) -> bool {
    name.starts_with("requirements") && (name.ends_with(".txt") || name.ends_with(".in"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_manifest_filenames() {
        let cases = [
            ("a/b/Cargo.toml", ManifestKind::CargoToml),
            ("go.mod", ManifestKind::GoMod),
            ("package.json", ManifestKind::PackageJson),
            ("deno.json", ManifestKind::DenoJson),
            ("deno.jsonc", ManifestKind::DenoJson),
            ("pnpm-workspace.yaml", ManifestKind::PnpmWorkspaceYaml),
            ("composer.json", ManifestKind::ComposerJson),
            ("requirements.txt", ManifestKind::RequirementsTxt),
            ("requirements-dev.txt", ManifestKind::RequirementsTxt),
            ("requirements.in", ManifestKind::RequirementsTxt),
            ("pyproject.toml", ManifestKind::PyprojectToml),
            ("pixi.toml", ManifestKind::PyprojectToml),
            ("pubspec.yaml", ManifestKind::PubspecYaml),
            ("mix.exs", ManifestKind::MixExs),
            ("App.csproj", ManifestKind::Csproj),
            ("Directory.Packages.props", ManifestKind::Csproj),
            (
                "gradle/libs.versions.toml",
                ManifestKind::GradleVersionCatalog,
            ),
            (
                "gradle/deps.versions.toml",
                ManifestKind::GradleVersionCatalog,
            ),
            ("services/api/pom.xml", ManifestKind::PomXml),
            ("app/Package.swift", ManifestKind::PackageSwift),
        ];
        for (path, expected) in cases {
            assert_eq!(
                ManifestKind::detect(Path::new(path)),
                Some(expected),
                "{path}"
            );
        }
    }

    #[test]
    fn ignores_unknown_files() {
        assert_eq!(ManifestKind::detect(Path::new("README.md")), None);
        assert_eq!(ManifestKind::detect(Path::new("notes.in")), None);
        assert_eq!(ManifestKind::detect(Path::new("setup.py")), None);
    }

    /// The file names a manifest kind's lockfiles are written to.
    fn names(kind: ManifestKind) -> Vec<&'static str> {
        kind.lockfiles()
            .iter()
            .map(|lockfile| lockfile.file_name())
            .collect()
    }

    #[test]
    fn lockfile_names() {
        assert_eq!(names(ManifestKind::CargoToml), ["Cargo.lock"]);
        assert_eq!(
            names(ManifestKind::PackageJson),
            ["package-lock.json", "bun.lock"]
        );
        assert_eq!(names(ManifestKind::ComposerJson), ["composer.lock"]);
        assert_eq!(names(ManifestKind::PubspecYaml), ["pubspec.lock"]);
        assert_eq!(names(ManifestKind::MixExs), ["mix.lock"]);
        assert_eq!(names(ManifestKind::PackageSwift), ["Package.resolved"]);
        assert!(names(ManifestKind::GoMod).is_empty());
        assert!(!ManifestKind::GoMod.has_lockfile_support());
    }

    /// Every kind but Cargo declares its versions in place, so the upward walk is
    /// skipped for all of them — the behaviour the boolean gate this replaced had.
    #[test]
    fn only_cargo_looks_for_a_workspace_root() {
        let cargo = ManifestKind::CargoToml
            .workspace_roots()
            .expect("Cargo inherits");
        assert_eq!(cargo.root_names, ["Cargo.toml"]);
        assert_eq!(cargo.root_kind, ManifestKind::CargoToml);
        assert!(cargo.self_governing, "a Cargo root may be a package too");

        for kind in [
            ManifestKind::GoMod,
            ManifestKind::PackageJson,
            ManifestKind::DenoJson,
            ManifestKind::PnpmWorkspaceYaml,
            ManifestKind::ComposerJson,
            ManifestKind::RequirementsTxt,
            ManifestKind::PyprojectToml,
            ManifestKind::PubspecYaml,
            ManifestKind::MixExs,
            ManifestKind::Csproj,
            ManifestKind::GradleVersionCatalog,
            ManifestKind::PomXml,
            ManifestKind::PackageSwift,
        ] {
            assert!(kind.workspace_roots().is_none(), "{kind:?}");
            assert!(
                !kind.declares_workspace("[workspace]\nmembers = []\n"),
                "{kind:?} recognised a Cargo workspace table"
            );
        }
    }

    /// Recognition has to stay the same predicate the walk used before, or a root
    /// that used to govern a member would be walked straight past.
    #[test]
    fn declaring_a_workspace_is_exactly_what_the_cargo_parser_sees() {
        let fixtures = [
            "[workspace]\nmembers = [\"sub\"]\n",
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1\"\n",
            "[package]\nname = \"root\"\n\n[workspace]\nmembers = []\n",
            "[package]\nname = \"solo\"\n\n[dependencies]\nserde = \"1\"\n",
            "",
            "this is not toml at all {{{",
        ];
        for content in fixtures {
            assert_eq!(
                ManifestKind::CargoToml.declares_workspace(content),
                parse_workspace(content).is_some(),
                "{content:?}"
            );
        }
    }

    /// A Gradle build script is a program: the catalog beside it is the only part of
    /// the build that is data, so the script has to be reported unread.
    #[test]
    fn a_gradle_build_script_is_recognised_but_unreadable() {
        let scripts = ManifestKind::GradleVersionCatalog.unreadable_manifests();
        let names: Vec<&str> = scripts.iter().map(|m| m.file_name).collect();
        assert_eq!(names, ["build.gradle.kts", "build.gradle"]);
        for script in scripts {
            assert_eq!(script.superseded_by, ["gradle/libs.versions.toml"]);
            assert!(script.reason.contains("libs.versions.toml"), "{script:?}");
        }
        // Every kind's entries have to be findable by a scan that has only a path.
        for script in scripts {
            assert!(
                UNREADABLE_MANIFESTS.contains(script),
                "{script:?} is unreachable from a directory scan"
            );
        }
        assert!(ManifestKind::CargoToml.unreadable_manifests().is_empty());
        // A `pom.xml` is data and reads fine; what it cannot resolve is reported
        // entry by entry, so there is nothing here to declare unreadable.
        assert!(ManifestKind::PomXml.unreadable_manifests().is_empty());
        // A `Package.swift` is a program too, and is not listed here on purpose: an
        // unreadable manifest is one whose dependencies went unread, and Swift's are
        // read in full from `Package.resolved` beside it. What a Swift run cannot
        // establish is currency, which is a different statement and is made per check.
        assert!(ManifestKind::PackageSwift.unreadable_manifests().is_empty());
    }

    /// Exactly one lockfile supplies the dependency list; the rest annotate one the
    /// manifest already produced, and a drift here would silently insert transitive
    /// packages into five other ecosystems' results.
    #[test]
    fn only_package_resolved_is_a_source_of_dependencies() {
        assert!(LockfileKind::PackageResolved.is_dependency_source());
        for kind in [
            LockfileKind::CargoLock,
            LockfileKind::PackageLockJson,
            LockfileKind::BunLock,
            LockfileKind::ComposerLock,
            LockfileKind::PubspecLock,
            LockfileKind::MixLock,
        ] {
            assert!(!kind.is_dependency_source(), "{kind:?}");
        }
    }

    #[test]
    fn a_lockfile_is_recognised_by_its_name() {
        assert_eq!(
            LockfileKind::detect(Path::new("/a/b/Cargo.lock")),
            Some(LockfileKind::CargoLock)
        );
        assert_eq!(
            LockfileKind::detect(Path::new("package-lock.json")),
            Some(LockfileKind::PackageLockJson)
        );
        assert_eq!(
            LockfileKind::detect(Path::new("app/Package.resolved")),
            Some(LockfileKind::PackageResolved)
        );
        assert_eq!(LockfileKind::detect(Path::new("Cargo.toml")), None);
        assert_eq!(LockfileKind::detect(Path::new("")), None);
    }

    #[test]
    fn every_lockfile_a_manifest_names_round_trips_through_detection() {
        // A kind whose file name is not recognised back would be located on disk
        // and then not parsed, which is the silent-drop failure this replaces.
        for kind in [
            ManifestKind::CargoToml,
            ManifestKind::PackageJson,
            ManifestKind::ComposerJson,
            ManifestKind::PubspecYaml,
            ManifestKind::MixExs,
            ManifestKind::PackageSwift,
        ] {
            for lockfile in kind.lockfiles() {
                assert_eq!(
                    LockfileKind::detect(Path::new(lockfile.file_name())),
                    Some(*lockfile),
                    "{lockfile:?} is not recognised by its own name"
                );
            }
        }
    }
}
