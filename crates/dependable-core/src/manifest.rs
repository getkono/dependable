//! Manifest-level types: what kind of manifest, and the result of parsing one.

use std::path::Path;

use crate::ecosystem::Ecosystem;
use crate::item::Item;

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

/// Distinguishes manifest files. Only [`ManifestKind::CargoToml`] is parsed in
/// V1; the rest exist so detection and the ecosystem mapping are forward-stable.
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
            _ => &[],
        }
    }

    /// Whether a sibling lockfile is read for this manifest kind.
    #[must_use]
    pub fn has_lockfile_support(self) -> bool {
        !self.lockfiles().is_empty()
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
            _ if is_requirements_file(name) => ManifestKind::RequirementsTxt,
            _ if name.ends_with(".csproj") => ManifestKind::Csproj,
            _ => return None,
        };
        Some(kind)
    }
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
        }
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
        assert!(names(ManifestKind::GoMod).is_empty());
        assert!(!ManifestKind::GoMod.has_lockfile_support());
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
