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

    /// The sibling lockfile name, if this manifest kind has one we read.
    #[must_use]
    pub fn lockfile_name(self) -> Option<&'static str> {
        match self {
            ManifestKind::CargoToml => Some("Cargo.lock"),
            ManifestKind::PackageJson => Some("package-lock.json"),
            ManifestKind::ComposerJson => Some("composer.lock"),
            ManifestKind::PubspecYaml => Some("pubspec.lock"),
            _ => None,
        }
    }

    /// Whether a sibling lockfile is read for this manifest kind.
    #[must_use]
    pub fn has_lockfile_support(self) -> bool {
        self.lockfile_name().is_some()
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
            _ if is_requirements_file(name) => ManifestKind::RequirementsTxt,
            _ if name.ends_with(".csproj") => ManifestKind::Csproj,
            _ => return None,
        };
        Some(kind)
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

    #[test]
    fn lockfile_names() {
        assert_eq!(ManifestKind::CargoToml.lockfile_name(), Some("Cargo.lock"));
        assert_eq!(
            ManifestKind::PackageJson.lockfile_name(),
            Some("package-lock.json")
        );
        assert_eq!(
            ManifestKind::ComposerJson.lockfile_name(),
            Some("composer.lock")
        );
        assert_eq!(
            ManifestKind::PubspecYaml.lockfile_name(),
            Some("pubspec.lock")
        );
        assert_eq!(ManifestKind::GoMod.lockfile_name(), None);
    }
}
