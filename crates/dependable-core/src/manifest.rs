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
    /// V1 recognizes only `Cargo.toml`; other manifests return `None` until their
    /// parser lands, so directory walks silently skip them.
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
        match path.file_name()?.to_str()? {
            "Cargo.toml" => Some(ManifestKind::CargoToml),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cargo_toml_only() {
        assert_eq!(
            ManifestKind::detect(Path::new("a/b/Cargo.toml")),
            Some(ManifestKind::CargoToml)
        );
        assert_eq!(ManifestKind::detect(Path::new("package.json")), None);
        assert_eq!(ManifestKind::CargoToml.lockfile_name(), Some("Cargo.lock"));
    }
}
