//! The package ecosystems dependable understands.

use serde::{Deserialize, Serialize};

/// A package ecosystem.
///
/// Only [`Ecosystem::Rust`] is wired end-to-end in V1; the remaining variants
/// exist so the data model (and OSV/registry mappings) stay stable as ecosystems
/// are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Ecosystem {
    Rust,
    Go,
    Npm,
    Python,
    Php,
    Dart,
    CSharp,
    Elixir,
}

impl Ecosystem {
    /// The `package.ecosystem` string used in OSV vulnerability queries.
    #[must_use]
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Rust => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Npm => "npm",
            Ecosystem::Python => "PyPI",
            Ecosystem::Php => "Packagist",
            Ecosystem::Dart => "Pub",
            Ecosystem::CSharp => "NuGet",
            Ecosystem::Elixir => "Hex",
        }
    }

    /// A human-readable name for display.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Ecosystem::Rust => "Rust",
            Ecosystem::Go => "Go",
            Ecosystem::Npm => "npm",
            Ecosystem::Python => "Python",
            Ecosystem::Php => "PHP",
            Ecosystem::Dart => "Dart",
            Ecosystem::CSharp => "C#",
            Ecosystem::Elixir => "Elixir",
        }
    }

    /// The default registry base URL for the ecosystem.
    #[must_use]
    pub fn default_registry(self) -> &'static str {
        match self {
            Ecosystem::Rust => "https://index.crates.io",
            Ecosystem::Go => "https://proxy.golang.org",
            Ecosystem::Npm => "https://registry.npmjs.org",
            Ecosystem::Python => "https://pypi.org/pypi",
            Ecosystem::Php => "https://repo.packagist.org",
            Ecosystem::Dart => "https://pub.dev",
            Ecosystem::CSharp => "https://api.nuget.org",
            Ecosystem::Elixir => "https://hex.pm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_maps_to_crates_io_for_osv() {
        assert_eq!(Ecosystem::Rust.osv_name(), "crates.io");
        assert_eq!(
            Ecosystem::Rust.default_registry(),
            "https://index.crates.io"
        );
    }
}
