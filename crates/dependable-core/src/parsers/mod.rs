//! Manifest parsers. V1 ships the `Cargo.toml` parser; other ecosystems are deferred.

use crate::error::ParseError;
use crate::manifest::{ManifestKind, ParsedManifest};

pub mod cargo_toml;
pub mod composer_json;
pub mod deno_json;
pub mod json_scan;
pub mod package_json;
pub mod pnpm_workspace;
pub mod position;

pub use cargo_toml::CargoTomlParser;
pub use composer_json::ComposerJsonParser;
pub use deno_json::DenoJsonParser;
pub use package_json::PackageJsonParser;
pub use pnpm_workspace::PnpmWorkspaceParser;

/// A pure manifest parser: `&str` in, structured data out, no side effects.
pub trait Parser {
    /// Parse manifest `content` into a [`ParsedManifest`].
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError>;
}

/// Parse `content` for a given manifest `kind`, dispatching to the right parser.
pub fn parse(kind: ManifestKind, content: &str) -> Result<ParsedManifest, ParseError> {
    match kind {
        ManifestKind::CargoToml => CargoTomlParser.parse(content),
        ManifestKind::PackageJson => PackageJsonParser.parse(content),
        ManifestKind::DenoJson => DenoJsonParser.parse(content),
        ManifestKind::PnpmWorkspaceYaml => PnpmWorkspaceParser.parse(content),
        ManifestKind::ComposerJson => ComposerJsonParser.parse(content),
        other => Err(ParseError::Unsupported(other)),
    }
}
