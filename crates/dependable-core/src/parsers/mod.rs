//! Manifest parsers. V1 ships the `Cargo.toml` parser; other ecosystems are deferred.

use crate::error::ParseError;
use crate::manifest::{ManifestKind, ParsedManifest};

pub mod cargo_toml;
pub mod go_mod;
pub mod position;
pub mod pyproject_toml;
pub mod requirements_txt;

pub use cargo_toml::CargoTomlParser;
pub use go_mod::GoModParser;
pub use pyproject_toml::PyprojectTomlParser;
pub use requirements_txt::RequirementsTxtParser;

/// A pure manifest parser: `&str` in, structured data out, no side effects.
pub trait Parser {
    /// Parse manifest `content` into a [`ParsedManifest`].
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError>;
}

/// Parse `content` for a given manifest `kind`, dispatching to the right parser.
pub fn parse(kind: ManifestKind, content: &str) -> Result<ParsedManifest, ParseError> {
    match kind {
        ManifestKind::CargoToml => CargoTomlParser.parse(content),
        ManifestKind::GoMod => GoModParser.parse(content),
        ManifestKind::RequirementsTxt => RequirementsTxtParser.parse(content),
        ManifestKind::PyprojectToml => PyprojectTomlParser.parse(content),
        other => Err(ParseError::Unsupported(other)),
    }
}
