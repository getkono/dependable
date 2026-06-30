//! Manifest parsers. V1 ships the `Cargo.toml` parser; other ecosystems are deferred.

use crate::error::ParseError;
use crate::manifest::{ManifestKind, ParsedManifest};

pub mod cargo_toml;
pub mod position;

pub use cargo_toml::CargoTomlParser;

/// A pure manifest parser: `&str` in, structured data out, no side effects.
pub trait Parser {
    /// Parse manifest `content` into a [`ParsedManifest`].
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError>;
}

/// Parse `content` for a given manifest `kind`, dispatching to the right parser.
pub fn parse(kind: ManifestKind, content: &str) -> Result<ParsedManifest, ParseError> {
    match kind {
        ManifestKind::CargoToml => CargoTomlParser.parse(content),
        other => Err(ParseError::Unsupported(other)),
    }
}
