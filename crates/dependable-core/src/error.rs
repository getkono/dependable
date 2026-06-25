//! Error types for the pure core.

use thiserror::Error;

use crate::manifest::ManifestKind;

/// An error produced while parsing a manifest or lockfile.
#[derive(Debug, Error)]
pub enum ParseError {
    /// The input was not valid TOML.
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml_edit::TomlError),

    /// No parser is compiled in for this manifest kind (deferred ecosystem).
    #[error("manifest kind {0:?} is not supported in this build")]
    Unsupported(ManifestKind),

    /// The TOML was valid but structurally not what we expected.
    #[error("malformed manifest: {0}")]
    Structural(String),
}
