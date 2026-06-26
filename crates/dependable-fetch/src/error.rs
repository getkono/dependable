//! Error type for the fetch layer.

use thiserror::Error;

/// An error from a registry or OSV request.
///
/// `#[non_exhaustive]`: match with a wildcard arm so new variants are additive.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("package `{0}` not found")]
    NotFound(String),

    #[error("registry returned status {code} for `{package}`")]
    Status { code: u16, package: String },

    #[error("failed to decode response for `{package}`: {detail}")]
    Decode { package: String, detail: String },

    #[error("OSV query failed: {0}")]
    Osv(String),
}
