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

    #[error("OSV returned status {code}")]
    OsvStatus { code: u16 },
}

impl FetchError {
    /// Whether retrying might succeed.
    ///
    /// Rate limits and server faults are the registry saying "not now"; a timeout or a
    /// refused connection is the network doing the same. A 404 is an answer, and a
    /// decode failure is a response we will parse identically next time — retrying
    /// either only spends the user's time reaching the same conclusion.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Status { code, .. } | Self::OsvStatus { code } => {
                *code == 429 || (500..600).contains(code)
            }
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::NotFound(_) | Self::Decode { .. } | Self::Osv(_) => false,
        }
    }
}
