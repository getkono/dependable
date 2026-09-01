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

    /// A successful response that carried no versions at all.
    ///
    /// Distinct from [`NotFound`](Self::NotFound), which is the registry saying the
    /// package does not exist. A `200` with an empty version list is not that answer: a
    /// Nexus or Artifactory group repository whose upstream proxy is down serves exactly
    /// such a locally-merged document for a package that certainly does exist. Treating
    /// it as a 404 exempted it from a `--fail-on` gate, certifying a build against a
    /// dependency nothing was ever known about.
    #[error("registry listed no versions for `{package}`")]
    EmptyVersionList { package: String },

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
            // An empty-but-well-formed document parses the same way next time, so a
            // retry only spends the user's time reaching the same conclusion — the same
            // reasoning as a decode failure. It is still not a 404, so the gate refuses
            // to certify through it.
            Self::NotFound(_)
            | Self::EmptyVersionList { .. }
            | Self::Decode { .. }
            | Self::Osv(_) => false,
        }
    }
}
