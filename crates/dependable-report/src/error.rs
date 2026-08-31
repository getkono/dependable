//! The error type shared by every renderer in this crate.

use thiserror::Error;

/// An error raised while building or rendering a report.
///
/// `#[non_exhaustive]`: match with a wildcard arm so new variants are additive.
/// Renderers added later contribute their own variants (template, serialization,
/// and IO failures) rather than defining error types of their own — one error
/// type is what lets a caller handle every report format the same way.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReportError {
    /// A timestamp could not be formatted (see
    /// [`Report::generated_at_rfc3339`](crate::Report::generated_at_rfc3339)).
    #[error("failed to format timestamp: {0}")]
    Format(#[from] time::error::Format),
    /// A report could not be serialized (see [`sarif::render`](crate::sarif::render)).
    #[error("failed to serialize report: {0}")]
    Serialize(#[from] serde_json::Error),
}
