//! OSV vulnerability scanning.

mod advisory;
pub mod client;
mod cvss;
pub mod types;

pub use client::{OsvClient, OsvQuery};

// The advisory model itself lives in `dependable-core` — a `CheckResult` field
// carries it, and core cannot name a type from this crate. Re-exported here so a
// consumer of the fetch layer never has to reach across to core for it.
pub use dependable_core::result::{
    Advisory, AdvisoryReference, AdvisorySeverity, AffectedRange, CvssVersion, ReferenceKind,
    Severity,
};
