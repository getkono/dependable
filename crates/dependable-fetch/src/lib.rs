//! Async IO layer for `dependable`: registry adapters, the OSV client, and caching.
//!
//! Depends on [`dependable_core`] for the pure data model and adds the network +
//! concurrency concerns that the core deliberately excludes.

use std::time::Duration;

pub mod cache;
pub mod check;
pub mod error;
pub mod osv;
pub mod registries;

// High-level entry point (recommended for embedding).
pub use check::{CheckError, Checker, CheckerBuilder, ManifestCheck, ProgressEvent};

// Low-level building blocks (compose-it-yourself).
pub use error::FetchError;
pub use osv::{OsvClient, OsvQuery};
pub use registries::{CratesIoFetcher, FetchedVersions, RegistryFetcher};

// Re-export the core types a consumer needs, so depending on `dependable-fetch`
// alone is sufficient. `core` is the escape hatch for everything else (lockfiles,
// parsers, `check_version`, ...).
pub use dependable_core as core;
pub use dependable_core::{
    CheckResult, DependencyStatus, Ecosystem, Evaluation, Item, ManifestKind, PackageSource,
    ParseError, ParsedManifest,
};

/// One-import convenience for consumers: `use dependable_fetch::prelude::*;`.
pub mod prelude {
    pub use crate::{
        CheckError, CheckResult, Checker, DependencyStatus, Ecosystem, ManifestCheck, ManifestKind,
        ProgressEvent,
    };
}

/// Build the shared HTTP client used by all fetchers.
///
/// rustls TLS, gzip decompression, a 10-second timeout, and a descriptive
/// User-Agent. The connection pool is shared by cloning the returned client.
///
/// # Errors
/// Returns an error if the TLS backend or client cannot be constructed.
pub fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(format!(
            "Dependable/{} ({})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        ))
        .timeout(Duration::from_secs(10))
        .build()
}
