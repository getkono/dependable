//! The high-level `dependable` library: parse a manifest, fetch registry versions
//! and OSV advisories, and report which dependencies are outdated or vulnerable.
//!
//! This crate is the recommended entry point for embedding `dependable` in another
//! tool (an IDE, a bot, a service). It re-exports the pure [`dependable_core`] data
//! model and adds the network + concurrency layer, so **depending on this crate
//! alone is sufficient**. The CLI binary is a thin wrapper over the same API.
//!
//! [`Checker`] is the entry point; [`CratesIoFetcher`]/[`OsvClient`] remain public
//! for callers who want to compose the low-level pieces by hand.
//!
//! Only direct registry dependencies are checked: local/git/workspace deps are
//! skipped, names are deduplicated before fetching, and transitive deps are never
//! queried. The design routes per [`Ecosystem`], so adding registries (npm, PyPI,
//! Go, …) is additive.
//!
//! # Example
//!
//! ```no_run
//! use dependable_fetch::{Checker, ManifestKind};
//!
//! # async fn run() -> Result<(), dependable_fetch::CheckError> {
//! // One checker, reused across manifests (shares the HTTP pool and caches).
//! let checker = Checker::new()?;
//!
//! // Check an in-memory manifest (e.g. an unsaved IDE buffer).
//! let manifest = std::fs::read_to_string("Cargo.toml")?;
//! let check = checker
//!     .check_manifest(ManifestKind::CargoToml, &manifest, None)
//!     .await?;
//!
//! for result in check.outdated() {
//!     println!("{}: {}", result.item.name, result.status.label());
//! }
//! # Ok(())
//! # }
//! ```

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
    ParseError, ParsedManifest, UnstableFilter,
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
