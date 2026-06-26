//! Async IO layer for `dependable`: registry adapters, the OSV client, and caching.
//!
//! Depends on [`dependable_core`] for the pure data model and adds the network +
//! concurrency concerns that the core deliberately excludes.

use std::time::Duration;

pub mod cache;
pub mod error;
pub mod osv;
pub mod registries;

pub use error::FetchError;
pub use osv::{OsvClient, OsvQuery};
pub use registries::{CratesIoFetcher, FetchedVersions, RegistryFetcher};

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
