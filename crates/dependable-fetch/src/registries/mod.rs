//! Registry fetchers. V1 ships the crates.io sparse-index fetcher.

use crate::error::FetchError;

pub mod crates_io;

pub use crates_io::CratesIoFetcher;

/// The versions fetched from a registry for one package.
#[derive(Debug, Clone)]
pub struct FetchedVersions {
    /// All available versions, newest-first.
    pub versions: Vec<String>,
    /// The registry's explicit "latest" tag, where available.
    pub latest_tag: Option<String>,
    /// A non-fatal note (e.g. deprecation), if any.
    pub error: Option<String>,
}

/// Fetches available versions for a package from a registry.
///
/// `async fn` in a trait is used deliberately: V1 has a single concrete fetcher
/// called directly (no `dyn`), and adding ecosystems is an additive change.
#[allow(async_fn_in_trait)]
pub trait RegistryFetcher: Send + Sync {
    /// Fetch all available versions for `name`.
    async fn fetch_versions(&self, name: &str) -> Result<FetchedVersions, FetchError>;
}
