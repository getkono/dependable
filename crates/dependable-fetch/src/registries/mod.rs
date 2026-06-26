//! Registry fetchers. V1 ships the crates.io sparse-index fetcher.

use futures::future::BoxFuture;

use crate::error::FetchError;

pub mod crates_io;

pub use crates_io::CratesIoFetcher;

/// The versions fetched from a registry for one package.
///
/// `#[non_exhaustive]`: build via [`FetchedVersions::new`] so future fields don't
/// break the registry fetchers that produce it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FetchedVersions {
    /// All available versions, newest-first.
    pub versions: Vec<String>,
    /// The registry's explicit "latest" tag, where available.
    pub latest_tag: Option<String>,
    /// A non-fatal note (e.g. deprecation), if any.
    pub error: Option<String>,
}

impl FetchedVersions {
    /// A result from a `versions` list (newest-first by convention); the latest
    /// tag defaults to the first entry.
    #[must_use]
    pub fn new(versions: Vec<String>) -> Self {
        let latest_tag = versions.first().cloned();
        Self {
            versions,
            latest_tag,
            error: None,
        }
    }

    /// Override the explicit "latest" tag.
    #[must_use]
    pub fn with_latest_tag(mut self, tag: impl Into<String>) -> Self {
        self.latest_tag = Some(tag.into());
        self
    }

    /// Attach a non-fatal note (e.g. a deprecation warning).
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.error = Some(note.into());
        self
    }
}

/// Fetches available versions for a package from a registry.
///
/// Object-safe (returns a [`BoxFuture`]) so a high-level checker can hold one
/// fetcher per ecosystem behind `Arc<dyn RegistryFetcher>`. Adding an ecosystem is
/// purely additive: implement this trait and register it on the checker builder.
pub trait RegistryFetcher: Send + Sync {
    /// Fetch all available versions for `name`.
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>>;
}
