//! Registry fetchers. V1 ships the crates.io sparse-index fetcher.

use futures::FutureExt;
use futures::future::BoxFuture;

use crate::error::FetchError;

pub mod crates_io;
pub mod go_proxy;
pub mod hex;
pub mod jsr;
pub mod npm;
pub mod nuget;
pub mod packagist;
pub mod pub_dev;
pub mod pypi;

pub use crates_io::CratesIoFetcher;
pub use go_proxy::GoProxyFetcher;
pub use hex::HexFetcher;
pub use jsr::JsrFetcher;
pub use npm::NpmFetcher;
pub use nuget::NuGetFetcher;
pub use packagist::PackagistFetcher;
pub use pub_dev::PubDevFetcher;
pub use pypi::PyPiFetcher;

/// The public metadata a registry publishes about a package.
///
/// Every field is optional because coverage varies by registry: crates.io exposes
/// all of it, most registries expose some of it, and a few expose none. A `None`
/// means "this registry did not tell us", never "the package has none" — a
/// distinction a UI must preserve rather than render as an empty string.
///
/// `#[non_exhaustive]`: build via [`PackageMetadata::default`] and fill in fields,
/// so later additions don't break the fetchers that produce it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackageMetadata {
    /// One-line summary of what the package does.
    pub description: Option<String>,
    /// Source repository URL.
    pub repository: Option<String>,
    /// Project homepage URL.
    pub homepage: Option<String>,
    /// Hosted API documentation URL.
    pub documentation: Option<String>,
    /// SPDX license expression, as the registry reports it.
    pub license: Option<String>,
    /// Authors, owners, or maintainers, as the registry names them.
    pub authors: Vec<String>,
    /// All-time download count, where the registry publishes one.
    pub downloads: Option<u64>,
    /// When the newest version was published (RFC 3339).
    pub last_published: Option<String>,
    /// Whether the newest version has been yanked / withdrawn.
    pub yanked: bool,
    /// The minimum supported Rust version, for registries that record one.
    pub msrv: Option<String>,
}

impl PackageMetadata {
    /// Whether the registry supplied nothing at all, so a caller can report
    /// "no metadata published" rather than rendering an empty panel.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

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
    /// Available feature-flag names for the newest version, where the registry
    /// exposes them (crates.io). Empty otherwise; surfaced by `list --features`.
    pub features: Vec<String>,
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
            features: Vec::new(),
            error: None,
        }
    }

    /// Attach the available feature-flag names (crates.io sparse index).
    #[must_use]
    pub fn with_features(mut self, features: Vec<String>) -> Self {
        self.features = features;
        self
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

    /// Fetch the registry's public metadata for `name`.
    ///
    /// Version checking never needs this, so it is a separate request made only
    /// when something is actually going to display it. Registries that publish no
    /// such endpoint keep the default and report `None`, which a caller renders as
    /// "not available" rather than as absent metadata.
    ///
    /// # Errors
    /// Returns [`FetchError`] if the request fails or the response cannot be
    /// decoded. A package that simply has no metadata is `Ok(None)`, not an error.
    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<PackageMetadata>, FetchError>> {
        let _ = name;
        futures::future::ready(Ok(None)).boxed()
    }
}
