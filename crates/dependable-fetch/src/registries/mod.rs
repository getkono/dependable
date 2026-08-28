//! Registry fetchers. V1 ships the crates.io sparse-index fetcher.

use std::collections::BTreeMap;

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

/// How a registry classifies an owner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OwnerKind {
    /// An individual account.
    #[default]
    User,
    /// A group account — a crates.io team, a GitHub organization.
    Team,
}

/// One owner, maintainer, or author of a package, as a registry describes them.
///
/// Registries disagree about what they publish: crates.io has a login and a
/// profile URL but never an email, npm has a name and an email but no profile,
/// PyPI has a single free-text author. Every field is therefore optional, and a
/// consumer should render whichever identifiers are present rather than assume
/// any particular one is.
///
/// At least one of `name`, `login`, or `email` is set on every owner a fetcher
/// produces — see [`Owner::is_anonymous`], which the fetchers filter on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Owner {
    /// Display name, as the registry spells it ("David Tolnay").
    pub name: Option<String>,
    /// Registry username, without any sigil ("dtolnay").
    pub login: Option<String>,
    /// Contact email, where the registry publishes one.
    pub email: Option<String>,
    /// Profile or homepage URL for this owner.
    pub url: Option<String>,
    /// Whether this is an individual or a group.
    pub kind: OwnerKind,
}

impl Owner {
    /// An owner known only by a display name — what a registry that publishes a
    /// bare string, such as Hex or PyPI, gives us.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }

    /// Whether this owner carries no identifier at all.
    ///
    /// A registry can return an owner record whose every name field is null; it
    /// tells a reader nothing, so fetchers drop it rather than render a blank.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.name.is_none() && self.login.is_none() && self.email.is_none()
    }

    /// The best human-readable label available, preferring a real name over a
    /// login over a bare email.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.name
            .as_deref()
            .or(self.login.as_deref())
            .or(self.email.as_deref())
    }
}

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
    /// Owners, maintainers, or authors, as the registry names them.
    pub owners: Vec<Owner>,
    /// All-time download count, where the registry publishes one.
    pub downloads: Option<u64>,
    /// When the *newest* version was published (RFC 3339).
    ///
    /// This describes the latest release, not whichever version a project has
    /// resolved. Use [`PackageMetadata::published_at`] for that.
    pub latest_published: Option<String>,
    /// Publish dates keyed by version (RFC 3339), for whichever versions the
    /// registry listed in the same response.
    ///
    /// Coverage varies and is never guaranteed to be complete: PyPI may list
    /// only the newest release, and no registry is obliged to date every one.
    /// A missing key means "not published to us", never "never published".
    pub published: BTreeMap<String, String>,
    /// Whether the newest version has been yanked / withdrawn.
    pub yanked: bool,
    /// The minimum supported Rust version, for registries that record one.
    pub msrv: Option<String>,
}

impl PackageMetadata {
    /// When a specific version was published, if the registry dated it.
    ///
    /// This is the honest answer for a resolved dependency;
    /// [`PackageMetadata::latest_published`] describes a different version and
    /// reads as wrong when shown beside one a project actually depends on.
    #[must_use]
    pub fn published_at(&self, version: &str) -> Option<&str> {
        self.published.get(version).map(String::as_str)
    }

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
