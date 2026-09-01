//! High-level end-to-end checker: parse → fetch → evaluate → optional OSV scan.
//!
//! This is the recommended entry point for embedding `dependable` in another tool
//! (an IDE, a bot, a service). It ties the pure [`dependable_core`] parsing and
//! version logic to the network layer in this crate, so a consumer needs only
//! `dependable-fetch`. The low-level building blocks ([`crate::CratesIoFetcher`],
//! [`crate::OsvClient`]) remain public for callers who want to compose by hand.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dependable_core::{
    CheckResult, DependencyStatus, Ecosystem, Evaluation, Item, LockfileKind, ManifestKind,
    PackageSource, UnstableFilter, apply_lockfile, check_version, lockfile_items, parse,
    parse_lockfile_kind, resolve_workspace_inheritance, to_semver_constraint,
};
use futures::stream::{self, StreamExt};
use semver::Version as SemverVersion;

use crate::build_client;
use crate::cache::{
    DISK_CACHE_TTL, DiskCache, MetadataCache, VersionsCache, WorkspaceCache, metadata_cache,
    versions_cache, workspace_cache,
};
use crate::error::FetchError;
use crate::osv::{Advisory, OsvClient, OsvQuery};
use crate::registries::{CratesIoFetcher, PackageMetadata, RegistryFetcher};

/// Default OSV `querybatch` endpoint.
const DEFAULT_OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// Default number of concurrent registry fetches.
const DEFAULT_CONCURRENCY: usize = 20;

/// A boxed progress callback.
type ProgressSink = Arc<dyn Fn(ProgressEvent) + Send + Sync>;

/// Progress emitted during one manifest's fetch phase.
///
/// Each [`Checker::check_manifest`]/[`Checker::check_path`] call emits one
/// `Started` → `Advanced`* → `Finished` cycle, letting a UI manage a per-manifest
/// progress bar. `#[non_exhaustive]` so new phases can be added later.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Fetching has begun; `total` registry lookups will run.
    Started {
        /// The number of unique packages to fetch.
        total: usize,
    },
    /// `completed` of `total` lookups have finished.
    Advanced {
        /// Lookups completed so far.
        completed: usize,
        /// Total lookups for this manifest.
        total: usize,
    },
    /// Fetching for this manifest is complete.
    Finished,
}

/// Errors from the high-level [`Checker`].
///
/// `#[non_exhaustive]`: match with a wildcard arm so new variants are additive.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The manifest content could not be parsed.
    #[error(transparent)]
    Parse(#[from] dependable_core::ParseError),
    /// No registry fetcher is registered for the manifest's ecosystem.
    #[error("no registry fetcher registered for {0:?}")]
    UnsupportedEcosystem(Ecosystem),
    /// The path's file name did not match a known manifest kind.
    #[error("unrecognized manifest: {0}")]
    UnknownManifest(PathBuf),
    /// Reading a manifest or lockfile from disk failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A registry or OSV request failed fatally.
    #[error(transparent)]
    Fetch(#[from] FetchError),
}

/// The outcome of checking one manifest.
///
/// `#[non_exhaustive]`: future fields are additive.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ManifestCheck {
    /// The manifest kind that was parsed.
    pub kind: ManifestKind,
    /// The ecosystem the manifest belongs to (`kind.ecosystem()`).
    pub ecosystem: Ecosystem,
    /// One result per declared dependency, in manifest order.
    pub results: Vec<CheckResult>,
    /// Non-fatal degradations (e.g. an OSV outage that skipped vulnerability data).
    pub warnings: Vec<String>,
    /// The manifest whose `[workspace.dependencies]` govern this one — itself, when it
    /// declares its own `[workspace]`, else the nearest ancestor that does.
    ///
    /// Set whenever such a manifest was found, whether or not anything was actually
    /// inherited from it: it names the table that *would* answer a `workspace = true`,
    /// which is what a caller needs in order to say where a constraint came from **and**
    /// where a missing one should have been. Absolute and symlink-resolved, per
    /// [`nearest_workspace_root`](crate::nearest_workspace_root).
    ///
    /// Per-manifest rather than per-result, which is what keeps [`PathBuf`] — and the
    /// filesystem it implies — out of [`Item`] and out of the IO-free core. `None` for a
    /// manifest outside a workspace, and for [`Checker::check_manifest`], which is given
    /// content with no file behind it and so has no tree to look up.
    pub workspace_root: Option<PathBuf>,
}

impl ManifestCheck {
    /// Results that represent an available upgrade (patch/update/outdated/vulnerable).
    pub fn outdated(&self) -> impl Iterator<Item = &CheckResult> {
        self.results.iter().filter(|r| {
            matches!(
                r.status,
                DependencyStatus::PatchAvailable
                    | DependencyStatus::UpdateAvailable
                    | DependencyStatus::Outdated
                    | DependencyStatus::Vulnerable
            )
        })
    }

    /// Results with known advisories on the current version.
    pub fn vulnerable(&self) -> impl Iterator<Item = &CheckResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.status, DependencyStatus::Vulnerable))
    }

    /// Whether anything needs attention (any outdated or vulnerable dependency).
    #[must_use]
    pub fn has_issues(&self) -> bool {
        self.outdated().next().is_some()
    }
}

/// End-to-end dependency checker.
///
/// Construct via [`Checker::new`] (crates.io + OSV defaults) or
/// [`Checker::builder`]. Cheap to clone and safe to share across manifests and
/// tasks — the HTTP connection pool and caches are shared by clones, so a server
/// should build one and reuse it.
#[derive(Clone)]
pub struct Checker {
    registries: HashMap<Ecosystem, Arc<dyn RegistryFetcher>>,
    /// Alternate Rust registries keyed by alias (`registry = "<alias>"`), resolved
    /// from `$CARGO_HOME/config.toml` + `credentials.toml`. A checkable item whose
    /// `registry` alias matches one here is fetched from it (with its auth token)
    /// instead of the default crates.io index.
    rust_registries: HashMap<String, Arc<dyn RegistryFetcher>>,
    /// Fetcher for [`PackageSource::Jsr`] items (a sub-registry of the npm
    /// ecosystem), used for Deno `jsr:` dependencies.
    jsr: Option<Arc<dyn RegistryFetcher>>,
    /// Ecosystems that publish no registry and that the caller has nonetheless
    /// asked to check. `registries` is the on switch for every ecosystem that has
    /// a fetcher; this is the on switch for the ones that cannot have one.
    registryless: HashSet<Ecosystem>,
    osv: Option<Arc<OsvClient>>,
    /// Whether `check_*` runs the advisory-enrichment post-pass. Off by default:
    /// enrichment costs one extra OSV request per vulnerable package version, so
    /// a plain check must not pay for data nothing asked for.
    advisory_details: bool,
    /// Whether `check_*` runs the license-collection post-pass. Off by default:
    /// it costs one metadata request per distinct dependency.
    licenses: bool,
    concurrency: usize,
    read_lockfiles: bool,
    unstable: UnstableFilter,
    versions_cache: VersionsCache,
    metadata_cache: MetadataCache,
    workspace_cache: WorkspaceCache,
    /// Persistent on-disk cache, consulted below the in-process cache. `None`
    /// disables it (`--no-cache`, or no resolvable cache directory).
    disk_cache: Option<Arc<DiskCache>>,
    progress: Option<ProgressSink>,
}

/// Cache key used for JSR lookups, kept distinct from the npm ecosystem key.
const JSR_CACHE_KEY: &str = "jsr";

/// One package to fetch: its name, the fetcher to use, and its versions-cache key.
/// The key is owned because alternate registries namespace it by alias at runtime.
struct FetchTask {
    name: String,
    fetcher: Arc<dyn RegistryFetcher>,
    cache_key: String,
}

/// The result of one fetch task: `(name, cache_key, versions-or-error)`.
type FetchOutcome = (String, String, Result<Vec<String>, String>);

/// Fetched versions (or a per-package error message) keyed by package name.
type FetchedMap = HashMap<String, Result<Vec<String>, String>>;

impl Checker {
    /// Start configuring a checker.
    pub fn builder() -> CheckerBuilder {
        CheckerBuilder::default()
    }

    /// A checker with default settings: the public crates.io index and OSV scanning.
    ///
    /// # Errors
    /// Returns [`CheckError::Fetch`] if the HTTP client cannot be constructed.
    pub fn new() -> Result<Self, CheckError> {
        Self::builder().build()
    }

    /// Check a manifest supplied as content (ideal for IDE buffers, including
    /// unsaved edits). `kind` selects the parser and ecosystem; `lockfile` is the
    /// resolved lockfile content, if the caller has it.
    ///
    /// Only direct registry dependencies are fetched: local/git/workspace deps are
    /// skipped, names are deduplicated, and transitive deps are never queried.
    ///
    /// # Errors
    /// [`CheckError::Parse`] on malformed content, or
    /// [`CheckError::UnsupportedEcosystem`] if no fetcher is registered for the
    /// manifest's ecosystem. Vulnerability-scan failures degrade to a warning
    /// rather than an error.
    pub async fn check_manifest(
        &self,
        kind: ManifestKind,
        manifest: &str,
        lockfile: Option<&str>,
    ) -> Result<ManifestCheck, CheckError> {
        // Content with no file behind it: the manifest's first lockfile is the
        // only thing it can be attributed to.
        let lockfile = lockfile.and_then(|lock| Some((*kind.lockfiles().first()?, lock)));
        // No file, so no tree above it: a `dep.workspace = true` here stays unresolved
        // and reports as it always has. [`Checker::check_path`] is the entry point that
        // can answer the question.
        self.check_inner(kind, manifest, lockfile, None).await
    }

    /// Check a manifest on disk: detect its kind, read it (and, when
    /// [`CheckerBuilder::read_lockfiles`] is set, its sibling lockfile), then check.
    /// This is the only place the library performs filesystem IO.
    ///
    /// # Errors
    /// [`CheckError::UnknownManifest`] if the file name is unrecognized,
    /// [`CheckError::Io`] if the manifest cannot be read, plus the errors of
    /// [`Checker::check_manifest`].
    /// Fetch the available versions for one package, newest-first.
    ///
    /// Shares the checker's version cache with `check_*`, so a package already
    /// seen in a check costs nothing here.
    ///
    /// # Errors
    /// Returns [`CheckError::UnsupportedEcosystem`] if no fetcher is registered for
    /// `ecosystem`, or [`CheckError::Fetch`] if the request fails.
    pub async fn fetch_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<String>, CheckError> {
        let key = (ecosystem.osv_name().to_owned(), name.to_owned());
        if let Some(hit) = self.versions_cache.get(&key).await {
            return Ok(hit);
        }
        let fetcher = self
            .registries
            .get(&ecosystem)
            .ok_or(CheckError::UnsupportedEcosystem(ecosystem))?;
        let versions = fetcher.fetch_versions(name).await?.versions;
        self.versions_cache.insert(key, versions.clone()).await;
        Ok(versions)
    }

    /// Query OSV for advisories affecting one exact package version.
    ///
    /// `check_*` scans a whole manifest in one batch; this exists for a UI asking
    /// about the single package it is displaying. Results share the OSV cache.
    ///
    /// # Errors
    /// Returns [`CheckError::Fetch`] if the query fails. Returns an empty list —
    /// not an error — when vulnerability scanning is disabled.
    pub async fn scan_package(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Vec<String>, CheckError> {
        let Some(osv) = &self.osv else {
            return Ok(Vec::new());
        };
        let query = OsvQuery {
            ecosystem: ecosystem.osv_name().to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
        };
        let mut results = osv.query_batch(std::slice::from_ref(&query)).await?;
        Ok(results.pop().unwrap_or_default())
    }

    /// Fetch full advisory records for one exact package version.
    ///
    /// Where [`Checker::scan_package`] answers "is this version affected?" with
    /// bare IDs, this answers "what exactly is wrong with it?" — severity, fixed
    /// versions, summary, and references. It exists for a UI displaying a single
    /// package it never ran a check over; a checked manifest gets the same records
    /// through [`Checker::enrich_advisories`]. Routing through the checker's
    /// shared OSV client means it inherits both warm caches.
    ///
    /// # Errors
    /// Returns [`CheckError::Fetch`] if the query fails. Returns an empty list —
    /// not an error — when vulnerability scanning is disabled.
    pub async fn fetch_advisories(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Vec<Advisory>, CheckError> {
        let Some(osv) = &self.osv else {
            return Ok(Vec::new());
        };
        let query = OsvQuery {
            ecosystem: ecosystem.osv_name().to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
        };
        Ok(osv.query_detail(&query).await?)
    }

    /// Attach full advisory records to every result that has vulnerability IDs.
    ///
    /// Costs one OSV request per distinct vulnerable package version, run at the
    /// checker's configured concurrency; clean packages are never queried, so a
    /// typical repository pays for the handful of dependencies that are actually
    /// affected. Enrichment never adds, removes, or reorders
    /// `current_vulnerabilities` and never changes a status — it only fills in
    /// [`CheckResult::advisories`], which stays keyed by those IDs.
    ///
    /// A version that fails to fetch is left unenriched rather than discarding the
    /// ones that succeeded; the first failure is still reported.
    ///
    /// [`CheckerBuilder::advisory_details`] runs this automatically at the end of
    /// each check. Calling it by hand is for a caller who wants the details only
    /// sometimes, or only for a check it already has.
    ///
    /// # Errors
    /// Returns [`CheckError::Fetch`] if an OSV request fails. Returns `Ok(())`
    /// with nothing enriched when vulnerability scanning is disabled.
    pub async fn enrich_advisories(&self, check: &mut ManifestCheck) -> Result<(), CheckError> {
        let Some(osv) = &self.osv else {
            return Ok(());
        };
        let ecosystem = check.ecosystem;
        let pending: Vec<(usize, OsvQuery)> = check
            .results
            .iter()
            .enumerate()
            .filter(|(_, result)| !result.current_vulnerabilities.is_empty())
            .filter_map(|(i, result)| osv_query_for(result, ecosystem).map(|query| (i, query)))
            .collect();
        if pending.is_empty() {
            return Ok(());
        }

        let fetched: Vec<(usize, Result<Vec<Advisory>, FetchError>)> = stream::iter(pending)
            .map(|(index, query)| {
                let osv = osv.clone();
                async move { (index, osv.query_detail(&query).await) }
            })
            .buffer_unordered(self.concurrency)
            .collect()
            .await;

        let mut failure: Option<FetchError> = None;
        for (index, outcome) in fetched {
            match outcome {
                Ok(advisories) => check.results[index].advisories = advisories,
                Err(e) => failure = failure.or(Some(e)),
            }
        }
        match failure {
            Some(e) => Err(CheckError::Fetch(e)),
            None => Ok(()),
        }
    }

    /// Attach each dependency's registry-declared license to its result.
    ///
    /// Costs one metadata request per **distinct** dependency name, run at the
    /// checker's configured concurrency and served from the metadata cache when
    /// a name was already looked up — so a second manifest naming the same
    /// packages is free. Nothing else about a result is touched.
    ///
    /// Registries that publish no metadata endpoint (the Go module proxy, JSR,
    /// NuGet, pub.dev) simply leave every license `None`; that is "we cannot
    /// ask", not "unlicensed", and the distinction is the caller's to preserve.
    /// Metadata is fetched from the ecosystem's default fetcher, so a crate from
    /// an alternate Cargo registry is looked up on crates.io and typically comes
    /// back without a license rather than with a wrong one.
    ///
    /// [`CheckerBuilder::licenses`] runs this automatically at the end of each
    /// check. A failure is non-fatal there: the versions are still correct.
    ///
    /// # Errors
    /// Returns the first [`CheckError`] a metadata request produced. The packages
    /// that did succeed are still attached — a partial answer beats none.
    pub async fn attach_licenses(
        &self,
        ecosystem: Ecosystem,
        results: &mut [CheckResult],
    ) -> Result<(), CheckError> {
        let mut seen: HashSet<&str> = HashSet::new();
        let names: Vec<String> = results
            .iter()
            .filter(|result| result.item.is_checkable())
            .filter(|result| seen.insert(result.item.name.as_str()))
            .map(|result| result.item.name.clone())
            .collect();
        if names.is_empty() {
            return Ok(());
        }

        let checker = self;
        let fetched: Vec<(String, Result<Option<PackageMetadata>, CheckError>)> =
            stream::iter(names)
                .map(move |name| async move {
                    let metadata = checker.fetch_metadata(ecosystem, &name).await;
                    (name, metadata)
                })
                .buffer_unordered(self.concurrency)
                .collect()
                .await;

        let mut licenses: HashMap<String, String> = HashMap::new();
        let mut failure: Option<CheckError> = None;
        for (name, outcome) in fetched {
            match outcome {
                Ok(Some(metadata)) => {
                    if let Some(license) = metadata.license {
                        licenses.insert(name, license);
                    }
                }
                Ok(None) => {}
                Err(e) => failure = failure.or(Some(e)),
            }
        }
        for result in results.iter_mut() {
            if let Some(license) = licenses.get(&result.item.name) {
                result.license = Some(license.clone());
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Fetch the registry's public metadata for one package.
    ///
    /// This is deliberately **not** part of `check_*`: version checking never needs
    /// repository, license, or owner information, and fetching it for every
    /// dependency would multiply the request count for data nothing is displaying.
    /// A UI calls this for the one package it is about to show.
    ///
    /// Results — including "this registry publishes none" — are cached, so
    /// revisiting a package costs nothing.
    ///
    /// # Errors
    /// Returns [`CheckError::UnsupportedEcosystem`] if no fetcher is registered for
    /// `ecosystem`, or [`CheckError::Fetch`] if the request fails.
    pub async fn fetch_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Option<PackageMetadata>, CheckError> {
        let key = (ecosystem.osv_name().to_owned(), name.to_owned());
        if let Some(hit) = self.metadata_cache.get(&key).await {
            return Ok(hit);
        }
        let fetcher = self
            .registries
            .get(&ecosystem)
            .ok_or(CheckError::UnsupportedEcosystem(ecosystem))?;
        let metadata = fetcher.fetch_metadata(name).await?;
        self.metadata_cache.insert(key, metadata.clone()).await;
        Ok(metadata)
    }

    pub async fn check_path(&self, path: impl AsRef<Path>) -> Result<ManifestCheck, CheckError> {
        let path = path.as_ref();
        let kind = ManifestKind::detect(path)
            .ok_or_else(|| CheckError::UnknownManifest(path.to_path_buf()))?;
        let manifest = tokio::fs::read_to_string(path).await?;
        let lockfile = self.read_lockfile(path, kind).await;
        let lockfile = lockfile.as_ref().map(|(kind, lock)| (*kind, lock.as_str()));
        // A member's `dep.workspace = true` states no version of its own; the constraint
        // is in the root above it. Only a path can find that root, which is why this
        // resolves here and not in `check_manifest`.
        let workspace = self.workspace_source(path, kind, &manifest).await;
        self.check_inner(kind, &manifest, lockfile, workspace).await
    }

    /// The workspace declarations governing `path`, read once per root per `Checker`.
    ///
    /// Every member of a workspace resolves against the same file, and parsing it once
    /// per member is the same waste the versions cache exists to avoid — with the
    /// difference that the answer is on local disk, so it only ever showed up as CPU. A
    /// 500-crate workspace parsed one root manifest 500 times.
    ///
    /// Locating the root is still done per manifest: it is the walk that produces the key
    /// this is cached on, and it is the cheap half.
    async fn workspace_source(
        &self,
        path: &Path,
        kind: ManifestKind,
        manifest: &str,
    ) -> Option<(PathBuf, Arc<Vec<Item>>)> {
        let (root, root_content) = crate::discover::workspace_root_of(path, kind, manifest)?;
        if let Some(hit) = self.workspace_cache.get(&root).await {
            return Some((root, hit));
        }
        let declarations = Arc::new(crate::discover::workspace_declarations(kind, &root_content));
        self.workspace_cache
            .insert(root.clone(), declarations.clone())
            .await;
        Some((root, declarations))
    }

    /// Read the lockfile governing `path`, whichever of its candidates exists.
    ///
    /// Uses the same search every other frontend does — the manifest's own
    /// directory first, then each ancestor, stopping at a repository boundary —
    /// so a workspace member picks up the lockfile at the workspace root rather
    /// than reporting no locked versions.
    async fn read_lockfile(
        &self,
        path: &Path,
        kind: ManifestKind,
    ) -> Option<(LockfileKind, String)> {
        if !self.read_lockfiles {
            return None;
        }
        let (lock_path, lock_kind) = crate::discover::locate_lockfile(path, kind)?;
        let content = tokio::fs::read_to_string(&lock_path).await.ok()?;
        Some((lock_kind, content))
    }

    async fn check_inner(
        &self,
        kind: ManifestKind,
        manifest: &str,
        lockfile: Option<(LockfileKind, &str)>,
        workspace: Option<(PathBuf, Arc<Vec<Item>>)>,
    ) -> Result<ManifestCheck, CheckError> {
        let ecosystem = kind.ecosystem();
        // An ecosystem that publishes **no registry at all** is not an unsupported
        // one: there is nothing to register, and its dependencies are still worth
        // scanning for vulnerabilities. Returning `UnsupportedEcosystem` here would
        // drop the manifest before the OSV scan ran, which is the whole feature
        // silently absent.
        //
        // Every other ecosystem keeps the contract it has always had, and that is
        // the point of asking [`Ecosystem::has_registry`] rather than merely
        // observing that no fetcher is registered: a *config-disabled* ecosystem
        // has a registry and is switched off, so it must still be skipped with
        // "is not enabled or not yet supported" rather than half-checked.
        let fetcher = match self.registries.get(&ecosystem) {
            Some(fetcher) => Some(fetcher.clone()),
            None if !ecosystem.has_registry() && self.registryless.contains(&ecosystem) => None,
            None => return Err(CheckError::UnsupportedEcosystem(ecosystem)),
        };

        let mut parsed = parse(kind, manifest)?;

        // Fill in what the workspace root declares, before anything asks which items are
        // checkable — an unresolved `dep.workspace = true` states no version, so it would
        // otherwise be skipped exactly as a `path` entry is. The resolved item keeps
        // `PackageSource::Inherited`, which is what keeps `--fix` off a span that means
        // nothing in this file.
        let mut warnings = Vec::new();
        warnings.extend(std::mem::take(&mut parsed.notices));
        if let Some((root, declarations)) = &workspace {
            // The resolved names are the caller's business; the annotated items are ours.
            let _ = resolve_workspace_inheritance(&mut parsed.items, declarations);
            warnings.extend(undeclared_inheritance(&parsed.items, root));
        }

        // Apply the lockfile to annotate locked versions, dispatching on the file
        // that was found rather than on the manifest beside it. An unparseable
        // lockfile is ignored — the dependency is simply checked without a locked
        // version. `apply_lockfile` only annotates existing items, never inserts,
        // so transitive deps are never introduced.
        if let Some((lock_kind, lock)) = lockfile {
            if let Some(pins) = lockfile_items(lock_kind, lock) {
                // The one lockfile that *is* the dependency list. Its manifest is a
                // program this crate declines to read, so without this a Swift
                // project reports zero dependencies with a `Package.resolved` full
                // of them sitting beside it. Appending rather than replacing keeps
                // the rule that a lockfile never removes what a manifest declared.
                parsed.items.extend(pins);
            } else if let Ok(data) = parse_lockfile_kind(lock_kind, lock) {
                apply_lockfile(&mut parsed.items, &data);
            }
        }

        if let Some(warning) = deferred_versions(&parsed.items, kind) {
            warnings.push(warning);
        }

        let mut results: Vec<CheckResult> = if let Some(fetcher) = &fetcher {
            // Build the fetch task list, routing each checkable item to a fetcher:
            // JSR-sourced items (Deno `jsr:` deps) to the JSR fetcher, items naming a
            // resolved alternate Rust registry to that registry, and everything else
            // to the ecosystem fetcher — each with a distinct cache key. Deduplicated
            // by (cache_key, name).
            let mut seen: HashSet<(String, String)> = HashSet::new();
            let mut tasks: Vec<FetchTask> = Vec::new();
            for item in parsed.items.iter().filter(|i| i.is_checkable()) {
                let (task_fetcher, cache_key) = self.route_item(item, fetcher, ecosystem);
                if seen.insert((cache_key.clone(), item.name.clone())) {
                    tasks.push(FetchTask {
                        name: item.name.clone(),
                        fetcher: task_fetcher,
                        cache_key,
                    });
                }
            }

            let fetched = self.fetch_all(tasks).await;
            parsed
                .items
                .iter()
                .map(|item| evaluate_item(item, &fetched, ecosystem, self.unstable))
                .collect()
        } else {
            // Nothing to ask, so nothing is claimed. The OSV scan below still runs:
            // it needs a package and a version, not a registry, and the lockfile
            // supplied both.
            parsed.items.iter().map(without_a_registry).collect()
        };

        if let Some(osv) = &self.osv
            && let Err(e) = scan_vulnerabilities(osv, ecosystem, &mut results).await
        {
            warnings.push(format!("vulnerability scan skipped: {e}"));
        }

        // License collection is a post-pass over the finished results, shaped
        // exactly like the vulnerability scan above: it degrades to a warning
        // rather than failing the check, because the version data is still
        // correct and useful without a license column.
        // A registry-less ecosystem publishes no metadata endpoint either, so this
        // would fail every time and say so in a warning about a feature the user
        // never asked this ecosystem for.
        if self.licenses
            && fetcher.is_some()
            && let Err(e) = self.attach_licenses(ecosystem, &mut results).await
        {
            warnings.push(format!("license collection skipped: {e}"));
        }

        let mut check = ManifestCheck {
            kind,
            ecosystem,
            results,
            warnings,
            workspace_root: workspace.map(|(root, _)| root),
        };

        // Enrichment is a post-pass over the finished results, so it can equally
        // be driven by hand ([`Checker::enrich_advisories`]) on a check the caller
        // already holds. It degrades exactly as the vulnerability scan does: an
        // OSV failure leaves a warning rather than failing the check, because the
        // version data is still correct and useful without it.
        if self.advisory_details {
            let enrichment = self.enrich_advisories(&mut check).await;
            if let Err(e) = enrichment {
                check
                    .warnings
                    .push(format!("advisory enrichment skipped: {e}"));
            }
        }

        Ok(check)
    }

    /// Choose the fetcher and cache namespace for one checkable item. JSR items go
    /// to the JSR fetcher; an item naming an alternate Rust registry that resolved
    /// to a fetcher goes there, with a per-alias cache key so same-named crates in
    /// different registries never collide; everything else uses `default` (the
    /// ecosystem's fetcher) under the ecosystem's cache key.
    fn route_item(
        &self,
        item: &Item,
        default: &Arc<dyn RegistryFetcher>,
        ecosystem: Ecosystem,
    ) -> (Arc<dyn RegistryFetcher>, String) {
        if item.source == PackageSource::Jsr
            && let Some(jsr) = &self.jsr
        {
            return (jsr.clone(), JSR_CACHE_KEY.to_string());
        }
        if let Some(alias) = &item.registry
            && let Some(fetcher) = self.rust_registries.get(alias)
        {
            return (
                fetcher.clone(),
                format!("{}::{alias}", ecosystem.osv_name()),
            );
        }
        (default.clone(), ecosystem.osv_name().to_string())
    }

    /// Run every fetch task concurrently, serving and populating the in-process
    /// versions cache (keyed per registry), and emitting one progress cycle.
    ///
    /// Because the cache lives on the `Checker` rather than on the call, a
    /// caller that checks several manifests through one `Checker` pays for a
    /// shared package exactly once — which is what makes a monorepo cost one
    /// request per distinct package rather than one per declaration.
    ///
    /// # Precondition
    /// **Manifests must be checked one at a time through a given `Checker`.**
    /// The lookup here is a plain `get` followed later by an `insert`, not
    /// moka's `try_get_with`, so there is no in-flight coalescing: two manifests
    /// checked concurrently would both miss the cache and both issue the
    /// request. The concurrency inside a single manifest is safe — its tasks are
    /// already deduplicated by `(cache_key, name)` before they get here. Anyone
    /// parallelising the *manifest* loop must add coalescing here first.
    async fn fetch_all(&self, tasks: Vec<FetchTask>) -> FetchedMap {
        let total = tasks.len();
        self.emit(ProgressEvent::Started { total });

        let mut out: FetchedMap = HashMap::new();
        let mut to_fetch: Vec<FetchTask> = Vec::new();
        for task in tasks {
            let key = (task.cache_key.clone(), task.name.clone());
            if let Some(versions) = self.versions_cache.get(&key).await {
                out.insert(task.name.clone(), Ok(versions));
            } else if let Some(disk) = &self.disk_cache
                && let Some(versions) = disk.get(&task.cache_key, &task.name).await
            {
                // Disk hit: warm the in-process cache so sibling manifests in this
                // run hit moka instead of re-reading the file.
                self.versions_cache.insert(key, versions.clone()).await;
                out.insert(task.name.clone(), Ok(versions));
            } else {
                to_fetch.push(task);
            }
        }

        let counter = Arc::new(AtomicUsize::new(out.len()));
        let fetched: Vec<FetchOutcome> = stream::iter(to_fetch)
            .map(|task| {
                let progress = self.progress.clone();
                let counter = counter.clone();
                async move {
                    let result = task
                        .fetcher
                        .fetch_versions(&task.name)
                        .await
                        .map(|fetched| fetched.versions)
                        .map_err(|e| e.to_string());
                    let done = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(p) = &progress {
                        p(ProgressEvent::Advanced {
                            completed: done,
                            total,
                        });
                    }
                    (task.name, task.cache_key, result)
                }
            })
            .buffer_unordered(self.concurrency)
            .collect()
            .await;

        for (name, cache_key, result) in fetched {
            if let Ok(versions) = &result {
                self.versions_cache
                    .insert((cache_key.clone(), name.clone()), versions.clone())
                    .await;
                if let Some(disk) = &self.disk_cache {
                    disk.put(&cache_key, &name, versions).await;
                }
            }
            out.insert(name, result);
        }

        self.emit(ProgressEvent::Finished);
        out
    }

    fn emit(&self, event: ProgressEvent) {
        if let Some(p) = &self.progress {
            p(event);
        }
    }
}

/// Name every entry that says it inherits but that the governing root never declared.
///
/// Cargo refuses to build such a manifest, so it is a real error and not a shrug — but it
/// is not this tool's error, and a version check that aborted on it would be less useful
/// than one that reports everything else and says what it could not resolve. The item
/// itself still reports as unchecked, exactly as it did before inheritance was resolved
/// at all; this is what stops that being silent.
fn undeclared_inheritance(items: &[Item], root: &Path) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|item| {
            item.source == PackageSource::Inherited && item.version_constraint.is_empty()
        })
        // A member may inherit the same crate in `[dependencies]` and
        // `[dev-dependencies]` both, which is one mistake to fix, not two to report.
        .filter(|item| seen.insert(item.name.as_str()))
        .map(|item| {
            format!(
                "`{}` is declared `workspace = true`, but {} declares no such dependency",
                item.name,
                root.display()
            )
        })
        .collect()
}

/// Say, once per manifest, that some of its entries state no version this file can
/// resolve — and therefore that nothing was checked for them.
///
/// Without it the run is silent: those entries report as
/// [`DependencyStatus::Undetermined`] in a table a reader may not be reading, and
/// stderr says nothing at all. `undeclared_inheritance` above is the Cargo
/// equivalent and stays separate, because a Cargo member inheriting a name its root
/// never declared is a *broken* manifest, while a POM deferring to its `<parent>` is
/// an ordinary, valid, extremely common one — the same status, two different things
/// to tell the reader.
fn deferred_versions(items: &[Item], kind: ManifestKind) -> Option<String> {
    let source = match kind {
        ManifestKind::PomXml => {
            "a `<parent>`, `<dependencyManagement>`, or a property this file does not declare"
        }
        _ => return None,
    };
    let mut names: Vec<&str> = items
        .iter()
        .filter(|item| {
            item.source == PackageSource::Inherited && item.version_constraint.is_empty()
        })
        .map(|item| item.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return None;
    }
    let (subject, verb, object) = if names.len() == 1 {
        ("dependency", "takes its version", "it")
    } else {
        ("dependencies", "take their version", "them")
    };
    Some(format!(
        "{} {subject} {verb} from {source}, so no version was read for {object} and nothing was checked: {}",
        names.len(),
        names.join(", ")
    ))
}

/// The verdict for an item nothing was ever going to fetch.
fn unfetchable(item: &Item) -> CheckResult {
    let status = match item.source {
        PackageSource::Git => DependencyStatus::Git,
        // An entry that defers its version elsewhere and found nothing there is
        // a real package on a real registry whose version this run never read.
        // `Local` would say the opposite — that there is no registry for it —
        // which of `spring-boot-starter-web` is simply false, and is the wrong
        // token for a CI consumer to read.
        PackageSource::Inherited => DependencyStatus::Undetermined,
        _ => DependencyStatus::Local,
    };
    CheckResult::new(item.clone(), status)
}

/// The verdict for one item in an ecosystem that publishes no registry.
///
/// A path or git dependency reports exactly what it always did — nothing was
/// going to be fetched for it either way. Everything else is
/// [`DependencyStatus::Undetermined`]: currency here is not merely unread but
/// *unknowable*, and both `UpToDate` and `Error` would be claims this run has no
/// basis for. `Local` would be worse still, since these are real published
/// packages that simply have no registry behind them.
fn without_a_registry(item: &Item) -> CheckResult {
    if !item.is_checkable() {
        return unfetchable(item);
    }
    CheckResult::new(item.clone(), DependencyStatus::Undetermined)
}

/// Evaluate one parsed item against the fetched version lists, applying the
/// configured pre-release filter before classification.
fn evaluate_item(
    item: &Item,
    fetched: &FetchedMap,
    ecosystem: Ecosystem,
    unstable: UnstableFilter,
) -> CheckResult {
    if !item.is_checkable() {
        return unfetchable(item);
    }
    match fetched.get(&item.name) {
        Some(Ok(versions)) => {
            // The current version drives `IncludeIfCurrent`: the locked version if
            // known, else the declared constraint (its pre-release markers, if any,
            // are detected by substring).
            let current = item
                .locked_version
                .as_deref()
                .or(Some(item.version_constraint.as_str()));
            // Filter on the raw (registry-native) version strings so pre-release
            // detection sees real markers, then translate to semver for comparison.
            let filtered = unstable.filter(versions, current, ecosystem);
            let filtered = same_flavour_only(&filtered, current, ecosystem);
            let translated = to_semver_versions(&filtered, ecosystem);
            let candidates: Vec<String> = translated
                .iter()
                .map(|(semver, _)| semver.clone())
                .collect();
            let constraint = to_semver_constraint(&item.version_constraint, ecosystem);
            let eval = check_version(&constraint, &candidates, item.locked_version.as_deref());
            CheckResult::from_evaluation(item.clone(), in_native_versions(eval, &translated))
        }
        Some(Err(e)) => CheckResult::new(item.clone(), DependencyStatus::Error(e.clone())),
        None => CheckResult::new(
            item.clone(),
            DependencyStatus::Error("not fetched".to_string()),
        ),
    }
}

/// Translate registry-native version strings into semver for comparison, keeping
/// each translation paired with the string the registry actually publishes.
///
/// Python (PEP 440), C# (NuGet), and the JVM (Maven) all spell versions in a
/// dialect semver cannot parse, so comparison needs a translation — but the
/// translation is **lossy in the direction that matters for reporting**:
/// `6.4.4.Final`, `5.3.9.RELEASE`, and `9.4.51.v20230217` translate to `6.4.4`,
/// `5.3.9`, and `9.4.51-v.20230217`, and none of those names a published artifact.
/// Reporting the translated string — or splicing it into a manifest with `--fix` —
/// hands the user a version that does not exist. So the pairing is carried through
/// evaluation and [`in_native_versions`] puts the native spelling back.
///
/// The result keeps the input order, which is the registry's newest-first order
/// ([`crate::registries::FetchedVersions`]).
fn to_semver_versions(versions: &[String], ecosystem: Ecosystem) -> Vec<(String, String)> {
    let translate: fn(&str) -> Option<String> = match ecosystem {
        Ecosystem::Python => dependable_core::semver::python::pep440_to_semver,
        Ecosystem::CSharp => dependable_core::semver::nuget::nuget_to_semver,
        Ecosystem::Jvm => dependable_core::semver::maven::maven_to_semver,
        // Every other ecosystem publishes semver already, so the native string is
        // its own translation.
        _ => return versions.iter().map(|v| (v.clone(), v.clone())).collect(),
    };
    versions
        .iter()
        .filter_map(|v| translate(v).map(|semver| (semver, v.clone())))
        .collect()
}

/// Restore the registry-native spelling of an evaluation's reported versions.
///
/// `check_version` compares semver and reports semver, so its `latest_compatible`
/// / `latest_available` are translated strings. Each is matched back to the native
/// string it came from by *parsed* semver equality rather than by text, because a
/// version that round-trips through [`semver::Version`] can come back spelled
/// differently from the string that was handed in.
///
/// Several natives can translate to one semver — Maven reads `1.0` and `1.0.0` as
/// the same version, so both translate to `1.0.0`. The first match in the list
/// wins, and the list is the registry's newest-first order, so the winner is the
/// newest native spelling of that version. A translated version with no surviving
/// native (which nothing produces today) is left as it was rather than dropped.
fn in_native_versions(mut eval: Evaluation, translated: &[(String, String)]) -> Evaluation {
    eval.latest_compatible = eval
        .latest_compatible
        .map(|v| native_for(&v, translated).unwrap_or(v));
    eval.latest_available = eval
        .latest_available
        .map(|v| native_for(&v, translated).unwrap_or(v));
    eval
}

/// The native string whose translation is `semver`, or `None` when none matches.
fn native_for(semver: &str, translated: &[(String, String)]) -> Option<String> {
    let wanted = SemverVersion::parse(semver).ok()?;
    translated
        .iter()
        .find(|(candidate, _)| SemverVersion::parse(candidate).is_ok_and(|parsed| parsed == wanted))
        .map(|(_, native)| native.clone())
}

/// Keep only the candidates in the same Maven *flavour* as the current version.
///
/// A flavour is a build variant published under the same version number —
/// `com.google.guava:guava` ships `32.1.3-android` beside `32.1.3-jre` — and it is
/// not a version at all: it selects which artifact, not which release. Maven's own
/// order compares the numbers first, so `33.7.1-jre` outranks `32.1.3-android` and
/// an Android project offered "the latest version" is quietly moved onto the JRE
/// jar, which is the classic desugaring break. Versions in a different flavour are
/// therefore not candidates for this dependency at all.
///
/// Filtering to nothing means the current flavour has no published versions, which
/// is not an answer anyone can use; the unfiltered list is returned instead, the
/// same fallback [`UnstableFilter::filter`] makes.
fn same_flavour_only(
    versions: &[String],
    current: Option<&str>,
    ecosystem: Ecosystem,
) -> Vec<String> {
    if ecosystem != Ecosystem::Jvm {
        return versions.to_vec();
    }
    let wanted = current.and_then(dependable_core::semver::maven::flavour);
    let kept: Vec<String> = versions
        .iter()
        .filter(|v| dependable_core::semver::maven::flavour(v) == wanted)
        .cloned()
        .collect();
    if kept.is_empty() {
        versions.to_vec()
    } else {
        kept
    }
}

/// The OSV query for one result, or `None` if there is nothing to ask about.
///
/// The version is the locked one if the lockfile resolved it, else the best
/// version satisfying the constraint — which is what an unlocked project would
/// actually install. Shared by the batch scan and the advisory-enrichment pass so
/// the two produce identical cache keys, and so the advisories describe the exact
/// version that was flagged.
fn osv_query_for(result: &CheckResult, ecosystem: Ecosystem) -> Option<OsvQuery> {
    if !result.item.is_checkable() || matches!(result.status, DependencyStatus::Error(_)) {
        return None;
    }
    let version = result
        .item
        .locked_version
        .clone()
        .or_else(|| result.latest_compatible.clone())?;
    Some(OsvQuery {
        ecosystem: ecosystem.osv_name().to_string(),
        name: result.item.name.clone(),
        version,
    })
}

/// Query OSV for the current version of each checkable dependency and flip its
/// status to `Vulnerable` when advisories are found. OSV chunking (≤500 per
/// request) is handled inside [`OsvClient::query_batch`].
async fn scan_vulnerabilities(
    osv: &OsvClient,
    ecosystem: Ecosystem,
    results: &mut [CheckResult],
) -> Result<(), FetchError> {
    let mut queries = Vec::new();
    let mut index_for = Vec::new();
    for (i, result) in results.iter().enumerate() {
        if let Some(query) = osv_query_for(result, ecosystem) {
            queries.push(query);
            index_for.push(i);
        }
    }
    if queries.is_empty() {
        return Ok(());
    }

    let osv_results = osv.query_batch(&queries).await?;
    for (query_idx, &result_idx) in index_for.iter().enumerate() {
        if let Some(ids) = osv_results.get(query_idx)
            && !ids.is_empty()
        {
            results[result_idx].current_vulnerabilities = ids.clone();
            results[result_idx].status = DependencyStatus::Vulnerable;
        }
    }
    Ok(())
}

/// Builder for [`Checker`]. Defaults target the public crates.io index with OSV
/// scanning enabled.
#[must_use]
pub struct CheckerBuilder {
    client: Option<reqwest::Client>,
    rust_registry: String,
    rust_auth: Option<String>,
    /// Alternate Rust registries: `(alias, sparse index URL, optional token)`.
    rust_alt_registries: Vec<(String, String, Option<String>)>,
    extra_registries: Vec<(Ecosystem, Arc<dyn RegistryFetcher>)>,
    jsr: Option<Arc<dyn RegistryFetcher>>,
    registryless: Vec<Ecosystem>,
    vulnerabilities: bool,
    include_ghsa: bool,
    advisory_details: bool,
    licenses: bool,
    osv_url: String,
    concurrency: usize,
    read_lockfiles: bool,
    unstable: UnstableFilter,
    disk_cache: bool,
    disk_cache_dir: Option<PathBuf>,
    progress: Option<ProgressSink>,
}

impl Default for CheckerBuilder {
    fn default() -> Self {
        Self {
            client: None,
            rust_registry: Ecosystem::Rust.default_registry().to_string(),
            rust_auth: None,
            rust_alt_registries: Vec::new(),
            extra_registries: Vec::new(),
            jsr: None,
            registryless: Vec::new(),
            vulnerabilities: true,
            include_ghsa: false,
            advisory_details: false,
            licenses: false,
            osv_url: DEFAULT_OSV_BATCH_URL.to_string(),
            concurrency: DEFAULT_CONCURRENCY,
            read_lockfiles: true,
            unstable: UnstableFilter::default(),
            disk_cache: true,
            disk_cache_dir: None,
            progress: None,
        }
    }
}

impl CheckerBuilder {
    /// Reuse an existing HTTP client (to share a connection pool). If unset, one
    /// is built on [`CheckerBuilder::build`].
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Configure the Rust/crates.io sparse index and an optional auth token.
    /// Defaults to `https://index.crates.io` with no auth.
    pub fn rust_registry(mut self, index_url: impl Into<String>, auth: Option<String>) -> Self {
        self.rust_registry = index_url.into();
        self.rust_auth = auth;
        self
    }

    /// Register an alternate Rust registry: an `alias` (matched against a
    /// dependency's `registry = "<alias>"`), its sparse `index_url`, and an
    /// optional `auth` token sent verbatim as `Authorization: <token>`. Call once
    /// per registry; the CLI resolves these from `$CARGO_HOME/config.toml` +
    /// `credentials.toml`. A `sparse+` URL prefix is accepted and stripped.
    pub fn rust_alt_registry(
        mut self,
        alias: impl Into<String>,
        index_url: impl Into<String>,
        auth: Option<String>,
    ) -> Self {
        self.rust_alt_registries
            .push((alias.into(), index_url.into(), auth));
        self
    }

    /// Register (or override) the fetcher for an ecosystem. This is the
    /// forward-compatible extension point for npm, PyPI, Go, and others.
    pub fn registry(mut self, ecosystem: Ecosystem, fetcher: Arc<dyn RegistryFetcher>) -> Self {
        self.extra_registries.push((ecosystem, fetcher));
        self
    }

    /// Check an ecosystem that publishes no registry, and so has no fetcher to
    /// register.
    ///
    /// For every other ecosystem [`CheckerBuilder::registry`] *is* the switch: a
    /// `Checker` with no fetcher for one skips its manifests with
    /// [`CheckError::UnsupportedEcosystem`]. An ecosystem with nothing to register
    /// would otherwise have no off switch at all, and declining it has to stay
    /// possible — the answers it gives are shaped differently from every other
    /// ecosystem's, reporting *vulnerable* but never *outdated*.
    ///
    /// Off by default, exactly as every non-Rust ecosystem is. Passing an ecosystem
    /// for which [`Ecosystem::has_registry`] is `true` does nothing: that ecosystem
    /// is enabled by registering its fetcher.
    pub fn registryless(mut self, ecosystem: Ecosystem) -> Self {
        self.registryless.push(ecosystem);
        self
    }

    /// Register the JSR fetcher used for Deno `jsr:` dependencies. JSR is a
    /// sub-registry of the npm ecosystem: items with [`PackageSource::Jsr`] route
    /// here instead of to the npm fetcher.
    pub fn jsr_registry(mut self, fetcher: Arc<dyn RegistryFetcher>) -> Self {
        self.jsr = Some(fetcher);
        self
    }

    /// Enable or disable OSV vulnerability scanning (default: enabled).
    pub fn vulnerabilities(mut self, enabled: bool) -> Self {
        self.vulnerabilities = enabled;
        self
    }

    /// Include GHSA-prefixed advisories in vulnerability results (default: false).
    pub fn include_ghsa(mut self, include: bool) -> Self {
        self.include_ghsa = include;
        self
    }

    /// Fetch full advisory records for vulnerable dependencies (default: false).
    ///
    /// Off by default because it is not free: enrichment costs one extra OSV
    /// request per distinct vulnerable package version, so a plain check makes no
    /// additional requests at all. Turn it on when something is going to *show*
    /// the advisories — a severity gate, a SARIF report, a detail pane.
    ///
    /// Harmless and silent when combined with `vulnerabilities(false)`: with no
    /// OSV client there is nothing to enrich.
    pub fn advisory_details(mut self, enabled: bool) -> Self {
        self.advisory_details = enabled;
        self
    }

    /// Collect each dependency's registry-declared license (default: false).
    ///
    /// Off by default because it is not free: one metadata request per distinct
    /// dependency name, on top of the version lookups. Turn it on when something
    /// is going to *use* the license — a `[policy] allowed_licenses` gate, or a
    /// report that shows it. Registries with no metadata endpoint stay `None`.
    pub fn licenses(mut self, enabled: bool) -> Self {
        self.licenses = enabled;
        self
    }

    /// Override the OSV batch endpoint (default: `api.osv.dev`).
    pub fn osv_url(mut self, url: impl Into<String>) -> Self {
        self.osv_url = url.into();
        self
    }

    /// Maximum concurrent registry fetches (default: 20, clamped to at least 1).
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = n.max(1);
        self
    }

    /// Whether [`Checker::check_path`] reads the sibling lockfile (default: true).
    pub fn read_lockfiles(mut self, enabled: bool) -> Self {
        self.read_lockfiles = enabled;
        self
    }

    /// How to treat pre-release versions (default: [`UnstableFilter::Exclude`]).
    pub fn unstable(mut self, filter: UnstableFilter) -> Self {
        self.unstable = filter;
        self
    }

    /// Enable or disable the persistent on-disk registry cache (default: enabled).
    /// When enabled, registry version lists are cached under the OS cache directory
    /// with a short TTL so repeat and CI runs avoid re-fetching. Maps to `--no-cache`.
    pub fn disk_cache(mut self, enabled: bool) -> Self {
        self.disk_cache = enabled;
        self
    }

    /// Override the on-disk cache directory (default: the OS cache directory).
    /// Mainly for tests and embedders that want an isolated cache location; has no
    /// effect when [`CheckerBuilder::disk_cache`] is disabled.
    pub fn disk_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.disk_cache_dir = Some(dir.into());
        self
    }

    /// Register a progress sink. Both check methods emit through it; external
    /// callers that don't need progress can ignore this.
    pub fn on_progress(mut self, sink: Arc<dyn Fn(ProgressEvent) + Send + Sync>) -> Self {
        self.progress = Some(sink);
        self
    }

    /// Build the checker.
    ///
    /// # Errors
    /// Returns [`CheckError::Fetch`] if an HTTP client must be constructed and TLS
    /// initialization fails.
    pub fn build(self) -> Result<Checker, CheckError> {
        let client = match self.client {
            Some(c) => c,
            None => build_client().map_err(FetchError::from)?,
        };

        let mut registries: HashMap<Ecosystem, Arc<dyn RegistryFetcher>> = HashMap::new();
        registries.insert(
            Ecosystem::Rust,
            Arc::new(CratesIoFetcher::with_registry(
                client.clone(),
                self.rust_registry,
                self.rust_auth,
            )),
        );
        for (ecosystem, fetcher) in self.extra_registries {
            registries.insert(ecosystem, fetcher);
        }

        // Alternate Rust registries, each a crates.io-protocol fetcher against its
        // own sparse index + token, keyed by the alias dependencies reference.
        let mut rust_registries: HashMap<String, Arc<dyn RegistryFetcher>> = HashMap::new();
        for (alias, index_url, auth) in self.rust_alt_registries {
            rust_registries.insert(
                alias,
                Arc::new(CratesIoFetcher::with_registry(
                    client.clone(),
                    index_url,
                    auth,
                )),
            );
        }

        let osv = self.vulnerabilities.then(|| {
            Arc::new(OsvClient::with_url(
                client.clone(),
                self.osv_url,
                self.include_ghsa,
            ))
        });

        // Resolve the disk cache: enabled + a usable directory (explicit override
        // or the OS default). If no directory resolves, the disk cache is simply off.
        let disk_cache = self
            .disk_cache
            .then(|| self.disk_cache_dir.or_else(DiskCache::default_root))
            .flatten()
            .map(|dir| Arc::new(DiskCache::new(dir, DISK_CACHE_TTL)));

        Ok(Checker {
            registries,
            rust_registries,
            jsr: self.jsr,
            registryless: self.registryless.into_iter().collect(),
            osv,
            advisory_details: self.advisory_details,
            licenses: self.licenses,
            concurrency: self.concurrency,
            read_lockfiles: self.read_lockfiles,
            unstable: self.unstable,
            versions_cache: versions_cache(),
            metadata_cache: metadata_cache(),
            workspace_cache: workspace_cache(),
            disk_cache,
            progress: self.progress,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dependable_core::parse;

    /// The single item declared by `manifest`. Built through the parser because
    /// `Item` is `#[non_exhaustive]` and cannot be written out from this crate.
    fn item(manifest: &str) -> Item {
        parse(ManifestKind::CargoToml, manifest)
            .expect("fixture should parse")
            .items
            .into_iter()
            .next()
            .expect("fixture should declare a dependency")
    }

    fn registry_item() -> Item {
        item("[dependencies]\ntime = \"0.2.7\"\n")
    }

    /// A `Package.resolved` v2 pin set, the only record of a Swift project's
    /// dependencies.
    const PACKAGE_RESOLVED: &str = r#"{
  "pins" : [
    {
      "identity" : "swift-nio",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/apple/swift-nio.git",
      "state" : { "revision" : "635b25", "version" : "2.65.0" }
    },
    {
      "identity" : "helpers",
      "kind" : "fileSystem",
      "location" : "/Users/me/helpers",
      "state" : { }
    }
  ],
  "version" : 2
}"#;

    /// A checker wired the way the CLI wires one when an ecosystem is switched off
    /// in config: no fetcher for it, and no network reachable if one were tried.
    fn offline_checker() -> Checker {
        Checker::builder()
            .rust_registry("http://127.0.0.1:1".to_string(), None)
            .registryless(Ecosystem::Swift)
            .vulnerabilities(false)
            .disk_cache(false)
            .build()
            .expect("a checker builds without a network")
    }

    /// The feature this whole ecosystem rests on. Before `has_registry`, a manifest
    /// whose ecosystem had no registered fetcher was dropped with
    /// `UnsupportedEcosystem` *before* the OSV scan — so a registry-less ecosystem
    /// was not degraded, it was absent.
    #[tokio::test]
    async fn an_ecosystem_with_no_registry_is_checked_rather_than_skipped() {
        let check = offline_checker()
            .check_manifest(ManifestKind::PackageSwift, "", Some(PACKAGE_RESOLVED))
            .await
            .expect("a registry-less ecosystem is not an unsupported one");

        assert_eq!(check.ecosystem, Ecosystem::Swift);
        let names: Vec<&str> = check.results.iter().map(|r| r.item.name.as_str()).collect();
        assert_eq!(
            names,
            ["github.com/apple/swift-nio", "helpers"],
            "the pin set is the dependency list; `Package.swift` supplied none"
        );

        let nio = &check.results[0];
        assert_eq!(
            nio.status,
            DependencyStatus::Undetermined,
            "no registry exists to compare against, so no currency claim is made"
        );
        assert_eq!(nio.item.locked_version.as_deref(), Some("2.65.0"));
        assert_eq!(
            nio.latest_available, None,
            "nothing was fetched, so nothing is offered as newer"
        );
        // A local package reports what it always did — nothing was going to be
        // fetched for it in any ecosystem.
        assert_eq!(check.results[1].status, DependencyStatus::Local);
    }

    /// The discriminator. `has_registry()` is true for every ecosystem but Swift,
    /// so an ecosystem the user switched off in config keeps the old path and the
    /// CLI keeps printing `skipping … is not enabled or not yet supported`.
    /// Collapsing the two would silently half-check every disabled ecosystem.
    #[tokio::test]
    async fn a_config_disabled_ecosystem_is_still_reported_unsupported() {
        for (kind, manifest, ecosystem) in [
            (
                ManifestKind::PubspecYaml,
                "dependencies:\n  http: ^1.1.0\n",
                Ecosystem::Dart,
            ),
            (
                ManifestKind::GoMod,
                "require github.com/a/b v1.0.0\n",
                Ecosystem::Go,
            ),
            (
                ManifestKind::MixExs,
                "defp deps do\n  [{:jason, \"~> 1.4\"}]\nend\n",
                Ecosystem::Elixir,
            ),
        ] {
            let outcome = offline_checker().check_manifest(kind, manifest, None).await;
            assert!(
                matches!(outcome, Err(CheckError::UnsupportedEcosystem(eco)) if eco == ecosystem),
                "{ecosystem:?} has a registry and was switched off, so it must be skipped, not checked"
            );
        }
    }

    /// Having no registry is not the same as being asked for. A caller that never
    /// opted in gets the same skip every other unregistered ecosystem gets, which
    /// is what gives `[swift] enabled = false` something to do.
    #[tokio::test]
    async fn a_registryless_ecosystem_not_asked_for_is_skipped() {
        let checker = Checker::builder()
            .rust_registry("http://127.0.0.1:1".to_string(), None)
            .vulnerabilities(false)
            .disk_cache(false)
            .build()
            .expect("a checker builds without a network");

        let outcome = checker
            .check_manifest(ManifestKind::PackageSwift, "", Some(PACKAGE_RESOLVED))
            .await;
        assert!(
            matches!(
                outcome,
                Err(CheckError::UnsupportedEcosystem(Ecosystem::Swift))
            ),
            "an ecosystem nobody asked for is off, registry or no registry"
        );
    }

    /// Two ways to have no fetcher, two different answers. This is the pair a
    /// reviewer should attack first.
    #[tokio::test]
    async fn having_no_registry_and_being_switched_off_are_not_the_same_state() {
        let checker = offline_checker();
        assert!(
            checker
                .check_manifest(ManifestKind::PackageSwift, "", Some(PACKAGE_RESOLVED))
                .await
                .is_ok()
        );
        assert!(
            checker
                .check_manifest(
                    ManifestKind::PubspecYaml,
                    "dependencies:\n  http: ^1.1.0\n",
                    None
                )
                .await
                .is_err()
        );
    }

    /// `apply_lockfile` never inserts, and five ecosystems depend on that. Only the
    /// one lockfile that *is* the dependency list may supply items.
    #[tokio::test]
    async fn a_lockfile_that_is_not_a_dependency_source_still_only_annotates() {
        let lock = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\n\
                    [[package]]\nname = \"transitive\"\nversion = \"9.9.9\"\n";
        let check = offline_checker()
            .check_manifest(
                ManifestKind::CargoToml,
                "[dependencies]\nserde = \"1\"\n",
                Some(lock),
            )
            .await
            .expect("rust is registered");
        let names: Vec<&str> = check.results.iter().map(|r| r.item.name.as_str()).collect();
        assert_eq!(
            names,
            ["serde"],
            "a transitive lock entry is not a dependency"
        );
    }

    #[test]
    fn a_locked_version_outranks_the_best_compatible_one() {
        let mut declared = registry_item();
        declared.locked_version = Some("0.2.7".to_string());
        let mut result = CheckResult::new(declared, DependencyStatus::UpToDate);
        result.latest_compatible = Some("0.2.9".to_string());

        let query = osv_query_for(&result, Ecosystem::Rust).expect("a query");
        assert_eq!(query.ecosystem, "crates.io");
        assert_eq!(query.name, "time");
        assert_eq!(query.version, "0.2.7");
    }

    #[test]
    fn an_unlocked_dependency_is_queried_at_its_best_compatible_version() {
        let mut result = CheckResult::new(registry_item(), DependencyStatus::UpToDate);
        result.latest_compatible = Some("0.2.9".to_string());
        let query = osv_query_for(&result, Ecosystem::Rust).expect("a query");
        assert_eq!(query.version, "0.2.9");
    }

    #[test]
    fn nothing_is_queried_without_a_version() {
        let result = CheckResult::new(registry_item(), DependencyStatus::UpToDate);
        assert!(osv_query_for(&result, Ecosystem::Rust).is_none());
    }

    #[test]
    fn a_path_dependency_is_never_queried() {
        let declared = item("[dependencies]\nlocal = { path = \"../local\" }\n");
        assert!(!declared.is_checkable());
        let result = CheckResult::new(declared, DependencyStatus::Local);
        assert!(osv_query_for(&result, Ecosystem::Rust).is_none());
    }

    #[test]
    fn an_errored_result_is_never_queried() {
        let mut declared = registry_item();
        declared.locked_version = Some("0.2.7".to_string());
        let result = CheckResult::new(
            declared,
            DependencyStatus::Error("registry unreachable".to_string()),
        );
        assert!(osv_query_for(&result, Ecosystem::Rust).is_none());
    }

    /// The single item declared by `manifest`, parsed as `kind`.
    fn item_of(kind: ManifestKind, manifest: &str) -> Item {
        parse(kind, manifest)
            .expect("fixture should parse")
            .items
            .into_iter()
            .next()
            .expect("fixture should declare a dependency")
    }

    /// A Maven coordinate declared in a Gradle catalog at `version`.
    fn jvm_item(coordinate: &str, version: &str) -> Item {
        item_of(
            ManifestKind::GradleVersionCatalog,
            &format!("[libraries]\nlib = \"{coordinate}:{version}\"\n"),
        )
    }

    /// Evaluate `item` against `versions` (newest-first, as a registry returns them).
    fn evaluated(
        item: &Item,
        versions: &[&str],
        ecosystem: Ecosystem,
        unstable: UnstableFilter,
    ) -> CheckResult {
        let mut fetched: FetchedMap = HashMap::new();
        fetched.insert(
            item.name.clone(),
            Ok(versions.iter().map(|v| (*v).to_string()).collect()),
        );
        evaluate_item(item, &fetched, ecosystem, unstable)
    }

    /// Every version this tool reports has to be one the registry publishes. The
    /// semver translation is for comparison only: `6.4.4.Final` compares as
    /// `6.4.4`, but `6.4.4` names no artifact, and `--fix` splices whatever is
    /// reported straight into the manifest.
    #[test]
    fn a_reported_jvm_version_is_one_maven_central_publishes() {
        // Reproduced live against Maven Central before this was fixed: each of
        // these was reported (and written by `--fix`) as its translation.
        for (coordinate, declared, available, expected_latest) in [
            (
                "org.hibernate.orm:hibernate-core",
                "6.4.4.Final",
                ["6.6.0.Final", "6.4.4.Final"],
                "6.6.0.Final",
            ),
            (
                "org.springframework:spring-core",
                "5.3.9.RELEASE",
                ["5.3.39.RELEASE", "5.3.9.RELEASE"],
                "5.3.39.RELEASE",
            ),
            (
                "org.eclipse.jetty:jetty-server",
                "9.4.51.v20230217",
                ["9.4.53.v20231009", "9.4.51.v20230217"],
                "9.4.53.v20231009",
            ),
        ] {
            let item = jvm_item(coordinate, declared);
            let result = evaluated(&item, &available, Ecosystem::Jvm, UnstableFilter::Exclude);
            assert_eq!(
                result.latest_available.as_deref(),
                Some(expected_latest),
                "{coordinate}"
            );
            // The constraint is exact, so the best compatible version is the
            // declared one — spelled the way the catalog spells it, or `--fix`
            // would see a change where there is none and rewrite the line.
            assert_eq!(
                result.latest_compatible.as_deref(),
                Some(declared),
                "{coordinate}"
            );
        }
    }

    /// The same loss, in the two other ecosystems that translate: NuGet drops a
    /// fourth segment and PEP 440 respells a pre-release, so both would report a
    /// version their registry has never heard of.
    #[test]
    fn a_reported_version_keeps_its_registry_spelling_outside_the_jvm() {
        let nuget = item_of(
            ManifestKind::Csproj,
            "<Project><ItemGroup>\
             <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\
             </ItemGroup></Project>",
        );
        let result = evaluated(
            &nuget,
            &["13.0.3.1", "13.0.1"],
            Ecosystem::CSharp,
            UnstableFilter::Exclude,
        );
        assert_eq!(
            result.latest_available.as_deref(),
            Some("13.0.3.1"),
            "the revision segment is dropped by the translation, not by NuGet"
        );

        let python = item_of(ManifestKind::RequirementsTxt, "requests==2.31.0\n");
        let result = evaluated(
            &python,
            &["3.0.0b1", "2.31.0"],
            Ecosystem::Python,
            UnstableFilter::IncludeAlways,
        );
        assert_eq!(
            result.latest_available.as_deref(),
            Some("3.0.0b1"),
            "PEP 440 spells this `3.0.0b1`; semver spells it `3.0.0-beta.1`"
        );
    }

    /// Maven reads `1.0` and `1.0.0` as one version, so two natives can translate
    /// to one semver. The list is newest-first, so the first match is the newest
    /// spelling — and the choice has to be a rule, not whichever the hash order
    /// happened to yield.
    #[test]
    fn the_first_native_wins_when_two_translate_to_one_version() {
        let item = jvm_item("org.example:lib", "0.9");
        let result = evaluated(
            &item,
            &["1.0.0", "1.0", "0.9"],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(result.latest_available.as_deref(), Some("1.0.0"));

        let reversed = evaluated(
            &item,
            &["1.0", "1.0.0", "0.9"],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(reversed.latest_available.as_deref(), Some("1.0"));
    }

    /// A flavour is which artifact, not which release: moving an Android project
    /// onto the JRE jar is the classic desugaring break, and `fix --all` did it
    /// silently because Maven's order compares the numbers first.
    #[test]
    fn an_android_build_is_never_offered_the_jre_one() {
        let item = jvm_item("com.google.guava:guava", "32.1.3-android");
        let result = evaluated(
            &item,
            &[
                "33.7.1-jre",
                "33.7.1-android",
                "32.1.3-jre",
                "32.1.3-android",
            ],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(result.latest_available.as_deref(), Some("33.7.1-android"));
        assert_eq!(result.latest_compatible.as_deref(), Some("32.1.3-android"));

        // And the other way round, which is the same defect mirrored.
        let jre = jvm_item("com.google.guava:guava", "32.1.3-jre");
        let result = evaluated(
            &jre,
            &[
                "33.7.1-jre",
                "33.7.1-android",
                "32.1.3-jre",
                "32.1.3-android",
            ],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(result.latest_available.as_deref(), Some("33.7.1-jre"));
    }

    /// A dated build stamp is not a flavour: Jetty stamps its whole 9.4 line, and
    /// reading that as a variant would hide every release above it.
    #[test]
    fn a_dated_build_stamp_does_not_partition_a_version_line() {
        let item = jvm_item("org.eclipse.jetty:jetty-server", "9.4.51.v20230217");
        let result = evaluated(
            &item,
            &["12.0.9", "9.4.53.v20231009", "9.4.51.v20230217"],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(result.latest_available.as_deref(), Some("12.0.9"));
    }

    /// Under the default filter — the one every user gets — a milestone or a beta
    /// is not the latest release.
    #[test]
    fn a_maven_prerelease_is_not_offered_as_the_latest_stable() {
        let hibernate = jvm_item("org.hibernate.orm:hibernate-core", "6.4.4.Final");
        let result = evaluated(
            &hibernate,
            &["8.0.0.Beta1", "6.6.0.Final", "6.4.4.Final"],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(result.latest_available.as_deref(), Some("6.6.0.Final"));

        let spring = jvm_item("org.springframework:spring-core", "5.3.9.RELEASE");
        let result = evaluated(
            &spring,
            &["7.1.0.M1", "6.1.14", "5.3.9.RELEASE"],
            Ecosystem::Jvm,
            UnstableFilter::Exclude,
        );
        assert_eq!(result.latest_available.as_deref(), Some("6.1.14"));

        // Asking for them still finds them, in their published spelling.
        let result = evaluated(
            &spring,
            &["7.1.0.M1", "6.1.14", "5.3.9.RELEASE"],
            Ecosystem::Jvm,
            UnstableFilter::IncludeAlways,
        );
        assert_eq!(result.latest_available.as_deref(), Some("7.1.0.M1"));
    }
}
