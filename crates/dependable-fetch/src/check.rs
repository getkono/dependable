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
    CheckResult, DependencyStatus, Ecosystem, Item, ManifestKind, PackageSource, UnstableFilter,
    apply_lockfile, check_version, parse, parse_lockfile, to_semver_constraint,
};
use futures::stream::{self, StreamExt};

use crate::build_client;
use crate::cache::{VersionsCache, versions_cache};
use crate::error::FetchError;
use crate::osv::{OsvClient, OsvQuery};
use crate::registries::{CratesIoFetcher, RegistryFetcher};

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
    /// Fetcher for [`PackageSource::Jsr`] items (a sub-registry of the npm
    /// ecosystem), used for Deno `jsr:` dependencies.
    jsr: Option<Arc<dyn RegistryFetcher>>,
    osv: Option<Arc<OsvClient>>,
    concurrency: usize,
    read_lockfiles: bool,
    unstable: UnstableFilter,
    versions_cache: VersionsCache,
    progress: Option<ProgressSink>,
}

/// Cache key used for JSR lookups, kept distinct from the npm ecosystem key.
const JSR_CACHE_KEY: &str = "jsr";

/// One package to fetch: its name, the fetcher to use, and its versions-cache key.
struct FetchTask {
    name: String,
    fetcher: Arc<dyn RegistryFetcher>,
    cache_key: &'static str,
}

/// The result of one fetch task: `(name, cache_key, versions-or-error)`.
type FetchOutcome = (String, &'static str, Result<Vec<String>, String>);

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
        self.check_inner(kind, manifest, lockfile).await
    }

    /// Check a manifest on disk: detect its kind, read it (and, when
    /// [`CheckerBuilder::read_lockfiles`] is set, its sibling lockfile), then check.
    /// This is the only place the library performs filesystem IO.
    ///
    /// # Errors
    /// [`CheckError::UnknownManifest`] if the file name is unrecognized,
    /// [`CheckError::Io`] if the manifest cannot be read, plus the errors of
    /// [`Checker::check_manifest`].
    pub async fn check_path(&self, path: impl AsRef<Path>) -> Result<ManifestCheck, CheckError> {
        let path = path.as_ref();
        let kind = ManifestKind::detect(path)
            .ok_or_else(|| CheckError::UnknownManifest(path.to_path_buf()))?;
        let manifest = tokio::fs::read_to_string(path).await?;
        let lockfile = self.read_sibling_lockfile(path, kind).await;
        self.check_inner(kind, &manifest, lockfile.as_deref()).await
    }

    async fn read_sibling_lockfile(&self, path: &Path, kind: ManifestKind) -> Option<String> {
        if !self.read_lockfiles {
            return None;
        }
        let name = kind.lockfile_name()?;
        let lock_path = path.parent().unwrap_or_else(|| Path::new(".")).join(name);
        tokio::fs::read_to_string(&lock_path).await.ok()
    }

    async fn check_inner(
        &self,
        kind: ManifestKind,
        manifest: &str,
        lockfile: Option<&str>,
    ) -> Result<ManifestCheck, CheckError> {
        let ecosystem = kind.ecosystem();
        let fetcher = self
            .registries
            .get(&ecosystem)
            .ok_or(CheckError::UnsupportedEcosystem(ecosystem))?
            .clone();

        let mut parsed = parse(kind, manifest)?;

        // Apply the lockfile to annotate locked versions, dispatching by manifest
        // kind. A kind without a lockfile parser (or an unparseable lockfile) is
        // ignored — the dependency is simply checked without a locked version.
        // `apply_lockfile` only annotates existing items, never inserts, so
        // transitive deps are never introduced.
        if let Some(lock) = lockfile
            && let Ok(data) = parse_lockfile(kind, lock)
        {
            apply_lockfile(&mut parsed.items, &data);
        }

        // Build the fetch task list, routing JSR-sourced items (Deno `jsr:` deps)
        // to the JSR fetcher and everything else to the ecosystem fetcher, with a
        // distinct cache key per registry. Deduplicated by (cache_key, name).
        let mut seen: HashSet<(&'static str, String)> = HashSet::new();
        let mut tasks: Vec<FetchTask> = Vec::new();
        for item in parsed.items.iter().filter(|i| i.is_checkable()) {
            let (task_fetcher, cache_key) = match (item.source, &self.jsr) {
                (PackageSource::Jsr, Some(jsr)) => (jsr.clone(), JSR_CACHE_KEY),
                _ => (fetcher.clone(), ecosystem.osv_name()),
            };
            if seen.insert((cache_key, item.name.clone())) {
                tasks.push(FetchTask {
                    name: item.name.clone(),
                    fetcher: task_fetcher,
                    cache_key,
                });
            }
        }

        let fetched = self.fetch_all(tasks).await;
        let mut results: Vec<CheckResult> = parsed
            .items
            .iter()
            .map(|item| evaluate_item(item, &fetched, ecosystem, self.unstable))
            .collect();

        let mut warnings = Vec::new();
        if let Some(osv) = &self.osv
            && let Err(e) = scan_vulnerabilities(osv, ecosystem, &mut results).await
        {
            warnings.push(format!("vulnerability scan skipped: {e}"));
        }

        Ok(ManifestCheck {
            kind,
            ecosystem,
            results,
            warnings,
        })
    }

    /// Run every fetch task concurrently, serving and populating the in-process
    /// versions cache (keyed per registry), and emitting one progress cycle.
    async fn fetch_all(&self, tasks: Vec<FetchTask>) -> FetchedMap {
        let total = tasks.len();
        self.emit(ProgressEvent::Started { total });

        let mut out: FetchedMap = HashMap::new();
        let mut to_fetch: Vec<FetchTask> = Vec::new();
        for task in tasks {
            let key = (task.cache_key.to_string(), task.name.clone());
            if let Some(versions) = self.versions_cache.get(&key).await {
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
                    .insert((cache_key.to_string(), name.clone()), versions.clone())
                    .await;
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

/// Evaluate one parsed item against the fetched version lists, applying the
/// configured pre-release filter before classification.
fn evaluate_item(
    item: &Item,
    fetched: &FetchedMap,
    ecosystem: Ecosystem,
    unstable: UnstableFilter,
) -> CheckResult {
    if !item.is_checkable() {
        let status = match item.source {
            PackageSource::Git => DependencyStatus::Git,
            _ => DependencyStatus::Local,
        };
        return CheckResult::new(item.clone(), status);
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
            let candidates = to_semver_versions(&filtered, ecosystem);
            let constraint = to_semver_constraint(&item.version_constraint, ecosystem);
            let eval = check_version(&constraint, &candidates, item.locked_version.as_deref());
            CheckResult::from_evaluation(item.clone(), eval)
        }
        Some(Err(e)) => CheckResult::new(item.clone(), DependencyStatus::Error(e.clone())),
        None => CheckResult::new(
            item.clone(),
            DependencyStatus::Error("not fetched".to_string()),
        ),
    }
}

/// Translate registry-native version strings into semver for comparison. Only
/// Python (PEP 440) needs conversion; other ecosystems already use semver.
fn to_semver_versions(versions: &[String], ecosystem: Ecosystem) -> Vec<String> {
    if ecosystem == Ecosystem::Python {
        versions
            .iter()
            .filter_map(|v| dependable_core::semver::python::pep440_to_semver(v))
            .collect()
    } else {
        versions.to_vec()
    }
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
        if !result.item.is_checkable() || matches!(result.status, DependencyStatus::Error(_)) {
            continue;
        }
        let current = result
            .item
            .locked_version
            .clone()
            .or_else(|| result.latest_compatible.clone());
        if let Some(version) = current {
            queries.push(OsvQuery {
                ecosystem: ecosystem.osv_name().to_string(),
                name: result.item.name.clone(),
                version,
            });
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
    extra_registries: Vec<(Ecosystem, Arc<dyn RegistryFetcher>)>,
    jsr: Option<Arc<dyn RegistryFetcher>>,
    vulnerabilities: bool,
    include_ghsa: bool,
    osv_url: String,
    concurrency: usize,
    read_lockfiles: bool,
    unstable: UnstableFilter,
    progress: Option<ProgressSink>,
}

impl Default for CheckerBuilder {
    fn default() -> Self {
        Self {
            client: None,
            rust_registry: Ecosystem::Rust.default_registry().to_string(),
            rust_auth: None,
            extra_registries: Vec::new(),
            jsr: None,
            vulnerabilities: true,
            include_ghsa: false,
            osv_url: DEFAULT_OSV_BATCH_URL.to_string(),
            concurrency: DEFAULT_CONCURRENCY,
            read_lockfiles: true,
            unstable: UnstableFilter::default(),
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

    /// Register (or override) the fetcher for an ecosystem. This is the
    /// forward-compatible extension point for npm, PyPI, Go, and others.
    pub fn registry(mut self, ecosystem: Ecosystem, fetcher: Arc<dyn RegistryFetcher>) -> Self {
        self.extra_registries.push((ecosystem, fetcher));
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

        let osv = self.vulnerabilities.then(|| {
            Arc::new(OsvClient::with_url(
                client.clone(),
                self.osv_url,
                self.include_ghsa,
            ))
        });

        Ok(Checker {
            registries,
            jsr: self.jsr,
            osv,
            concurrency: self.concurrency,
            read_lockfiles: self.read_lockfiles,
            unstable: self.unstable,
            versions_cache: versions_cache(),
            progress: self.progress,
        })
    }
}
