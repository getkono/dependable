//! Orchestration: discover manifests, check each via `dependable-fetch`, render.
//!
//! All dependency-checking logic (parse → fetch → evaluate → OSV scan) lives in
//! [`dependable_fetch::Checker`]. This module owns only CLI concerns: config
//! layering, manifest discovery, progress UX, output rendering, and exit codes.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use dependable_fetch::core::{
    AlternateRegistryDecl, NpmrcConfig, PackageField, ProjectMeta, WorkspaceDecl, apply_lockfile,
    parse, parse_cargo_config, parse_npmrc, parse_project, parse_workspace,
};
use dependable_fetch::{
    CheckError, Checker, CratesIoFetcher, DependencyKind, DependencyStatus, Ecosystem,
    GoProxyFetcher, GraphSource, HexFetcher, Item, JsrFetcher, ManifestKind, NpmFetcher,
    NuGetFetcher, PackageSource, PackagistFetcher, ParseError, ProgressEvent, PubDevFetcher,
    PyPiFetcher, RegistryFetcher, ScopedRegistry, TreeOptions, UnstableFilter,
    WorkspaceGraphOptions, build_client, build_workspace_graph,
};
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::{CheckArgs, FailOn, FixArgs, ListArgs, TreeArgs};
use crate::config::{Config, load_config};
use crate::fix;
use crate::output::list::ProjectReport;
use crate::output::{self, ManifestReport};

/// Effective settings after layering CLI flags over env vars over config.
struct Settings {
    concurrency: usize,
    depth: usize,
    check_lockfile: bool,
    check_vuln: bool,
    cache: bool,
    include_ghsa: bool,
    fail_on: FailOn,
    unstable: UnstableFilter,
    registry: String,
    osv_url: String,
}

fn resolve_check_settings(args: &CheckArgs, cfg: &Config) -> Settings {
    let env_no_vuln = std::env::var_os("DEPENDABLE_NO_VULN").is_some();
    let env_no_cache = std::env::var_os("DEPENDABLE_NO_CACHE").is_some();
    let env_ghsa = std::env::var_os("DEPENDABLE_INCLUDE_GHSA").is_some();
    let env_concurrency = std::env::var("DEPENDABLE_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());
    let env_fail_on = std::env::var("DEPENDABLE_FAIL_ON")
        .ok()
        .and_then(|s| FailOn::from_env(&s));

    let fail_on = if args.fail_on != FailOn::None {
        args.fail_on
    } else {
        env_fail_on.unwrap_or(cfg.global.fail_on)
    };

    Settings {
        concurrency: args
            .concurrency
            .or(env_concurrency)
            .unwrap_or(cfg.global.concurrency)
            .max(1),
        depth: args.depth,
        check_lockfile: !args.no_lock_file && cfg.global.lock_file,
        check_vuln: cfg.vulnerability.enabled && !args.no_vuln && !env_no_vuln,
        cache: !args.no_cache && !env_no_cache,
        include_ghsa: args.include_ghsa || cfg.global.include_ghsa || env_ghsa,
        fail_on,
        unstable: args
            .unstable
            .map_or_else(|| cfg.global.unstable.into(), Into::into),
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    }
}

/// Adapts the library [`Checker`] to the CLI's per-manifest report shape.
struct Engine {
    checker: Checker,
}

impl Engine {
    fn new(settings: &Settings, cfg: &Config, show_progress: bool) -> anyhow::Result<Self> {
        // One HTTP client, shared (connection pool included) by every fetcher.
        let client = build_client().context("building HTTP client")?;
        let mut builder = Checker::builder()
            .http_client(client.clone())
            .rust_registry(settings.registry.clone(), None)
            .vulnerabilities(settings.check_vuln)
            .include_ghsa(settings.include_ghsa)
            .osv_url(settings.osv_url.clone())
            .concurrency(settings.concurrency)
            .read_lockfiles(settings.check_lockfile)
            .unstable(settings.unstable)
            .disk_cache(settings.cache);
        // Wire alternate Cargo registries (private index + auth token) resolved
        // from `$CARGO_HOME`, so a `registry = "..."` dependency is fetched from
        // and authenticated against its own index. Registries without an index URL
        // are skipped.
        for reg in cargo_alt_registries() {
            if let Some(index_url) = reg.index_url {
                builder = builder.rust_alt_registry(reg.name, index_url, reg.auth_token);
            }
        }
        // Register non-Rust ecosystem fetchers when enabled in config.
        if cfg.go.enabled {
            builder = builder.registry(
                Ecosystem::Go,
                Arc::new(GoProxyFetcher::with_proxy(
                    client.clone(),
                    cfg.go.registry.clone(),
                )),
            );
        }
        if cfg.npm.enabled {
            // Layer `.npmrc` on top of config: its `registry=` (if any) overrides
            // the configured default, and its `_authToken`s become bearer auth for
            // the default and per-scope private registries.
            let npmrc = npmrc_config();
            let registry = npmrc
                .default_registry
                .clone()
                .unwrap_or_else(|| cfg.npm.registry.clone());
            let default_token = npmrc.token_for(&registry).map(str::to_owned);
            let scopes = npmrc
                .scope_registries
                .iter()
                .map(|(scope, url)| {
                    let token = npmrc.token_for(url).map(str::to_owned);
                    (
                        scope.clone(),
                        ScopedRegistry {
                            registry: url.clone(),
                            token,
                        },
                    )
                })
                .collect();
            builder = builder
                .registry(
                    Ecosystem::Npm,
                    Arc::new(
                        NpmFetcher::with_registry(client.clone(), registry)
                            .with_auth(default_token, scopes),
                    ),
                )
                .jsr_registry(Arc::new(JsrFetcher::with_registry(
                    client.clone(),
                    cfg.npm.jsr_registry.clone(),
                )));
        }
        if cfg.python.enabled {
            builder = builder.registry(
                Ecosystem::Python,
                Arc::new(PyPiFetcher::with_registry(
                    client.clone(),
                    cfg.python.registry.clone(),
                )),
            );
        }
        if cfg.php.enabled {
            builder = builder.registry(
                Ecosystem::Php,
                Arc::new(PackagistFetcher::with_registry(
                    client.clone(),
                    cfg.php.registry.clone(),
                )),
            );
        }
        if cfg.dart.enabled {
            builder = builder.registry(
                Ecosystem::Dart,
                Arc::new(PubDevFetcher::with_registry(
                    client.clone(),
                    cfg.dart.registry.clone(),
                )),
            );
        }
        if cfg.csharp.enabled {
            builder = builder.registry(
                Ecosystem::CSharp,
                Arc::new(NuGetFetcher::with_registry(
                    client.clone(),
                    cfg.csharp.registry.clone(),
                )),
            );
        }
        if cfg.elixir.enabled {
            builder = builder.registry(
                Ecosystem::Elixir,
                Arc::new(HexFetcher::with_registry(
                    client.clone(),
                    cfg.elixir.registry.clone(),
                )),
            );
        }
        if show_progress {
            builder = builder.on_progress(progress_sink());
        }
        let checker = builder.build().context("building checker")?;
        Ok(Self { checker })
    }

    /// Check one manifest, returning `None` (with a skip note) when its ecosystem
    /// has no registered checker or no parser yet — so a polyglot repo with a
    /// not-yet-supported manifest does not abort the whole run.
    async fn check_manifest(&self, path: &Path) -> anyhow::Result<Option<ManifestReport>> {
        match self.checker.check_path(path).await {
            Ok(check) => {
                for warning in &check.warnings {
                    eprintln!("warning: {} — {warning}", path.display());
                }
                Ok(Some(ManifestReport {
                    path: path.to_path_buf(),
                    ecosystem: check.ecosystem,
                    results: check.results,
                }))
            }
            Err(CheckError::UnsupportedEcosystem(eco)) => {
                eprintln!(
                    "skipping {}: {} is not enabled or not yet supported",
                    path.display(),
                    eco.display_name()
                );
                Ok(None)
            }
            Err(CheckError::Parse(ParseError::Unsupported(kind))) => {
                eprintln!("skipping {}: no parser for {kind:?}", path.display());
                Ok(None)
            }
            Err(CheckError::UnknownManifest(p)) => {
                eprintln!("skipping {}: unrecognized manifest", p.display());
                Ok(None)
            }
            Err(e) => Err(anyhow::Error::new(e).context(format!("checking {}", path.display()))),
        }
    }
}

/// A progress sink that drives a per-manifest indicatif bar. Each manifest's
/// check emits one `Started → Advanced* → Finished` cycle, so the shared bar is
/// (re)created on `Started` and cleared on `Finished`.
fn progress_sink() -> Arc<dyn Fn(ProgressEvent) + Send + Sync> {
    let bar: Arc<Mutex<Option<ProgressBar>>> = Arc::new(Mutex::new(None));
    Arc::new(move |event| {
        let Ok(mut slot) = bar.lock() else { return };
        match event {
            ProgressEvent::Started { total } => {
                if total == 0 {
                    return;
                }
                let pb = ProgressBar::new(total as u64);
                if let Ok(style) = ProgressStyle::with_template("{spinner} fetching {pos}/{len}") {
                    pb.set_style(style);
                }
                *slot = Some(pb);
            }
            ProgressEvent::Advanced { completed, .. } => {
                if let Some(pb) = slot.as_ref() {
                    pb.set_position(completed as u64);
                }
            }
            ProgressEvent::Finished => {
                if let Some(pb) = slot.take() {
                    pb.finish_and_clear();
                }
            }
            _ => {}
        }
    })
}

/// `dependable check`
pub async fn run_check(args: CheckArgs) -> anyhow::Result<ExitCode> {
    let cfg = load_config(&args.config);
    let settings = resolve_check_settings(&args, &cfg);
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        settings.depth,
    );
    if manifests.is_empty() {
        eprintln!("No supported manifests found.");
        return Ok(ExitCode::SUCCESS);
    }

    let fail_on = settings.fail_on;
    let engine = Engine::new(&settings, &cfg, !args.quiet)?;
    let mut reports = Vec::new();
    for manifest in &manifests {
        if let Some(report) = engine.check_manifest(manifest).await? {
            reports.push(report);
        }
    }

    output::render(args.format, &reports, args.quiet)?;
    Ok(exit_code(&reports, fail_on))
}

/// `dependable list`
///
/// Offline by default: every manifest is parsed, its declared identity read, and any
/// sibling lockfile applied. Only `--features` touches the network.
pub async fn run_list(args: ListArgs) -> anyhow::Result<ExitCode> {
    let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let manifests = collect_manifests(args.manifest.as_deref(), args.path.as_deref(), args.depth);
    if manifests.is_empty() {
        eprintln!("No supported manifests found.");
        return Ok(ExitCode::SUCCESS);
    }
    // `--features` fetches crates.io feature flags, so `list` only touches the
    // network when it is set. Feature data is crates.io-only (Rust manifests).
    let feature_fetcher = if args.features {
        Some(CratesIoFetcher::new(
            build_client().context("building HTTP client")?,
        ))
    } else {
        None
    };

    let mut reports = Vec::new();
    for manifest in &manifests {
        let Some(kind) = ManifestKind::detect(manifest) else {
            continue;
        };
        let content = std::fs::read_to_string(manifest)
            .with_context(|| format!("reading {}", manifest.display()))?;
        let mut parsed = match parse(kind, &content) {
            Ok(parsed) => parsed,
            Err(ParseError::Unsupported(_)) => {
                eprintln!(
                    "skipping {}: {} is not yet supported",
                    manifest.display(),
                    kind.ecosystem().display_name()
                );
                continue;
            }
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("parsing {}", manifest.display()))
                );
            }
        };

        let lockfile = (!args.no_lock_file)
            .then(|| apply_nearest_lockfile(manifest, kind, &root, &mut parsed.items))
            .flatten();
        // A member writing `dep.workspace = true` states no version of its own; the
        // constraint lives in the workspace root.
        let inherited = inherit_workspace_constraints(manifest, kind, &mut parsed.items);
        let meta = parse_project(kind, &content);
        let (version, version_inherited) = resolve_version(manifest, kind, &meta);

        let mut features = BTreeMap::new();
        if let Some(fetcher) = &feature_fetcher {
            for item in &parsed.items {
                if kind.ecosystem() == Ecosystem::Rust
                    && item.is_checkable()
                    && let Ok(fetched) = fetcher.fetch_versions(&item.name).await
                    && !fetched.features.is_empty()
                {
                    features.insert(item.name.clone(), fetched.features);
                }
            }
        }

        reports.push(ProjectReport {
            relative: relative_to(&root, manifest),
            ecosystem: kind.ecosystem(),
            // A `*.csproj` is named by its file, which the IO-free reader cannot see.
            name: meta.name.clone().or_else(|| csproj_name(manifest, kind)),
            version,
            version_inherited,
            role: meta.role,
            lockfile,
            inherited,
            items: parsed.items,
            features,
        });
    }

    output::list::render(args.format, &reports, &root)?;
    Ok(ExitCode::SUCCESS)
}

/// Apply the nearest lockfile at or above the manifest, returning its path relative to
/// `root` when one was read.
///
/// A workspace keeps one lockfile at its root, so a member's locked versions are only
/// found by walking up. The walk stops at the repository root (the first ancestor
/// holding a `.git`) so a stray lockfile outside the project is never read, and the
/// path that was used is reported rather than assumed.
fn apply_nearest_lockfile(
    manifest: &Path,
    kind: ManifestKind,
    root: &Path,
    items: &mut [Item],
) -> Option<PathBuf> {
    let (path, resolved) = dependable_fetch::find_lockfile(manifest, kind)?;
    apply_lockfile(items, &resolved);
    Some(relative_to(root, &path))
}

/// Fill in the constraints a member inherits from `[workspace.dependencies]`, returning
/// the names that were resolved that way.
///
/// A `dep.workspace = true` entry parses as a local dependency with no constraint —
/// correct for version checking, which must skip it, but an inventory that reported it
/// that way would hide both the version in force and the fact that the crate comes from
/// a registry. The workspace root's own declaration supplies all of it.
fn inherit_workspace_constraints(
    manifest: &Path,
    kind: ManifestKind,
    items: &mut [Item],
) -> Vec<String> {
    if kind != ManifestKind::CargoToml {
        return Vec::new();
    }
    let Some(declared) = workspace_declarations(manifest) else {
        return Vec::new();
    };
    let mut inherited = Vec::new();
    for item in items {
        // Only an entry with nothing of its own to say can be inheriting.
        if !item.version_constraint.is_empty() || item.source != PackageSource::Local {
            continue;
        }
        let Some(source) = declared.get(&item.name) else {
            continue;
        };
        item.version_constraint
            .clone_from(&source.version_constraint);
        item.source = source.source;
        item.registry.clone_from(&source.registry);
        inherited.push(item.name.clone());
    }
    inherited
}

/// The `[workspace.dependencies]` entries of the nearest ancestor workspace root, keyed
/// by package name.
fn workspace_declarations(manifest: &Path) -> Option<HashMap<String, Item>> {
    let (_, content) = nearest_workspace_root(manifest)?;
    let parsed = parse(ManifestKind::CargoToml, &content).ok()?;
    Some(
        parsed
            .items
            .into_iter()
            .filter(|item| item.kind == DependencyKind::Workspace)
            .map(|item| (item.name.clone(), item))
            .collect(),
    )
}

/// The manifest's version, resolving a Cargo `version.workspace = true` against the
/// nearest ancestor `[workspace.package]` table. Returns the version and whether it was
/// inherited.
fn resolve_version(
    manifest: &Path,
    kind: ManifestKind,
    meta: &ProjectMeta,
) -> (Option<String>, bool) {
    match &meta.version {
        None => (None, false),
        Some(PackageField::Literal(version)) => (Some(version.clone()), false),
        Some(PackageField::Workspace) => {
            let inherited = workspace_package_defaults(manifest, kind)
                .and_then(|defaults| defaults.get("version").cloned());
            (inherited, true)
        }
        // A future inheritance form resolves to nothing rather than a wrong version.
        _ => (None, true),
    }
}

/// `[workspace.package]` from the nearest ancestor `Cargo.toml` declaring a workspace.
fn workspace_package_defaults(
    manifest: &Path,
    kind: ManifestKind,
) -> Option<BTreeMap<String, String>> {
    if kind != ManifestKind::CargoToml {
        return None;
    }
    let (workspace, _) = nearest_workspace_root(manifest)?;
    Some(workspace.package_defaults)
}

/// The nearest ancestor `Cargo.toml` declaring a `[workspace]`, with its content.
///
/// The manifest itself is excluded: a member inherits from a root above it, and a root
/// that is also a package declares its own values literally. The walk stops at the
/// repository root so inheritance never resolves against a manifest outside the project.
fn nearest_workspace_root(manifest: &Path) -> Option<(WorkspaceDecl, String)> {
    let mut dir = manifest.parent()?;
    loop {
        let candidate = dir.join("Cargo.toml");
        if !same_file(&candidate, manifest)
            && let Ok(content) = std::fs::read_to_string(&candidate)
            && let Some(workspace) = parse_workspace(&content)
        {
            return Some((workspace, content));
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// Whether two paths name the same file. Compared after canonicalization, since a
/// discovered manifest (`./Cargo.toml`) and a candidate built while walking up
/// (`Cargo.toml`) can spell one file two ways.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// A `*.csproj`'s project name is its file stem; `Directory.Packages.props` is a central
/// version file and keeps no name.
fn csproj_name(manifest: &Path, kind: ManifestKind) -> Option<String> {
    if kind != ManifestKind::Csproj {
        return None;
    }
    let name = manifest.file_name()?.to_str()?;
    if name == "Directory.Packages.props" {
        return None;
    }
    Some(manifest.file_stem()?.to_string_lossy().into_owned())
}

/// `manifest` relative to the scanned `root`, falling back to the path as given.
fn relative_to(root: &Path, manifest: &Path) -> PathBuf {
    manifest
        .strip_prefix(root)
        .map_or_else(|_| manifest.to_path_buf(), Path::to_path_buf)
}

/// `dependable tree`
///
/// Offline: builds the workspace dependency graph from `Cargo.lock` (or a
/// shallow fallback from manifests) and renders it. No network or async.
pub fn run_tree(args: TreeArgs) -> anyhow::Result<ExitCode> {
    let root = args.path.as_deref().unwrap_or_else(|| Path::new("."));
    let mut opts = WorkspaceGraphOptions::default();
    opts.package = args.package.clone();

    let built = build_workspace_graph(root, &opts).context("building the dependency graph")?;
    if built.source == GraphSource::Manifests {
        eprintln!(
            "warning: no Cargo.lock found — showing a shallow tree of direct \
             dependencies only. Run `cargo generate-lockfile` for the full \
             resolved graph."
        );
    }

    let graph = if args.invert {
        built.graph.inverted()
    } else {
        built.graph
    };
    let tree_opts = TreeOptions {
        max_depth: args.depth,
        dedupe: !args.no_dedupe,
    };
    output::tree::render(&graph, args.format, &tree_opts)?;
    Ok(ExitCode::SUCCESS)
}

/// `dependable fix`
pub async fn run_fix(args: FixArgs) -> anyhow::Result<ExitCode> {
    let cfg = load_config(&args.config);
    let settings = Settings {
        concurrency: args.concurrency.unwrap_or(cfg.global.concurrency).max(1),
        depth: args.depth,
        check_lockfile: cfg.global.lock_file,
        check_vuln: false,
        cache: true,
        include_ghsa: false,
        fail_on: FailOn::None,
        unstable: cfg.global.unstable.into(),
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    };
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        settings.depth,
    );
    if manifests.is_empty() {
        eprintln!("No supported manifests found.");
        return Ok(ExitCode::SUCCESS);
    }

    let engine = Engine::new(&settings, &cfg, true)?;
    let mut total = 0;
    for manifest in &manifests {
        let Some(report) = engine.check_manifest(manifest).await? else {
            continue;
        };
        let records = fix::apply_fixes(manifest, &report.results, args.all, args.dry_run)?;
        if records.is_empty() {
            continue;
        }
        println!(
            "{}{}",
            manifest.display(),
            if args.dry_run { " (dry run)" } else { "" }
        );
        for record in &records {
            println!("  {} {} → {}", record.name, record.from, record.to);
            total += 1;
        }
    }
    if total == 0 {
        println!("Everything is already up to date.");
    } else if !args.dry_run {
        println!(
            "\nUpdated {total} dependenc{}.",
            if total == 1 { "y" } else { "ies" }
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn collect_manifests(manifest: Option<&Path>, path: Option<&Path>, depth: usize) -> Vec<PathBuf> {
    if let Some(manifest) = manifest {
        return vec![manifest.to_path_buf()];
    }
    let root = path.map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    dependable_fetch::find_manifests(&root, depth)
}

/// Cargo's home directory: `$CARGO_HOME`, else `~/.cargo`. Returns `None` when
/// unresolvable, which disables alternate-registry auth gracefully.
fn cargo_home() -> Option<PathBuf> {
    resolve_cargo_home(env_dir("CARGO_HOME"), home_dir())
}

/// Cargo's home from the resolved directories: an explicit `$CARGO_HOME`, else
/// `~/.cargo`. Pure (no environment access) so the fallback is testable everywhere.
fn resolve_cargo_home(cargo_home: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    cargo_home.or_else(|| home.map(|h| h.join(".cargo")))
}

/// A non-empty environment variable as a [`PathBuf`].
fn env_dir(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The user's home directory, cross-platform: `$HOME` (all platforms), then, on
/// Windows only, `%USERPROFILE%`. `None` when unresolvable.
fn home_dir() -> Option<PathBuf> {
    if let Some(home) = env_dir("HOME") {
        return Some(home);
    }
    #[cfg(windows)]
    if let Some(profile) = env_dir("USERPROFILE") {
        return Some(profile);
    }
    None
}

/// Resolve alternate Cargo registries (alias → index URL + token) from
/// `$CARGO_HOME/config.toml` + `credentials.toml` (falling back to the extension-
/// less legacy names). Best-effort: any missing or unparseable file simply yields
/// fewer registries, so a check never fails because of Cargo config.
fn cargo_alt_registries() -> Vec<AlternateRegistryDecl> {
    let Some(home) = cargo_home() else {
        return Vec::new();
    };
    let read = |names: [&str; 2]| {
        names
            .iter()
            .find_map(|name| std::fs::read_to_string(home.join(name)).ok())
    };
    match read(["config.toml", "config"]) {
        Some(config) => parse_cargo_config(
            &config,
            read(["credentials.toml", "credentials"]).as_deref(),
        ),
        None => Vec::new(),
    }
}

/// Load and merge npm's `.npmrc` auth config: the user `~/.npmrc` overlaid by the
/// project `./.npmrc` (project wins). `${VAR}` references expand from the
/// environment. Best-effort: missing/unreadable files contribute nothing.
fn npmrc_config() -> NpmrcConfig {
    let load = |content: String| parse_npmrc(&expand_env(&content));
    let user = home_dir()
        .and_then(|home| std::fs::read_to_string(home.join(".npmrc")).ok())
        .map(load)
        .unwrap_or_default();
    let project = std::fs::read_to_string(".npmrc")
        .ok()
        .map(load)
        .unwrap_or_default();
    user.merge(project)
}

/// Expand `${VAR}` references in `.npmrc` content from the environment. An unset
/// variable expands to empty (npm's behavior), so a stale placeholder is never
/// sent as a token; an unterminated `${` is emitted verbatim.
fn expand_env(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                if let Ok(value) = std::env::var(&after[..end]) {
                    out.push_str(&value);
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str("${");
                out.push_str(after);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

fn exit_code(reports: &[ManifestReport], fail_on: FailOn) -> ExitCode {
    let triggered = reports
        .iter()
        .flat_map(|report| &report.results)
        .any(|result| match fail_on {
            FailOn::None => false,
            FailOn::Vulnerable => matches!(result.status, DependencyStatus::Vulnerable),
            FailOn::Outdated => matches!(
                result.status,
                DependencyStatus::Outdated
                    | DependencyStatus::UpdateAvailable
                    | DependencyStatus::Vulnerable
            ),
            FailOn::Any => !matches!(
                result.status,
                DependencyStatus::UpToDate | DependencyStatus::Local | DependencyStatus::Git
            ),
        });
    if triggered {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_home_prefers_explicit_env_then_dot_cargo() {
        // An explicit `$CARGO_HOME` is used verbatim.
        assert_eq!(
            resolve_cargo_home(Some("/opt/cargo".into()), Some("/home/u".into())),
            Some(PathBuf::from("/opt/cargo"))
        );
        // Otherwise fall back to `~/.cargo` (built with the platform separator).
        assert_eq!(
            resolve_cargo_home(None, Some("/home/u".into())),
            Some(PathBuf::from("/home/u").join(".cargo"))
        );
        // No home at all -> unresolvable, so alt-registry auth is simply disabled.
        assert_eq!(resolve_cargo_home(None, None), None);
    }

    #[test]
    fn expand_env_substitutes_blanks_unset_and_passes_through() {
        // No placeholders -> verbatim.
        assert_eq!(expand_env("registry=https://x/"), "registry=https://x/");
        // An unset variable expands to empty (never sends a stale placeholder).
        assert_eq!(
            expand_env("//x/:_authToken=${DEPENDABLE_NPMRC_UNSET_XYZ}"),
            "//x/:_authToken="
        );
        // An unterminated `${` is emitted verbatim.
        assert_eq!(expand_env("a=${OPEN"), "a=${OPEN");
    }
}
