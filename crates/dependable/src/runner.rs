//! Orchestration: discover manifests, check each via `dependable-fetch`, render.
//!
//! All dependency-checking logic (parse → fetch → evaluate → OSV scan) lives in
//! [`dependable_fetch::Checker`]. This module owns only CLI concerns: config
//! layering, manifest discovery, progress UX, output rendering, and exit codes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use dependable_fetch::core::parse;
use dependable_fetch::{
    CheckError, Checker, CratesIoFetcher, DependencyStatus, Ecosystem, GoProxyFetcher, HexFetcher,
    JsrFetcher, ManifestKind, NpmFetcher, NuGetFetcher, PackageSource, PackagistFetcher,
    ParseError, ProgressEvent, PubDevFetcher, PyPiFetcher, RegistryFetcher, UnstableFilter,
    build_client,
};
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::{CheckArgs, FailOn, FixArgs, ListArgs};
use crate::config::{Config, load_config};
use crate::output::{self, ManifestReport};
use crate::{discover, fix};

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
            builder = builder
                .registry(
                    Ecosystem::Npm,
                    Arc::new(NpmFetcher::with_registry(
                        client.clone(),
                        cfg.npm.registry.clone(),
                    )),
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
pub async fn run_list(args: ListArgs) -> anyhow::Result<ExitCode> {
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

    let mut printed = 0;
    for manifest in &manifests {
        let Some(kind) = ManifestKind::detect(manifest) else {
            continue;
        };
        let content = std::fs::read_to_string(manifest)
            .with_context(|| format!("reading {}", manifest.display()))?;
        let parsed = match parse(kind, &content) {
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
        if printed > 0 {
            println!();
        }
        printed += 1;
        println!(
            "{} — {} ({} dependencies)",
            manifest.display(),
            kind.ecosystem().display_name(),
            parsed.items.len()
        );
        for item in &parsed.items {
            let constraint = if item.version_constraint.is_empty() {
                "—"
            } else {
                &item.version_constraint
            };
            let note = match item.source {
                PackageSource::Local => " (local)",
                PackageSource::Git => " (git)",
                PackageSource::Jsr => " (jsr)",
                PackageSource::Registry => "",
                _ => "",
            };
            println!("  {} {}{}", item.name, constraint, note);

            // Under `--features`, show the crate's available feature flags. Only
            // crates.io exposes them, so this is limited to checkable Rust deps.
            if let Some(fetcher) = &feature_fetcher
                && kind.ecosystem() == Ecosystem::Rust
                && item.is_checkable()
                && let Ok(fetched) = fetcher.fetch_versions(&item.name).await
                && !fetched.features.is_empty()
            {
                println!("      features: {}", fetched.features.join(", "));
            }
        }
    }
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
    discover::find_manifests(&root, depth)
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
