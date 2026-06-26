//! Orchestration: discover → parse → fetch → check → render.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use dependable_core::{
    CargoTomlParser, CheckResult, DependencyStatus, Ecosystem, Item, ManifestKind, PackageSource,
    Parser, apply_lockfile, check_version, parse_cargo_lock,
};
use dependable_fetch::{CratesIoFetcher, OsvClient, OsvQuery, RegistryFetcher, build_client};
use futures::stream::{self, StreamExt};
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
    include_ghsa: bool,
    fail_on: FailOn,
    registry: String,
    osv_url: String,
}

fn resolve_check_settings(args: &CheckArgs, cfg: &Config) -> Settings {
    let env_no_vuln = std::env::var_os("DEPENDABLE_NO_VULN").is_some();
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
        include_ghsa: args.include_ghsa || cfg.global.include_ghsa || env_ghsa,
        fail_on,
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    }
}

/// Holds the shared HTTP-backed fetchers and settings for one run.
struct Engine {
    fetcher: CratesIoFetcher,
    osv: OsvClient,
    settings: Settings,
    show_progress: bool,
}

impl Engine {
    fn new(settings: Settings, show_progress: bool) -> anyhow::Result<Self> {
        let client = build_client().context("building HTTP client")?;
        let fetcher =
            CratesIoFetcher::with_registry(client.clone(), settings.registry.clone(), None);
        let osv = OsvClient::with_url(client, settings.osv_url.clone(), settings.include_ghsa);
        Ok(Self {
            fetcher,
            osv,
            settings,
            show_progress,
        })
    }

    async fn check_manifest(&self, path: &Path) -> anyhow::Result<ManifestReport> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut parsed = CargoTomlParser
            .parse(&content)
            .with_context(|| format!("parsing {}", path.display()))?;

        if self.settings.check_lockfile
            && let Some(lock_path) = lockfile_path(path)
            && let Ok(lock_content) = std::fs::read_to_string(&lock_path)
            && let Ok(lock) = parse_cargo_lock(&lock_content)
        {
            apply_lockfile(&mut parsed.items, &lock);
        }

        let mut names: Vec<String> = parsed
            .items
            .iter()
            .filter(|i| i.is_checkable())
            .map(|i| i.name.clone())
            .collect();
        names.sort();
        names.dedup();

        let fetched = self.fetch_all(&names).await;
        let mut results: Vec<CheckResult> = parsed
            .items
            .iter()
            .map(|item| self.evaluate_item(item, &fetched))
            .collect();

        if self.settings.check_vuln {
            self.scan_vulnerabilities(&mut results).await?;
        }

        Ok(ManifestReport {
            path: path.to_path_buf(),
            ecosystem: Ecosystem::Rust,
            results,
        })
    }

    /// Fetch versions for every name concurrently.
    async fn fetch_all(&self, names: &[String]) -> HashMap<String, Result<Vec<String>, String>> {
        let progress = self.progress_bar(names.len() as u64);
        let fetcher = self.fetcher.clone();
        let map = stream::iter(names.iter().cloned())
            .map(|name| {
                let fetcher = fetcher.clone();
                let progress = progress.clone();
                async move {
                    let result = fetcher
                        .fetch_versions(&name)
                        .await
                        .map(|fetched| fetched.versions)
                        .map_err(|e| e.to_string());
                    progress.inc(1);
                    (name, result)
                }
            })
            .buffer_unordered(self.settings.concurrency)
            .collect::<HashMap<_, _>>()
            .await;
        progress.finish_and_clear();
        map
    }

    fn evaluate_item(
        &self,
        item: &Item,
        fetched: &HashMap<String, Result<Vec<String>, String>>,
    ) -> CheckResult {
        if !item.is_checkable() {
            let status = match item.source {
                PackageSource::Git => DependencyStatus::Git,
                _ => DependencyStatus::Local,
            };
            return base_result(item, status);
        }
        match fetched.get(&item.name) {
            Some(Ok(versions)) => {
                let eval = check_version(
                    &item.version_constraint,
                    versions,
                    item.locked_version.as_deref(),
                );
                CheckResult::from_evaluation(item.clone(), eval)
            }
            Some(Err(e)) => base_result(item, DependencyStatus::Error(e.clone())),
            None => base_result(item, DependencyStatus::Error("not fetched".to_string())),
        }
    }

    /// Query OSV for the current version of each checkable dependency and flip
    /// its status to `Vulnerable` when advisories are found.
    async fn scan_vulnerabilities(&self, results: &mut [CheckResult]) -> anyhow::Result<()> {
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
                    ecosystem: Ecosystem::Rust.osv_name().to_string(),
                    name: result.item.name.clone(),
                    version,
                });
                index_for.push(i);
            }
        }
        if queries.is_empty() {
            return Ok(());
        }

        let osv_results = self
            .osv
            .query_batch(&queries)
            .await
            .context("querying OSV")?;
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

    fn progress_bar(&self, len: u64) -> ProgressBar {
        if !self.show_progress || len == 0 {
            return ProgressBar::hidden();
        }
        let bar = ProgressBar::new(len);
        if let Ok(style) = ProgressStyle::with_template("{spinner} fetching {pos}/{len}") {
            bar.set_style(style);
        }
        bar
    }
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
        eprintln!("No Cargo.toml manifests found.");
        return Ok(ExitCode::SUCCESS);
    }

    let fail_on = settings.fail_on;
    let engine = Engine::new(settings, !args.quiet)?;
    let mut reports = Vec::new();
    for manifest in &manifests {
        reports.push(engine.check_manifest(manifest).await?);
    }

    output::render(args.format, &reports, args.quiet)?;
    Ok(exit_code(&reports, fail_on))
}

/// `dependable list`
pub async fn run_list(args: ListArgs) -> anyhow::Result<ExitCode> {
    let manifests = collect_manifests(args.manifest.as_deref(), args.path.as_deref(), args.depth);
    if manifests.is_empty() {
        eprintln!("No Cargo.toml manifests found.");
        return Ok(ExitCode::SUCCESS);
    }
    for (i, manifest) in manifests.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let content = std::fs::read_to_string(manifest)
            .with_context(|| format!("reading {}", manifest.display()))?;
        let parsed = CargoTomlParser
            .parse(&content)
            .with_context(|| format!("parsing {}", manifest.display()))?;
        println!(
            "{} — Rust ({} dependencies)",
            manifest.display(),
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
        include_ghsa: false,
        fail_on: FailOn::None,
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    };
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        settings.depth,
    );
    if manifests.is_empty() {
        eprintln!("No Cargo.toml manifests found.");
        return Ok(ExitCode::SUCCESS);
    }

    let engine = Engine::new(settings, true)?;
    let mut total = 0;
    for manifest in &manifests {
        let report = engine.check_manifest(manifest).await?;
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

fn base_result(item: &Item, status: DependencyStatus) -> CheckResult {
    CheckResult::new(item.clone(), status)
}

fn lockfile_path(manifest: &Path) -> Option<PathBuf> {
    let name = ManifestKind::CargoToml.lockfile_name()?;
    Some(manifest.parent().unwrap_or(Path::new(".")).join(name))
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
