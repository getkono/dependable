//! Orchestration: discover manifests, check each via `dependable-fetch`, render.
//!
//! All dependency-checking logic (parse → fetch → evaluate → OSV scan) lives in
//! [`dependable_fetch::Checker`]. This module owns only CLI concerns: config
//! layering, manifest discovery, progress UX, output rendering, and exit codes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use dependable_fetch::core::{CargoTomlParser, Parser};
use dependable_fetch::{Checker, DependencyStatus, PackageSource, ProgressEvent};
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

/// Adapts the library [`Checker`] to the CLI's per-manifest report shape.
struct Engine {
    checker: Checker,
}

impl Engine {
    fn new(settings: &Settings, show_progress: bool) -> anyhow::Result<Self> {
        let mut builder = Checker::builder()
            .rust_registry(settings.registry.clone(), None)
            .vulnerabilities(settings.check_vuln)
            .include_ghsa(settings.include_ghsa)
            .osv_url(settings.osv_url.clone())
            .concurrency(settings.concurrency)
            .read_lockfiles(settings.check_lockfile);
        if show_progress {
            builder = builder.on_progress(progress_sink());
        }
        let checker = builder.build().context("building checker")?;
        Ok(Self { checker })
    }

    async fn check_manifest(&self, path: &Path) -> anyhow::Result<ManifestReport> {
        let check = self
            .checker
            .check_path(path)
            .await
            .with_context(|| format!("checking {}", path.display()))?;
        for warning in &check.warnings {
            eprintln!("warning: {} — {warning}", path.display());
        }
        Ok(ManifestReport {
            path: path.to_path_buf(),
            ecosystem: check.ecosystem,
            results: check.results,
        })
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
        eprintln!("No Cargo.toml manifests found.");
        return Ok(ExitCode::SUCCESS);
    }

    let fail_on = settings.fail_on;
    let engine = Engine::new(&settings, !args.quiet)?;
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

    let engine = Engine::new(&settings, true)?;
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
