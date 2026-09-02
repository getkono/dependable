//! Orchestration: discover manifests, check each via `dependable-fetch`, render.
//!
//! All dependency-checking logic (parse → fetch → evaluate → OSV scan) lives in
//! [`dependable_fetch::Checker`]. This module owns only CLI concerns: config
//! layering, manifest discovery, progress UX, output rendering, and exit codes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use dependable_fetch::core::{
    AlternateRegistryDecl, NpmrcConfig, PackageField, ProjectMeta, apply_lockfile, parse,
    parse_cargo_config, parse_npmrc, parse_project, parse_workspace, resolve_workspace_inheritance,
};
use dependable_fetch::{
    CheckError, Checker, DependencyStatus, Ecosystem, ErrorOrigin, GoProxyFetcher, GraphSource,
    HexFetcher, Item, JsrFetcher, ManifestKind, MavenCentralFetcher, NpmFetcher, NuGetFetcher,
    PackageSource, PackagistFetcher, ParseError, ProgressEvent, PubDevFetcher, PyPiFetcher,
    ScopedRegistry, TreeOptions, UnstableFilter, WorkspaceGraphOptions, build_client,
    build_workspace_graph, nearest_workspace_root, workspace_source,
};
use dependable_tui::TuiOptions;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::{CheckArgs, EcosystemArg, FailOn, FixArgs, ListArgs, TreeArgs, TuiArgs};
use crate::config::{Config, load_config};
#[cfg(feature = "report")]
use crate::config::{PolicySource, load_policy};
use crate::fix;
use crate::output::list::ProjectReport;
use crate::output::{self, ManifestReport, ScanIntegrity};

/// Effective settings after layering CLI flags over env vars over config.
struct Settings {
    concurrency: usize,
    depth: usize,
    check_lockfile: bool,
    check_vuln: bool,
    /// Whether to collect each dependency's registry-declared license. Only
    /// `check` sets it, and only when `[policy] allowed_licenses` needs it.
    licenses: bool,
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

    // Documented precedence, honoured for every value: CLI, then env, then config.
    // The old test `args.fail_on != FailOn::None` could not tell an explicit
    // `--fail-on none` from clap's default, so a config `fail_on` could not be turned
    // off from the command line at all.
    let fail_on = args.fail_on.or(env_fail_on).unwrap_or(cfg.global.fail_on);

    Settings {
        concurrency: args
            .concurrency
            .or(env_concurrency)
            .unwrap_or(cfg.global.concurrency)
            .max(1),
        depth: args.depth,
        check_lockfile: !args.no_lock_file && cfg.global.lock_file,
        check_vuln: cfg.vulnerability.enabled && !args.no_vuln && !env_no_vuln,
        licenses: policy_requires_licenses(cfg),
        cache: !args.no_cache && !env_no_cache,
        // `--include-ghsa` is a flag, so absence is indistinguishable from `false` and
        // it can only ever widen the scan. OR-ing is therefore the whole contract: any
        // layer asking for GHSA gets it, and no layer can silently take it away.
        include_ghsa: args.include_ghsa || cfg.global.include_ghsa || env_ghsa,
        fail_on,
        unstable: args
            .unstable
            .map_or_else(|| cfg.global.unstable.into(), Into::into),
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    }
}

/// Whether the config's `[policy]` block needs license data collected.
///
/// Always false in a build without the `report` feature, where the policy types
/// do not exist at all.
fn policy_requires_licenses(cfg: &Config) -> bool {
    #[cfg(feature = "report")]
    {
        cfg.policy.requires_licenses()
    }
    #[cfg(not(feature = "report"))]
    {
        let _ = cfg;
        false
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
            // Enrichment rides on the vulnerability scan: it costs one extra OSV
            // lookup per distinct vulnerable package version (a clean run pays
            // nothing) and is what gives the CVSS policy gate a score to compare.
            .advisory_details(settings.check_vuln)
            // License collection costs one metadata request per dependency, so
            // it rides on a `[policy] allowed_licenses` that will consume it.
            .licenses(settings.licenses)
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
        if cfg.jvm.enabled {
            builder = builder.registry(
                Ecosystem::Jvm,
                Arc::new(MavenCentralFetcher::with_registry(
                    client.clone(),
                    cfg.jvm.registry.clone(),
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
        report_lockfile_notices(path);
        match self.checker.check_path(path).await {
            Ok(check) => {
                for warning in &check.warnings {
                    eprintln!("warning: {} — {warning}", path.display());
                }
                // Split by provenance, not by status: a 404 is the registry answering,
                // and anything else that produced an `Error` is this run failing to
                // evaluate the dependency. Only the first is exempt from the gate.
                let count = |origin| {
                    check
                        .results
                        .iter()
                        .filter(|r| r.error_origin == origin)
                        .count()
                };
                let integrity = ScanIntegrity {
                    vulnerability_scan_failed: check.vulnerability_scan_failed,
                    registry_unreachable: check.registry_unreachable,
                    unresolved: count(ErrorOrigin::NotFound),
                    unevaluated: count(ErrorOrigin::Local),
                };
                Ok(Some(ManifestReport {
                    path: path.to_path_buf(),
                    ecosystem: check.ecosystem,
                    results: check.results,
                    workspace_root: check.workspace_root,
                    integrity,
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

/// Warn about lockfiles that are present beside `manifest` but cannot be used.
///
/// Without this a `bun.lockb` is silently skipped and every dependency is
/// reported unlocked, with nothing to tell the user that a lockfile they can
/// migrate is the reason.
fn report_lockfile_notices(manifest: &Path) {
    let Some(kind) = ManifestKind::detect(manifest) else {
        return;
    };
    for notice in dependable_fetch::lockfile_notices(manifest, kind) {
        eprintln!("warning: {notice}");
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
    let cfg =
        load_config(&args.config).with_context(|| format!("reading {}", args.config.display()))?;
    let settings = resolve_check_settings(&args, &cfg);
    // Both policy steps run before discovery, so a misconfigured gate costs a
    // parse rather than a full network check.
    #[cfg(feature = "report")]
    let policy = {
        let policy = resolve_policy(&args.config)?;
        if let Some(policy) = &policy {
            check_policy_is_enforceable(policy, settings.check_vuln)?;
        }
        policy
    };
    #[cfg(not(feature = "report"))]
    warn_policy_ignored(&args.config);

    let ecosystems = requested_ecosystems(&args.ecosystem);
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        settings.depth,
        &args.manifest_glob,
        &ecosystems,
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        report_no_manifests(&ecosystems);
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
    // Before the policy gate, so annotations are printed whether or not policy
    // short-circuits the run. `emit` returns `()` and never `Result`, so no
    // GitHub-integration failure can reach `main`'s error arm and turn a clean
    // run into exit 2.
    output::github::emit(&reports, args.annotations);

    // `[policy]` composes with `--fail-on` rather than replacing it: they gate
    // different things (a rules gate over scores, names, and versions, versus a
    // freshness gate over statuses), both are opt-in, and both already exit 1.
    // OR-ing them is the only composition that cannot downgrade a failure the
    // user explicitly asked for.
    #[cfg(feature = "report")]
    if let Some(policy) = &policy {
        // The static check above proved the gate *could* be enforced; this one proves it
        // *was*. A CVSS rule reads advisory lists, and a scan that never ran leaves those
        // empty — indistinguishable from a project with no advisories, so the gate would
        // pass vacuously on exactly the run that could not check it.
        if policy.requires_cvss()
            && reports
                .iter()
                .any(|r| r.integrity.vulnerability_scan_failed)
        {
            eprintln!(
                "error: `[policy]` gates on advisory severity, but the vulnerability scan did not complete"
            );
            eprintln!("       refusing to pass a policy that was never evaluated");
            return Ok(ExitCode::from(2));
        }
        let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
        let outcome = dependable_report::policy::evaluate(&build_report(root, &reports), policy);
        report_policy(&outcome);
        if outcome.has_violations() {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(exit_code(&reports, fail_on, args.quiet))
}

/// Assemble the neutral report model the policy engine consumes from the CLI's
/// per-manifest reports.
#[cfg(feature = "report")]
fn build_report(root: PathBuf, reports: &[ManifestReport]) -> dependable_report::Report {
    let mut report = dependable_report::Report::new(root);
    for manifest in reports {
        report.push(dependable_report::ManifestResults::new(
            manifest.path.clone(),
            manifest.ecosystem,
            manifest.results.clone(),
        ));
    }
    report
}

/// Print the policy's findings to **stderr**, always — `--quiet` included.
///
/// They are the reason for the exit code, so suppressing them would leave a
/// failing build with nothing to explain it; stderr keeps stdout machine-readable
/// for `--format json`/`text`.
#[cfg(feature = "report")]
fn report_policy(outcome: &dependable_report::policy::PolicyOutcome) {
    use dependable_report::policy::Level;

    for note in &outcome.notes {
        eprintln!("policy: {note}");
    }
    for finding in &outcome.findings {
        let level = match finding.level {
            Level::Violation => "policy violation",
            _ => "policy warning",
        };
        eprintln!("{level}: {}", finding.message());
    }
    let violations = outcome.violation_count();
    if violations > 0 {
        let plural = if violations == 1 { "" } else { "s" };
        eprintln!(
            "policy: {violations} violation{plural} across {} dependencies",
            outcome.evaluated
        );
    }
}

/// A CVSS rule needs vulnerability scanning to mean anything.
///
/// With scanning off every advisory list is empty, and an empty list is
/// indistinguishable from "nothing was found" — so the gate would pass
/// vacuously. Failing here, before any network access, is the only honest
/// answer: a gate is either enforceable or it is a configuration error.
///
/// # Errors
///
/// When the policy sets `max_cvss`/`fail_on_severity` and scanning is disabled.
#[cfg(feature = "report")]
fn check_policy_is_enforceable(
    policy: &dependable_report::policy::Policy,
    check_vuln: bool,
) -> anyhow::Result<()> {
    if policy.requires_cvss() && !check_vuln {
        let key = if policy.max_cvss.is_some() {
            "max_cvss"
        } else {
            "fail_on_severity"
        };
        anyhow::bail!(
            "`[policy] {key}` requires vulnerability scanning, which is disabled; drop \
             `--no-vuln` (or re-enable `[vulnerability] enabled`), or remove the CVSS rule"
        );
    }
    Ok(())
}

/// The effective `[policy]` block: the config file's, with `DEPENDABLE_*`
/// overrides applied. `None` means nothing is gated.
///
/// Unlike the rest of the environment layer, a malformed override is an error
/// rather than a silently ignored value — the same reasoning as
/// [`crate::config::load_policy`]: an unenforced gate must never look enforced.
///
/// # Errors
///
/// When a `[policy]` table exists but is invalid, or an override is unusable.
#[cfg(feature = "report")]
fn resolve_policy(config: &Path) -> anyhow::Result<Option<dependable_report::policy::Policy>> {
    use dependable_fetch::core::result::Severity;
    use dependable_report::policy::Policy;

    // The kill switch, mirroring `DEPENDABLE_NO_VULN`: presence is enough.
    if std::env::var_os("DEPENDABLE_NO_POLICY").is_some() {
        return Ok(None);
    }

    let mut policy = match load_policy(config) {
        Ok(PolicySource::Configured(policy)) => policy,
        Ok(PolicySource::Absent) => Policy::default(),
        Ok(PolicySource::Unreadable(why)) => {
            eprintln!(
                "warning: {} could not be parsed; configuration ignored ({why})",
                config.display()
            );
            Policy::default()
        }
        Err(e) => {
            return Err(anyhow::Error::new(*e).context(format!(
                "invalid `[policy]` in {} — a policy that is configured is enforced or it is an error",
                config.display()
            )));
        }
    };

    if let Some(score) = env_override(
        "DEPENDABLE_MAX_CVSS",
        |raw| raw.parse::<f64>().ok().filter(is_cvss_score),
        "a CVSS score between 0.0 and 10.0",
    )? {
        policy.max_cvss = Some(score);
    }
    if let Some(band) = env_override(
        "DEPENDABLE_FAIL_ON_SEVERITY",
        Severity::parse,
        "a severity band (none, low, medium, high, critical)",
    )? {
        policy.fail_on_severity = Some(band);
    }
    if let Some(behind) = env_override(
        "DEPENDABLE_MAX_MAJOR_BEHIND",
        |raw| raw.parse::<u64>().ok(),
        "a non-negative whole number",
    )? {
        policy.max_major_behind = Some(behind);
    }

    if let Some(score) = policy.max_cvss.filter(|s| !is_cvss_score(s)) {
        anyhow::bail!("`[policy] max_cvss = {score}` is outside the CVSS range 0.0 to 10.0");
    }

    // A policy that gates nothing is the same as no policy at all.
    Ok(policy.is_active().then_some(policy))
}

/// Whether `score` is a value CVSS can actually produce.
#[cfg(feature = "report")]
fn is_cvss_score(score: &f64) -> bool {
    (0.0..=10.0).contains(score)
}

/// Read one `DEPENDABLE_*` policy override, failing loudly on a value that
/// cannot be understood. An unset or empty variable overrides nothing.
#[cfg(feature = "report")]
fn env_override<T>(
    key: &str,
    parse: impl Fn(&str) -> Option<T>,
    expected: &str,
) -> anyhow::Result<Option<T>> {
    let Some(raw) = std::env::var_os(key) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy().trim().to_string();
    if raw.is_empty() {
        return Ok(None);
    }
    parse(&raw)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("{key}={raw:?} is not {expected}"))
}

/// Say so when a `[policy]` block is present in a build that cannot enforce it.
///
/// Without the `report` feature the policy types do not exist, so the block can
/// only be detected, not read — but silence would look exactly like a gate that
/// passed.
#[cfg(not(feature = "report"))]
fn warn_policy_ignored(config: &Path) {
    if crate::config::has_policy_table(config) {
        eprintln!(
            "warning: {} declares `[policy]`, but this build has no `report` feature; the policy is not enforced",
            config.display()
        );
    }
}

/// `dependable list`
///
/// Offline by default: every manifest is parsed, its declared identity read, and any
/// sibling lockfile applied. Only `--features` touches the network.
pub async fn run_list(args: ListArgs) -> anyhow::Result<ExitCode> {
    let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    // `list` needs no configuration to do its own work, but the unread-manifest
    // warnings discovery emits are advice to *enable* something — and telling
    // someone to enable an ecosystem they switched off is noise `check`, `fix`, and
    // `report` already know not to make.
    // Fallible for the same reason as every other command: the file decides which
    // ecosystems are on, so a config that cannot be read must not be silently
    // replaced by defaults that enable all of them.
    let cfg =
        load_config(&args.config).with_context(|| format!("reading {}", args.config.display()))?;
    let ecosystems = requested_ecosystems(&args.ecosystem);
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        args.depth,
        &args.manifest_glob,
        &ecosystems,
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        report_no_manifests(&ecosystems);
        return Ok(ExitCode::SUCCESS);
    }
    let mut reports = Vec::new();
    for manifest in &manifests {
        let Some(kind) = ManifestKind::detect(manifest) else {
            continue;
        };
        report_lockfile_notices(manifest);
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

        // A member writing `dep.workspace = true` states no version of its own; the
        // constraint lives in the workspace root. Same resolution `check` and `fix` get,
        // so an inventory and a check never disagree about what a member depends on.
        //
        // Before the lockfile, and in that order for a reason: a lockfile can hold several
        // versions of one crate, and `pick_locked` chooses among them *by the declared
        // constraint*. Resolving second would hand it an empty constraint and pick the
        // highest — reporting `syn 2.0` locked against a member that inherits `syn = "1"`.
        let inherited = workspace_source(manifest, kind, &content)
            .map(|(_, declarations)| {
                resolve_workspace_inheritance(&mut parsed.items, &declarations)
            })
            .unwrap_or_default();
        let lockfile = (!args.no_lock_file)
            .then(|| apply_nearest_lockfile(manifest, kind, &root, &mut parsed.items))
            .flatten();
        let meta = parse_project(kind, &content);
        let (version, version_inherited) = resolve_version(manifest, kind, &meta);

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
            features: BTreeMap::new(),
            licenses: BTreeMap::new(),
        });
    }

    // Second passes, so one HTTP client — and one request per distinct package —
    // serves every manifest. Fetching inside the loop above asked the registry the
    // same question once per member that declared the crate.
    if args.features {
        crate::features::fetch_all(&mut reports).await?;
    }
    if args.licenses {
        crate::licenses::fetch_all(&mut reports).await?;
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
///
/// Reading the located root as a Cargo `[workspace]` table is this function's own
/// business: scalar inheritance (`version.workspace = true`) is a different axis from the
/// dependency inheritance the walk itself serves, and only Cargo has it.
fn workspace_package_defaults(
    manifest: &Path,
    kind: ManifestKind,
) -> Option<BTreeMap<String, String>> {
    if kind != ManifestKind::CargoToml {
        return None;
    }
    let (_, content) = nearest_workspace_root(manifest, kind)?;
    Some(parse_workspace(&content)?.package_defaults)
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

/// `dependable tui` (and a bare `dependable` in a terminal)
///
/// Builds the same fully-wired [`Checker`] the other commands use — every enabled
/// ecosystem, alternate registries, `.npmrc` auth — and hands it to the UI, which
/// only ever asks it about the one package on screen.
///
/// # Errors
/// Returns an error if the checker cannot be built or the terminal cannot be
/// configured.
pub async fn run_tui(args: TuiArgs) -> anyhow::Result<ExitCode> {
    let cfg =
        load_config(&args.config).with_context(|| format!("reading {}", args.config.display()))?;
    let settings = tui_settings(&cfg);
    // No progress bar: the UI draws its own screen.
    let engine = Engine::new(&settings, &cfg, false)?;

    let options = TuiOptions {
        path: args.path.unwrap_or_else(|| PathBuf::from(".")),
        depth: args.depth,
    };
    dependable_tui::run(options, Arc::new(engine.checker))
        .await
        .context("running the interactive UI")?;
    Ok(ExitCode::SUCCESS)
}

/// Settings for the UI: the config file's choices, with none of the check-only
/// flags (there is no `--fail-on` or output format to honor here).
fn tui_settings(cfg: &Config) -> Settings {
    Settings {
        concurrency: cfg.global.concurrency.max(1),
        depth: 3,
        check_lockfile: cfg.global.lock_file,
        check_vuln: cfg.vulnerability.enabled,
        licenses: false,
        cache: true,
        include_ghsa: cfg.global.include_ghsa,
        fail_on: FailOn::None,
        unstable: cfg.global.unstable.into(),
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    }
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
        collapse_roots: !args.no_dedupe,
    };
    output::tree::render(&graph, args.format, &tree_opts)?;
    Ok(ExitCode::SUCCESS)
}

/// `dependable fix`
pub async fn run_fix(args: FixArgs) -> anyhow::Result<ExitCode> {
    let cfg =
        load_config(&args.config).with_context(|| format!("reading {}", args.config.display()))?;
    let settings = Settings {
        concurrency: args.concurrency.unwrap_or(cfg.global.concurrency).max(1),
        depth: args.depth,
        check_lockfile: cfg.global.lock_file,
        // A vulnerable-but-current dependency is exactly the one worth upgrading, and
        // `fix.rs` has always had a `Vulnerable` arm — it was simply unreachable.
        check_vuln: cfg.vulnerability.enabled && !args.no_vuln,
        licenses: false,
        // `fix` writes to the user's manifests, so it must be able to refuse a cached
        // answer. Without this it decided what to write from an hour-old cache with no
        // way to bypass it.
        cache: !args.no_cache,
        include_ghsa: cfg.global.include_ghsa,
        fail_on: FailOn::None,
        unstable: cfg.global.unstable.into(),
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    };
    let ecosystems = requested_ecosystems(&args.ecosystem);
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        settings.depth,
        &args.manifest_glob,
        &ecosystems,
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        report_no_manifests(&ecosystems);
        return Ok(ExitCode::SUCCESS);
    }

    let engine = Engine::new(&settings, &cfg, true)?;

    // Plan every manifest before writing any of them. Writing as it went left the tree
    // half-rewritten when a later manifest failed — and because the report was printed
    // *after* each write, the failing iteration also destroyed the record of what had
    // already changed.
    let mut planned = Vec::new();
    for manifest in &manifests {
        let Some(report) = engine.check_manifest(manifest).await? else {
            continue;
        };
        report_inherited_skips(manifest, &report);
        let plan = fix::plan(manifest, &report.results, args.all)?;
        report_declined_fixes(manifest, &plan.declined);
        planned.push(plan);
    }

    let mut total = 0;
    for plan in &planned {
        if plan.records.is_empty() {
            continue;
        }
        if !args.dry_run {
            fix::commit(plan)?;
        }
        println!(
            "{}{}",
            plan.path.display(),
            if args.dry_run { " (dry run)" } else { "" }
        );
        for record in &plan.records {
            println!("  {} {} → {}", record.name, record.from, record.to);
            total += 1;
        }
    }
    let declined: usize = planned.iter().map(|plan| plan.declined.len()).sum();
    if total == 0 {
        // "Everything is already up to date" is only true when nothing was left
        // behind. Saying it over a declined update is the contradiction with
        // `check` that this whole path exists to remove, so the count of what was
        // left alone takes over the line and points at the notes that explain it.
        if declined == 0 {
            println!("Everything is already up to date.");
        } else {
            println!(
                "Nothing to rewrite. {declined} available update{} left alone; \
                 see the notes above.",
                if declined == 1 { "" } else { "s" }
            );
        }
    } else if !args.dry_run {
        println!(
            "\nUpdated {total} dependenc{}.",
            if total == 1 { "y" } else { "ies" }
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// The directory `dependable report` reads template overrides from, relative to
/// the report root.
#[cfg(feature = "report")]
const TEMPLATE_DIR: &str = "dependable-templates";

/// Effective settings for `dependable report`.
///
/// A focused resolver beside [`resolve_check_settings`] rather than a coercion of
/// [`ReportArgs`] into [`CheckArgs`]: `report` deliberately has no `--fail-on`,
/// `--unstable`, `--format`, or `--ecosystem`, and inventing values for them
/// would be worse than twenty honest lines.
#[cfg(feature = "report")]
fn resolve_report_settings(args: &crate::cli::ReportArgs, cfg: &Config) -> Settings {
    let env_no_vuln = std::env::var_os("DEPENDABLE_NO_VULN").is_some();
    let env_no_cache = std::env::var_os("DEPENDABLE_NO_CACHE").is_some();
    let env_ghsa = std::env::var_os("DEPENDABLE_INCLUDE_GHSA").is_some();
    let env_concurrency = std::env::var("DEPENDABLE_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());

    Settings {
        concurrency: env_concurrency.unwrap_or(cfg.global.concurrency).max(1),
        depth: args.depth,
        check_lockfile: cfg.global.lock_file,
        check_vuln: cfg.vulnerability.enabled && !args.no_vuln && !env_no_vuln,
        licenses: false,
        cache: !env_no_cache,
        include_ghsa: cfg.global.include_ghsa || env_ghsa,
        // Reserved and unwired: a report exits 0 whatever it finds. Gating a
        // build is `check`'s job, and exit 1 belongs to the policy engine.
        fail_on: FailOn::None,
        unstable: cfg.global.unstable.into(),
        registry: cfg.rust.registry.clone(),
        osv_url: cfg.vulnerability.osv_batch_url.clone(),
    }
}

/// Say which upgrades this manifest cannot make, and where they can be made instead.
///
/// A member inheriting `dep.workspace = true` is reported as outdated by `check` and then
/// silently left alone by `fix`, because the version string is in the workspace root and
/// there is no line here to rewrite. Without this the two commands appear to contradict
/// each other, and nothing points at the file that can actually be changed.
fn report_inherited_skips(manifest: &Path, report: &ManifestReport) {
    let Some(root) = &report.workspace_root else {
        return;
    };
    let mut names: Vec<&str> = report
        .results
        .iter()
        .filter(|result| {
            result.item.source == PackageSource::Inherited && result.status.has_update()
        })
        .map(|result| result.item.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return;
    }
    eprintln!(
        "note: {} inherits {} from the workspace; upgrade {} in {}",
        manifest.display(),
        names.join(", "),
        if names.len() == 1 { "it" } else { "them" },
        root.display()
    );
}

/// Say which available updates this manifest's own constraints refused, and why.
///
/// The sibling of [`report_inherited_skips`], for the other way `fix` can decline
/// an upgrade `check` just reported: there the version string lives in another
/// file, here it lives in a constraint that a concrete version would not
/// reproduce — a wildcard, a dist-tag, a two-bound range. Both are silent skips,
/// and silence is what makes the two commands look like they disagree.
///
/// stderr, like its sibling: a note is not part of the record of what `fix`
/// changed, and piping stdout must not swallow it or mix it into that record.
fn report_declined_fixes(manifest: &Path, declined: &[fix::Declined]) {
    for item in declined {
        eprintln!(
            "note: left {} = {} alone in {}: {} is available, but {}",
            item.name,
            item.constraint,
            manifest.display(),
            item.target,
            item.reason.explain()
        );
    }
}

/// Read whole-template overrides from `<root>/dependable-templates/`.
///
/// The directory is taken literally — no ancestor search, no `$XDG_CONFIG_HOME`,
/// no `$HOME`. One discoverable, per-project place, and nothing outside the
/// repository can silently restyle a report.
///
/// Only files sitting directly in that directory and ending `.html` or `.css` are
/// considered, so a `README.md` left there is ignored rather than rejected. A
/// considered file whose name is not one of
/// [`dependable_report::html::TEMPLATE_NAMES`] is a hard error naming the valid
/// set: an override with a typo that silently does nothing is the worst outcome
/// of the three.
///
/// # Errors
///
/// When the directory cannot be listed, a considered file cannot be read or is
/// not UTF-8, or a considered file is not a known template name.
#[cfg(feature = "report")]
fn load_template_overrides(root: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    use dependable_report::html::TEMPLATE_NAMES;

    let dir = root.join(TEMPLATE_DIR);
    if !dir.is_dir() {
        return Ok(BTreeMap::new());
    }
    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("reading template overrides from {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".html") || name.ends_with(".css") {
            names.push(name);
        }
    }
    // Sorted, so which of several bad names is reported first does not depend on
    // directory iteration order.
    names.sort();

    let mut overrides = BTreeMap::new();
    for name in names {
        anyhow::ensure!(
            TEMPLATE_NAMES.contains(&name.as_str()),
            "{}: `{name}` is not a template this report renders; valid names are: {}",
            dir.display(),
            TEMPLATE_NAMES.join(", ")
        );
        let path = dir.join(&name);
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading the template override {}", path.display()))?;
        overrides.insert(name, source);
    }
    Ok(overrides)
}

/// `dependable report`
///
/// Discovers manifests, checks each through the same [`Checker`] every other
/// command uses, and renders one self-contained HTML document. The document goes
/// to **stdout** unless `--output` names a file, which makes
/// `dependable report > report.html` the obvious idiom and keeps the command free
/// of filesystem side effects by default.
///
/// Manifest paths are stored relative to the report root, so no absolute machine
/// path lands in a document that gets emailed. (Pass an absolute root and you get
/// absolute paths — your choice.)
///
/// Exit codes: `0` when a document was rendered — finding vulnerabilities is this
/// command's job, not a failure — and `0` with a note on stderr when there is
/// nothing to report on. `2` for a discovery, fetch, template, or IO failure.
/// `1` is reserved for the policy engine and is not raised here.
///
/// # Errors
///
/// When the checker cannot be built, a manifest cannot be checked, a template
/// override is unknown or malformed, or the output file cannot be written.
#[cfg(feature = "report")]
pub async fn run_report(args: crate::cli::ReportArgs) -> anyhow::Result<ExitCode> {
    use std::io::Write;

    let cfg =
        load_config(&args.config).with_context(|| format!("reading {}", args.config.display()))?;
    let settings = resolve_report_settings(&args, &cfg);
    let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));

    // Before discovery and before the network: a bad override must not cost a
    // full check first.
    let overrides = load_template_overrides(&root)?;

    // `report` has no `--manifest-glob`: it describes a repository as a whole.
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        Some(&root),
        settings.depth,
        &[],
        &[],
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        // `report` has no `--ecosystem`, so there is never a specific line to
        // print instead.
        report_no_manifests(&[]);
        return Ok(ExitCode::SUCCESS);
    }

    let mut notes: Vec<String> = Vec::new();
    if !settings.check_vuln {
        notes.push(
            "Vulnerability scanning was disabled for this run, so the advisory sections are empty."
                .to_owned(),
        );
    }

    let engine = Engine::new(&settings, &cfg, !args.quiet)?;
    let mut report = dependable_report::Report::new(root.clone());
    for manifest in &manifests {
        for notice in lockfile_notes(manifest) {
            notes.push(notice);
        }
        match engine.check_manifest(manifest).await? {
            Some(checked) => report.push(dependable_report::ManifestResults::new(
                relative_to(&root, &checked.path),
                checked.ecosystem,
                checked.results,
            )),
            None => notes.push(format!(
                "Skipped {}: its ecosystem is not enabled or not yet supported.",
                relative_to(&root, manifest).display()
            )),
        }
    }

    let mut options = dependable_report::html::HtmlOptions::new()
        .with_title(format!("dependable report — {}", root.display()));
    for (name, source) in overrides {
        options = options.with_override(name, source);
    }
    // A report is frequently the only artifact a reviewer sees, so a warning that
    // exists only on a CI console is a warning that does not exist.
    if !args.quiet {
        for note in notes {
            options = options.with_note(note);
        }
    }

    let document =
        dependable_report::html::render(&report, &options).context("rendering the HTML report")?;

    match args.output {
        // `--output` does not create parent directories: silently materializing a
        // tree the user did not ask for is worse than saying the path is wrong.
        Some(path) => {
            std::fs::write(&path, document.as_bytes())
                .with_context(|| format!("writing the report to {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            out.write_all(document.as_bytes())
                .context("writing the report to stdout")?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Lockfile notices for one manifest, as document notes.
///
/// The same notices [`Engine::check_manifest`] prints to stderr; a reader of the
/// document has no access to that console.
#[cfg(feature = "report")]
fn lockfile_notes(manifest: &Path) -> Vec<String> {
    ManifestKind::detect(manifest).map_or_else(Vec::new, |kind| {
        dependable_fetch::lockfile_notices(manifest, kind)
            .iter()
            .map(ToString::to_string)
            .collect()
    })
}

/// The manifests a command should act on: the one named by `--manifest`, else the
/// depth-limited walk of `path`, narrowed by any `--ecosystem` values and then by
/// any `--manifest-glob` patterns.
///
/// Both filters run *after* the walk rather than pruning inside it: `path` still
/// roots the scan and `--depth` still bounds it, so they compose instead of
/// competing, and there stays exactly one walk implementation — in
/// `dependable-fetch`, which knows nothing about globs.
///
/// `ecosystems` empty means unrestricted. When it is not, it does two distinct
/// things, and both are required for the flag to mean what it says:
///
/// - It narrows the returned set. `dependable_fetch::discover` documents that its
///   `enabled` predicate "gates the notices only — discovery still returns every
///   manifest it recognizes, and narrowing that set stays the caller's job", so
///   composing the request into that predicate alone would suppress warnings and
///   change nothing a command actually reads.
/// - It is composed into that predicate all the same, so `--ecosystem rust` does
///   not also print advice about the Gradle build it just excluded.
///
/// The filter re-derives each manifest's ecosystem from its path. Discovery only
/// ever returns paths [`ManifestKind::detect`] recognized, so the `None` arm is
/// unreachable in practice; a path that somehow failed to detect is dropped,
/// because an ecosystem nothing can name is not one of the ones asked for.
///
/// The ecosystem filter runs **before** the glob filter so that the glob's
/// "matched nothing" line counts only the manifests still in play.
fn collect_manifests(
    manifest: Option<&Path>,
    path: Option<&Path>,
    depth: usize,
    globs: &[String],
    ecosystems: &[Ecosystem],
    enabled: &dyn Fn(Ecosystem) -> bool,
) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(manifest) = manifest {
        // `--manifest` names one exact file and bypasses discovery entirely, so
        // there is no discovered set for a glob or an ecosystem to filter. clap
        // rejects both combinations rather than letting one be silently ignored.
        return Ok(vec![manifest.to_path_buf()]);
    }
    let root = path.map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let requested = |ecosystem: Ecosystem| ecosystems.is_empty() || ecosystems.contains(&ecosystem);
    // One walk for both answers. Manifests we recognise but cannot read produce
    // nothing for the walk to return, so this is the only point at which their
    // absence can be reported at all.
    let found = dependable_fetch::discover(&root, depth, |ecosystem| {
        enabled(ecosystem) && requested(ecosystem)
    });
    for notice in &found.notices {
        eprintln!("warning: {notice}");
    }
    let mut found = found.manifests;
    if !ecosystems.is_empty() {
        let kept: Vec<PathBuf> = found
            .iter()
            .filter(|manifest| {
                ManifestKind::detect(manifest)
                    .is_some_and(|kind| ecosystems.contains(&kind.ecosystem()))
            })
            .cloned()
            .collect();
        if kept.is_empty() {
            eprintln!("{}", no_ecosystem_match(ecosystems, &found, depth));
        }
        found = kept;
    }
    if globs.is_empty() {
        return Ok(found);
    }
    let set = manifest_globs(globs)?;
    let kept: Vec<PathBuf> = found
        .iter()
        .filter(|manifest| set.is_match(output::posix(&relative_to(&root, manifest))))
        .cloned()
        .collect();
    if kept.is_empty() && !found.is_empty() {
        // `--depth` defaults to 3, so a pattern deeper than that matches nothing
        // however well it is written. Say what was searched, not just that the
        // answer was empty.
        eprintln!(
            "no manifest matched {} (searched {} manifest{} up to --depth {depth})",
            globs.join(", "),
            found.len(),
            if found.len() == 1 { "" } else { "s" }
        );
    }
    Ok(kept)
}

/// The ecosystems `--ecosystem` asked for, as the core type. Empty means
/// unrestricted, which is what an absent flag produces.
fn requested_ecosystems(args: &[EcosystemArg]) -> Vec<Ecosystem> {
    args.iter().copied().map(Ecosystem::from).collect()
}

/// Why an `--ecosystem` filter came back empty: what was asked for, how much was
/// searched, and which ecosystems were there instead.
///
/// This *replaces* the generic "No supported manifests found." rather than joining
/// it — see [`report_no_manifests`]. Naming what was found is the whole point: the
/// two answers a user needs to tell apart are "this repository has no Rust in it"
/// and "the filter removed everything", and the generic line says neither.
fn no_ecosystem_match(requested: &[Ecosystem], searched: &[PathBuf], depth: usize) -> String {
    // Discovery returns a sorted list, so first-seen order is deterministic.
    // `Ecosystem` is `Eq` but not `Ord`, so dedupe by membership rather than sort.
    let mut present: Vec<Ecosystem> = Vec::new();
    for kind in searched.iter().filter_map(|m| ManifestKind::detect(m)) {
        let ecosystem = kind.ecosystem();
        if !present.contains(&ecosystem) {
            present.push(ecosystem);
        }
    }
    let count = searched.len();
    let plural = if count == 1 { "" } else { "s" };
    let asked = ecosystem_names(requested);
    if present.is_empty() {
        format!("no manifest for {asked} (searched {count} manifest{plural} up to --depth {depth})")
    } else {
        format!(
            "no manifest for {asked} (searched {count} manifest{plural} up to --depth {depth}; found {})",
            ecosystem_names(&present)
        )
    }
}

/// Ecosystems as a human-readable list, in the order given.
fn ecosystem_names(ecosystems: &[Ecosystem]) -> String {
    ecosystems
        .iter()
        .map(|ecosystem| ecosystem.display_name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The line a command prints when discovery came back with nothing to do.
///
/// Silent when `--ecosystem` narrowed the set to nothing: [`collect_manifests`]
/// has already said which ecosystems were asked for and what was there instead,
/// and "No supported manifests found." is a falsehood in a repository full of
/// manifests the filter removed. Either way the exit code is 0 — an empty
/// selection is an answer, not a tool error, and a per-ecosystem CI matrix job
/// must not fail on the ecosystems a repository does not use.
fn report_no_manifests(ecosystems: &[Ecosystem]) {
    if ecosystems.is_empty() {
        eprintln!("No supported manifests found.");
    }
}

/// Compile `--manifest-glob` patterns into a matcher over manifest paths, with
/// union semantics: a manifest matching any pattern is kept.
///
/// These are **paths**, so `literal_separator(true)`: `*` and `?` stop at `/` and
/// only `**` crosses it. `crates/*/Cargo.toml` names one level of members, and
/// nobody who writes that expects `crates/a/vendor/b/Cargo.toml` back. Matching is
/// case-sensitive for the same reason — a path is not a name.
///
/// This is deliberately the opposite of [`dependable_tui::filter::Filter`], which
/// matches **package names** and therefore sets `literal_separator(false)` so `*`
/// spans `/` and `@types/*` works. Neither rule is right for both jobs, which is
/// why the two do not share a type.
///
/// # Errors
/// Returns an error if a pattern is not a valid glob. A typo silently matching
/// nothing would be indistinguishable from a correct pattern with no hits.
fn manifest_globs(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .with_context(|| format!("invalid --manifest-glob pattern: {pattern}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .context("compiling --manifest-glob patterns")
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

/// Whether a gate can be honoured from what this run actually established.
///
/// `FailOn::None` gates on nothing, so nothing can be missing. Every other setting is a
/// promise not to pass a build with a particular property, and a run that failed to
/// *look* cannot keep it.
///
/// The question is about the run, not about any one dependency. A registry that never
/// answered, or an advisory scan that did not complete, leaves the whole result set
/// unfounded — every dependency it covered is reported non-vulnerable because nothing
/// was asked. A registry that answered "no such package" left nothing unfounded: that
/// is a permanent, per-dependency fact about a private, internal, or deleted package,
/// visible in the table and in `--format json`, and gating the whole build on it turned
/// one unpublished internal package into a hard exit 2 for every repository that has
/// one — including every consumer of the shipped Action, which defaults to
/// `--fail-on vulnerable`.
///
/// The carve-out is for that answer alone. A dependency this run failed to evaluate by
/// itself — a constraint written in a dialect that did not parse — reached no registry,
/// so there is no fact standing in for its status and the gate is as unanswerable as it
/// ever was. Exempting those too let `{"lodash": "^^^bogus"}` pass
/// `--fail-on vulnerable` under a note blaming a registry that was never asked.
fn gate_is_answerable(reports: &[ManifestReport], fail_on: FailOn) -> Result<(), String> {
    if fail_on == FailOn::None {
        return Ok(());
    }
    let mut reasons: Vec<String> = Vec::new();
    if reports
        .iter()
        .any(|r| r.integrity.vulnerability_scan_failed)
    {
        reasons.push("the vulnerability scan did not complete".to_owned());
    }
    // `FailOn::Any` fails on `DependencyStatus::Error`, and both an unanswering registry
    // and an unreadable constraint produce exactly that — so there the promise is kept
    // rather than missed, and the run exits 1 on the errors themselves. The other
    // settings match specific statuses and skip errors entirely, which is where a run
    // that established nothing could still be reported as clean.
    if fail_on != FailOn::Any {
        if reports.iter().any(|r| r.integrity.registry_unreachable) {
            reasons.push("the registry did not answer".to_owned());
        }
        let unevaluated: usize = reports.iter().map(|r| r.integrity.unevaluated).sum();
        if unevaluated > 0 {
            reasons.push(format!(
                "{unevaluated} dependenc{} could not be evaluated",
                if unevaluated == 1 { "y" } else { "ies" }
            ));
        }
    }
    if reasons.is_empty() {
        return Ok(());
    }
    Err(join_reasons(&reasons))
}

/// `a`, `a and b`, `a, b and c` — the gate's reasons read as a sentence.
fn join_reasons(reasons: &[String]) -> String {
    match reasons {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Say on stderr how many dependencies the registry reported as non-existent.
///
/// Such a dependency has no status to gate on and the gate no longer stops for it, so
/// the run says plainly that it was not covered — otherwise a passing
/// `--fail-on vulnerable` reads as "every dependency here is clean" when one of them was
/// never checked.
///
/// Silent for `FailOn::None` (nothing was gated on) and for `FailOn::Any` (which fails
/// on these results, so they *were* gated on), and silent under `--quiet`, whose help
/// says "Only print errors" — a note about what was skipped is not one.
///
/// Counted from the registry's own answer ([`ScanIntegrity::unresolved`]), never from
/// every `Error`: an unreadable constraint reached no registry, and saying it was "not
/// found in its registry" reported a cause that never happened.
fn note_unresolved(reports: &[ManifestReport], fail_on: FailOn, quiet: bool) {
    if quiet || matches!(fail_on, FailOn::None | FailOn::Any) {
        return;
    }
    let unresolved: usize = reports.iter().map(|r| r.integrity.unresolved).sum();
    if unresolved == 0 {
        return;
    }
    eprintln!(
        "note: {unresolved} dependenc{} not found in {} registry, so {} not gated on",
        if unresolved == 1 { "y was" } else { "ies were" },
        if unresolved == 1 { "its" } else { "their" },
        if unresolved == 1 { "it is" } else { "they are" },
    );
}

/// Say on stderr how many dependencies this run could not read a version out of.
///
/// `Undetermined` is a real package whose declared constraint this run could not
/// translate, and the status was made honest without saying so anywhere: it trips no
/// `--fail-on outdated` gate, produces no SARIF result, and left a passing run reading
/// as "everything here is current" when a dependency had never been evaluated.
///
/// Mirrors [`note_unresolved`] exactly — same silences, same shape. Deliberately *not* a
/// gate: adding `Undetermined` to `--fail-on outdated` would change what that setting
/// promises, and `--fail-on any` already fails on it.
fn note_undetermined(reports: &[ManifestReport], fail_on: FailOn, quiet: bool) {
    if quiet || matches!(fail_on, FailOn::None | FailOn::Any) {
        return;
    }
    let undetermined = reports
        .iter()
        .flat_map(|report| &report.results)
        .filter(|result| matches!(result.status, DependencyStatus::Undetermined))
        .count();
    if undetermined == 0 {
        return;
    }
    eprintln!(
        "note: {undetermined} dependenc{} a declared version this run could not read, so {} not \
         gated on",
        if undetermined == 1 {
            "y has"
        } else {
            "ies have"
        },
        if undetermined == 1 {
            "it is"
        } else {
            "they are"
        },
    );
}

fn exit_code(reports: &[ManifestReport], fail_on: FailOn, quiet: bool) -> ExitCode {
    // A gate whose inputs are missing must fail, not pass. `--fail-on vulnerable` with an
    // unreachable OSV used to exit 0 while printing the errors that explain why it could
    // not know — a green build that had never been checked, which is the one outcome a
    // gate exists to prevent.
    if let Err(reason) = gate_is_answerable(reports, fail_on) {
        eprintln!("error: cannot honour --fail-on: {reason}");
        eprintln!("       refusing to report a clean run that was never completed");
        return ExitCode::from(2);
    }
    note_unresolved(reports, fail_on, quiet);
    note_undetermined(reports, fail_on, quiet);
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

    /// The monorepo fixture: `services/{a,b}/Cargo.toml`, one level deeper at
    /// `services/a/nested/Cargo.toml`, and `tools/lint/Cargo.toml` outside it.
    fn monorepo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-monorepo")
    }

    fn matched(globs: &[&str]) -> Vec<String> {
        let globs: Vec<String> = globs.iter().map(|g| (*g).to_string()).collect();
        let root = monorepo();
        collect_manifests(None, Some(&root), 4, &globs, &[], &|_| true)
            .expect("the patterns are valid")
            .iter()
            .map(|m| output::posix(&relative_to(&root, m)))
            .collect()
    }

    #[test]
    fn a_star_in_a_manifest_glob_does_not_cross_a_slash() {
        assert_eq!(
            matched(&["services/*/Cargo.toml"]),
            vec!["services/a/Cargo.toml", "services/b/Cargo.toml"],
            "`*` stops at `/`, so the manifest a level deeper is excluded"
        );
    }

    #[test]
    fn a_double_star_crosses_a_slash() {
        assert_eq!(
            matched(&["services/**/Cargo.toml"]),
            vec![
                "services/a/Cargo.toml",
                "services/a/nested/Cargo.toml",
                "services/b/Cargo.toml",
            ]
        );
    }

    #[test]
    fn repeated_patterns_are_a_union() {
        assert_eq!(
            matched(&["services/a/Cargo.toml", "tools/*/Cargo.toml"]),
            vec!["services/a/Cargo.toml", "tools/lint/Cargo.toml"]
        );
    }

    #[test]
    fn no_pattern_keeps_every_discovered_manifest() {
        assert_eq!(matched(&[]).len(), 4);
    }

    #[test]
    fn a_pattern_matching_nothing_yields_nothing_rather_than_everything() {
        assert!(matched(&["apps/*/Cargo.toml"]).is_empty());
    }

    #[test]
    fn an_explicit_manifest_is_returned_whatever_the_patterns() {
        // clap rejects the combination, so this only documents that the glob
        // never silently filters away a file the user named outright.
        let named = PathBuf::from("some/other/Cargo.toml");
        assert_eq!(
            collect_manifests(Some(&named), None, 3, &["nope/*".to_string()], &[], &|_| {
                true
            })
            .expect("the pattern is valid"),
            vec![named]
        );
    }

    #[test]
    fn an_unparseable_pattern_is_an_error_not_an_empty_result() {
        let root = monorepo();
        assert!(
            collect_manifests(
                None,
                Some(&root),
                4,
                &["services/[".to_string()],
                &[],
                &|_| true
            )
            .is_err()
        );
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

    fn fixture_item() -> dependable_fetch::Item {
        dependable_fetch::core::parse(
            dependable_fetch::ManifestKind::CargoToml,
            "[dependencies]\nserde = \"1\"\n",
        )
        .expect("fixture manifest")
        .items
        .into_iter()
        .next()
        .expect("one dependency")
    }

    /// A result the **registry** produced by name: no such package. Built through
    /// [`CheckResult::not_found`] rather than by hand, because the provenance — not the
    /// wording of the message — is what the gate reads.
    fn not_found_result() -> dependable_fetch::CheckResult {
        dependable_fetch::CheckResult::errored(
            fixture_item(),
            "package `@acme/internal` not found",
            ErrorOrigin::NotFound,
        )
    }

    fn report_of(
        integrity: ScanIntegrity,
        results: Vec<dependable_fetch::CheckResult>,
    ) -> ManifestReport {
        ManifestReport {
            path: PathBuf::from("Cargo.toml"),
            ecosystem: dependable_fetch::Ecosystem::Rust,
            results,
            workspace_root: None,
            integrity,
        }
    }

    fn report_with(integrity: ScanIntegrity, statuses: &[DependencyStatus]) -> ManifestReport {
        report_of(
            integrity,
            statuses
                .iter()
                .map(|s| dependable_fetch::CheckResult::new(fixture_item(), s.clone()))
                .collect(),
        )
    }

    /// The defect this exists to prevent: OSV unreachable, `--fail-on vulnerable` armed,
    /// every result left non-vulnerable because nothing was ever asked — and the run
    /// exiting 0, certifying a build it had not checked.
    #[test]
    fn a_failed_scan_cannot_pass_a_vulnerability_gate() {
        let reports = vec![report_with(
            ScanIntegrity {
                vulnerability_scan_failed: true,
                registry_unreachable: false,
                unresolved: 0,
                unevaluated: 0,
            },
            &[DependencyStatus::UpToDate],
        )];
        assert!(gate_is_answerable(&reports, FailOn::Vulnerable).is_err());
        assert!(gate_is_answerable(&reports, FailOn::Outdated).is_err());
        assert!(gate_is_answerable(&reports, FailOn::Any).is_err());
        // Nothing was gated on, so nothing can be missing.
        assert!(gate_is_answerable(&reports, FailOn::None).is_ok());
    }

    /// A registry that never answered leaves every dependency it covered unfounded, so
    /// the gate still cannot be honoured — the half of the guard that has to survive the
    /// narrowing below.
    #[test]
    fn an_unreachable_registry_cannot_pass_a_status_gate() {
        let reports = vec![report_with(
            ScanIntegrity {
                vulnerability_scan_failed: false,
                registry_unreachable: true,
                unresolved: 0,
                unevaluated: 0,
            },
            &[DependencyStatus::Error("registry unreachable".to_owned())],
        )];
        assert!(gate_is_answerable(&reports, FailOn::Vulnerable).is_err());
        assert!(gate_is_answerable(&reports, FailOn::Outdated).is_err());
        assert_eq!(
            exit_code(&reports, FailOn::Vulnerable, false),
            ExitCode::from(2)
        );
        // `Any` fails on the `Error` statuses an unanswering registry produces, so its
        // promise is kept — that is the gate working, not a hole.
        assert!(gate_is_answerable(&reports, FailOn::Any).is_ok());
        assert_eq!(exit_code(&reports, FailOn::Any, false), ExitCode::from(1));
        // Nothing was gated on, so nothing can be missing.
        assert!(gate_is_answerable(&reports, FailOn::None).is_ok());
    }

    /// A registry that answered "no such package" answered. A private or internal
    /// package, one served by a registry this run does not route to, or a deleted one is
    /// a permanent per-dependency fact: it is reported, and it does not turn every
    /// `--fail-on` setting into exit 2 for the dependencies that *did* resolve.
    ///
    /// This corrects an assertion that pinned the opposite. `--fail-on vulnerable` is
    /// the shipped Action's default, so under the old rule every repository containing
    /// one unpublished internal package went from a passing step to a hard failure, with
    /// no escape short of dropping the gate.
    #[test]
    fn a_package_the_registry_says_does_not_exist_does_not_break_the_gate() {
        let not_found = not_found_result();
        assert_eq!(
            not_found.error_origin,
            ErrorOrigin::NotFound,
            "the carve-out has to be reached through the provenance, not through the message"
        );
        let reports = vec![report_of(
            ScanIntegrity {
                vulnerability_scan_failed: false,
                registry_unreachable: false,
                unresolved: 1,
                unevaluated: 0,
            },
            vec![
                dependable_fetch::CheckResult::new(fixture_item(), DependencyStatus::UpToDate),
                not_found,
            ],
        )];
        assert!(gate_is_answerable(&reports, FailOn::Vulnerable).is_ok());
        assert!(gate_is_answerable(&reports, FailOn::Outdated).is_ok());
        assert!(gate_is_answerable(&reports, FailOn::Any).is_ok());
        assert_eq!(
            exit_code(&reports, FailOn::Vulnerable, false),
            ExitCode::SUCCESS
        );
        assert_eq!(
            exit_code(&reports, FailOn::Outdated, false),
            ExitCode::SUCCESS
        );
        // `Any` still fails on the error itself — that is the gate working, and it is
        // the setting that asks to hear about anything less than a clean answer.
        assert_eq!(exit_code(&reports, FailOn::Any, false), ExitCode::from(1));
    }

    /// The other half of the same distinction, and the regression the carve-out
    /// introduced: an unparseable constraint never reaches a registry, so nothing was
    /// established about the dependency at all. Exempting it alongside the 404s let
    /// `{"lodash": "^^^bogus"}` pass `--fail-on vulnerable` under a note saying the
    /// registry had not found it — a gate certifying a build it had not evaluated.
    #[test]
    fn a_dependency_this_run_could_not_evaluate_still_breaks_the_gate() {
        let error = dependable_fetch::CheckResult::new(
            fixture_item(),
            DependencyStatus::Error("unparseable constraint: unexpected character '^'".to_owned()),
        );
        assert_eq!(
            error.error_origin,
            ErrorOrigin::Local,
            "no registry was ever asked about this dependency"
        );
        let reports = vec![report_of(
            ScanIntegrity {
                vulnerability_scan_failed: false,
                registry_unreachable: false,
                unresolved: 0,
                unevaluated: 1,
            },
            vec![
                dependable_fetch::CheckResult::new(fixture_item(), DependencyStatus::UpToDate),
                error,
            ],
        )];
        assert_eq!(
            gate_is_answerable(&reports, FailOn::Vulnerable).unwrap_err(),
            "1 dependency could not be evaluated"
        );
        assert!(gate_is_answerable(&reports, FailOn::Outdated).is_err());
        assert_eq!(
            exit_code(&reports, FailOn::Vulnerable, false),
            ExitCode::from(2)
        );
        // `Any` fails on the `Error` itself, so its promise is kept.
        assert!(gate_is_answerable(&reports, FailOn::Any).is_ok());
        assert_eq!(exit_code(&reports, FailOn::Any, false), ExitCode::from(1));
        // Nothing was gated on, so nothing can be missing.
        assert!(gate_is_answerable(&reports, FailOn::None).is_ok());
    }

    /// Every unanswerable reason at once, read as one sentence rather than as a
    /// hand-written combination per pair.
    #[test]
    fn the_gate_names_every_reason_it_could_not_be_honoured() {
        let reports = vec![report_of(
            ScanIntegrity {
                vulnerability_scan_failed: true,
                registry_unreachable: true,
                unresolved: 0,
                unevaluated: 2,
            },
            vec![],
        )];
        assert_eq!(
            gate_is_answerable(&reports, FailOn::Vulnerable).unwrap_err(),
            "the vulnerability scan did not complete, the registry did not answer and 2 \
             dependencies could not be evaluated"
        );
    }

    /// A complete run still gates on what it found, and still passes when it finds
    /// nothing — the guard must not turn every check into a failure.
    #[test]
    fn a_complete_run_gates_on_its_findings_as_before() {
        let clean = vec![report_with(
            ScanIntegrity::default(),
            &[DependencyStatus::UpToDate],
        )];
        assert!(gate_is_answerable(&clean, FailOn::Vulnerable).is_ok());
        assert_eq!(
            exit_code(&clean, FailOn::Vulnerable, false),
            ExitCode::SUCCESS
        );

        let vulnerable = vec![report_with(
            ScanIntegrity::default(),
            &[DependencyStatus::Vulnerable],
        )];
        assert_eq!(
            exit_code(&vulnerable, FailOn::Vulnerable, false),
            ExitCode::from(1)
        );
    }

    /// Parse a real command line, so the test exercises the same `Option` clap produces
    /// rather than a hand-built struct that could disagree with it.
    fn check_args(argv: &[&str]) -> crate::cli::CheckArgs {
        use clap::Parser as _;
        let cli = crate::cli::Cli::try_parse_from(argv).expect("a valid command line");
        match cli.command {
            Some(crate::cli::Command::Check(args)) => args,
            _ => panic!("expected the check subcommand"),
        }
    }

    /// Documented precedence is CLI over env over config. `fail_on` inverted it: the
    /// guard compared against `FailOn::None`, which is also clap's default, so an
    /// explicit `--fail-on none` was indistinguishable from the flag being absent and a
    /// config that armed the gate could not be disarmed from the command line.
    #[test]
    fn an_explicit_fail_on_none_beats_the_config() {
        let mut cfg = Config::default();
        cfg.global.fail_on = FailOn::Any;

        let explicit = resolve_check_settings(
            &check_args(&["dependable", "check", "--fail-on", "none"]),
            &cfg,
        );
        assert_eq!(
            explicit.fail_on,
            FailOn::None,
            "the command line was ignored"
        );

        // Absent, the config still governs.
        let absent = resolve_check_settings(&check_args(&["dependable", "check"]), &cfg);
        assert_eq!(absent.fail_on, FailOn::Any);

        // And a non-default flag still wins, as it always did.
        let vulnerable = resolve_check_settings(
            &check_args(&["dependable", "check", "--fail-on", "vulnerable"]),
            &cfg,
        );
        assert_eq!(vulnerable.fail_on, FailOn::Vulnerable);
    }
}
