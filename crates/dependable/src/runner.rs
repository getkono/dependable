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
    AlternateRegistryDecl, NpmrcConfig, PackageField, ProjectMeta, apply_lockfile, lockfile_items,
    parse, parse_cargo_config, parse_npmrc, parse_project, parse_workspace,
    resolve_workspace_inheritance,
};
use dependable_fetch::{
    CheckError, Checker, DependencyStatus, Ecosystem, GoProxyFetcher, GraphSource, HexFetcher,
    Item, JsrFetcher, ManifestKind, MavenCentralFetcher, NpmFetcher, NuGetFetcher, PackageSource,
    PackagistFetcher, ParseError, ProgressEvent, PubDevFetcher, PyPiFetcher, ScopedRegistry,
    TreeOptions, UnstableFilter, WorkspaceGraphOptions, build_client, build_workspace_graph,
    nearest_workspace_root, workspace_source,
};
use dependable_tui::TuiOptions;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::{CheckArgs, FailOn, FixArgs, ListArgs, TreeArgs, TuiArgs};
use crate::config::{Config, load_config};
#[cfg(feature = "report")]
use crate::config::{PolicySource, load_policy};
use crate::fix;
use crate::output::list::ProjectReport;
use crate::output::{self, ManifestReport};

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
        licenses: policy_requires_licenses(cfg),
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
        // Swift has no fetcher to register — it has no registry — so enabling it is
        // an assertion rather than a registration. Same switch, same config key,
        // and without it `[swift] enabled = false` would do nothing at all.
        if cfg.swift.enabled {
            builder = builder.registryless(Ecosystem::Swift);
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
        let dependencies_unread = report_lockfile_notices(path);
        match self.checker.check_path(path).await {
            Ok(check) => {
                for warning in &check.warnings {
                    eprintln!("warning: {} — {warning}", path.display());
                }
                Ok(Some(ManifestReport {
                    path: path.to_path_buf(),
                    ecosystem: check.ecosystem,
                    results: check.results,
                    workspace_root: check.workspace_root,
                    dependencies_unread,
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

/// Warn about lockfiles that are present beside `manifest` but cannot be used —
/// or, for the one format that *is* the dependency list, absent altogether.
///
/// Without this a `bun.lockb` is silently skipped and every dependency is
/// reported unlocked, with nothing to tell the user that a lockfile they can
/// migrate is the reason.
///
/// Returns whether any notice means the project's dependency list itself went
/// unread, which the caller has to carry into the exit code: a run that knows
/// nothing about a project must not report it clean.
fn report_lockfile_notices(manifest: &Path) -> bool {
    let Some(kind) = ManifestKind::detect(manifest) else {
        return false;
    };
    let mut unread = false;
    for notice in dependable_fetch::lockfile_notices(manifest, kind) {
        eprintln!("warning: {notice}");
        unread |= notice.dependency_list_unread;
    }
    unread
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

    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        settings.depth,
        &args.manifest_glob,
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
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
        let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
        let outcome = dependable_report::policy::evaluate(&build_report(root, &reports), policy);
        report_policy(&outcome);
        if outcome.has_violations() {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(exit_code(&reports, fail_on))
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
            "`[policy] {key}` requires vulnerability scanning, which is disabled;              drop `--no-vuln` (or re-enable `[vulnerability] enabled`), or remove the CVSS rule"
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
            "warning: {} declares `[policy]`, but this build has no `report` feature;              the policy is not enforced",
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
    let cfg = load_config(&args.config);
    let manifests = collect_manifests(
        args.manifest.as_deref(),
        args.path.as_deref(),
        args.depth,
        &args.manifest_glob,
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        eprintln!("No supported manifests found.");
        return Ok(ExitCode::SUCCESS);
    }
    let mut reports = Vec::new();
    for manifest in &manifests {
        let Some(kind) = ManifestKind::detect(manifest) else {
            continue;
        };
        let _ = report_lockfile_notices(manifest);
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
        // What the parser saw and declined to read. On stderr rather than in the
        // listing, so the same words reach a reader whichever `--format` they
        // chose, and no machine-readable document changes shape — the same place
        // `check` puts a manifest-level warning.
        for notice in &parsed.notices {
            eprintln!("warning: {} — {notice}", manifest.display());
        }

        let inherited = workspace_source(manifest, kind, &content)
            .map(|(_, declarations)| {
                resolve_workspace_inheritance(&mut parsed.items, &declarations)
            })
            .unwrap_or_default();
        let lockfile =
            apply_nearest_lockfile(manifest, kind, &root, !args.no_lock_file, &mut parsed.items);
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
///
/// # `annotations`
/// `--no-lock-file` clears this, and it governs **only** the annotating half. The flag
/// is documented as "ignore sibling lockfiles (do not report locked versions)": it
/// suppresses the `locked_at` column, which is an annotation on a list the manifest
/// already produced. A `Package.resolved` is not that — it *is* the list, because a
/// `Package.swift` is a program this tool declines to read. Honouring the flag there
/// would not withhold a version column, it would report a Swift project as depending
/// on nothing at all, which is the inversion this ecosystem's support exists to
/// prevent. So a dependency-source lockfile is read regardless, and the flag keeps
/// exactly the meaning its help text claims.
fn apply_nearest_lockfile(
    manifest: &Path,
    kind: ManifestKind,
    root: &Path,
    annotations: bool,
    items: &mut Vec<Item>,
) -> Option<PathBuf> {
    // One lockfile *is* the dependency list rather than an annotation on one: a
    // `Package.swift` is a program this tool declines to read, so its
    // `Package.resolved` is where the dependencies come from. Without this branch
    // `list` reports a Swift project as depending on nothing.
    if let Some((path, lock_kind)) = dependable_fetch::locate_lockfile(manifest, kind)
        && lock_kind.is_dependency_source()
    {
        let content = std::fs::read_to_string(&path).ok()?;
        items.extend(lockfile_items(lock_kind, &content)?);
        return Some(relative_to(root, &path));
    }
    if !annotations {
        return None;
    }
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
    let cfg = load_config(&args.config);
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
    let cfg = load_config(&args.config);
    let settings = Settings {
        concurrency: args.concurrency.unwrap_or(cfg.global.concurrency).max(1),
        depth: args.depth,
        check_lockfile: cfg.global.lock_file,
        check_vuln: false,
        licenses: false,
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
        &args.manifest_glob,
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        eprintln!("No supported manifests found.");
        return Ok(ExitCode::SUCCESS);
    }

    let engine = Engine::new(&settings, &cfg, true)?;
    let mut total = 0;
    let mut unchecked = 0;
    for manifest in &manifests {
        let Some(report) = engine.check_manifest(manifest).await? else {
            continue;
        };
        report_inherited_skips(manifest, &report);
        unchecked += report
            .results
            .iter()
            .filter(|result| result.status == DependencyStatus::Undetermined)
            .count();
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
    if total == 0 && unchecked == 0 {
        println!("Everything is already up to date.");
    } else if total == 0 {
        // "Up to date" is a claim about versions that were compared against a
        // registry. Where none could be — an ecosystem that publishes no registry
        // at all, or an entry whose version this manifest never states — nothing
        // was established, and printing the clean line anyway turns "we did not
        // look" into "we looked and found nothing", which is the one thing a fix
        // run must never say.
        println!(
            "Nothing to rewrite. {unchecked} dependenc{} could not be checked for a newer \
             version; see the warnings above.",
            if unchecked == 1 { "y" } else { "ies" }
        );
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
            result.item.source == PackageSource::Inherited
                && matches!(
                    result.status,
                    DependencyStatus::PatchAvailable
                        | DependencyStatus::UpdateAvailable
                        | DependencyStatus::Outdated
                        | DependencyStatus::Vulnerable
                )
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

    let cfg = load_config(&args.config);
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
        &|ecosystem| cfg.ecosystem_enabled(ecosystem),
    )?;
    if manifests.is_empty() {
        eprintln!("No supported manifests found.");
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
/// depth-limited walk of `path`, narrowed by any `--manifest-glob` patterns.
///
/// The globs filter *after* the walk rather than pruning inside it: `path` still
/// roots the scan and `--depth` still bounds it, so the three compose instead of
/// competing, and there stays exactly one walk implementation — in
/// `dependable-fetch`, which knows nothing about globs.
fn collect_manifests(
    manifest: Option<&Path>,
    path: Option<&Path>,
    depth: usize,
    globs: &[String],
    enabled: &dyn Fn(Ecosystem) -> bool,
) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(manifest) = manifest {
        // `--manifest` names one exact file and bypasses discovery entirely, so
        // there is no discovered set for a glob to filter. clap rejects the
        // combination rather than letting one of them be silently ignored.
        return Ok(vec![manifest.to_path_buf()]);
    }
    let root = path.map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    // One walk for both answers. Manifests we recognise but cannot read produce
    // nothing for the walk to return, so this is the only point at which their
    // absence can be reported at all.
    let found = dependable_fetch::discover(&root, depth, enabled);
    for notice in &found.notices {
        eprintln!("warning: {notice}");
    }
    let found = found.manifests;
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

/// The exit code for a finished run under the configured gate.
///
/// # Where [`DependencyStatus::Undetermined`] sits
///
/// It is **clean** under `--fail-on vulnerable` and `--fail-on outdated`, and
/// **not clean** under `--fail-on any`.
///
/// Those two named gates ask a specific question — is anything vulnerable, is
/// anything behind — and an unread version answers neither. Failing a build that
/// asked about vulnerabilities because a POM defers to its `<parent>` would make
/// the flag mean something other than what it says.
///
/// `--fail-on any` asks the general one: is every dependency checked and current.
/// A dependency whose version was never read is not current — it is unestablished,
/// and exiting `0` asserts something this run never determined. That is precisely
/// how a parent-inheriting POM used to pass green while dependable had read
/// nothing at all. It is grouped with the failures rather than with
/// [`DependencyStatus::Local`] and [`DependencyStatus::Git`], which are clean
/// because they were skipped *on purpose*: there is no registry behind them, so
/// there is nothing a stricter run could ever learn.
///
/// The status never travels alone: `check` emits a manifest-level warning on
/// stderr naming the dependencies involved, so a failing job says what to fix.
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
            // `Undetermined` is absent from this clean list on purpose — see the
            // doc comment above.
            FailOn::Any => !matches!(
                result.status,
                DependencyStatus::UpToDate | DependencyStatus::Local | DependencyStatus::Git
            ),
        });
    // A manifest whose dependency list was never read has no results to inspect,
    // so the loop above sees an empty list and finds nothing wrong with it. That
    // is the inversion in its purest form: zero rows read as a clean project. Only
    // `--fail-on any` asks the question this answers — `vulnerable` and `outdated`
    // ask about findings, and there are none to have.
    let unread = fail_on == FailOn::Any && reports.iter().any(|r| r.dependencies_unread);
    if triggered || unread {
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
        collect_manifests(None, Some(&root), 4, &globs, &|_| true)
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
            collect_manifests(Some(&named), None, 3, &["nope/*".to_string()], &|_| true)
                .expect("the pattern is valid"),
            vec![named]
        );
    }

    #[test]
    fn an_unparseable_pattern_is_an_error_not_an_empty_result() {
        let root = monorepo();
        assert!(
            collect_manifests(None, Some(&root), 4, &["services/[".to_string()], &|_| true)
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
}
