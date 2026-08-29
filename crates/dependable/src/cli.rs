//! Command-line interface definition (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "dependable",
    version,
    about = "Check dependency versions and known vulnerabilities"
)]
pub struct Cli {
    /// The subcommand, or `None` for a bare `dependable`.
    ///
    /// Optional so that running `dependable` with no arguments can open the TUI.
    /// Making it optional is also what turns off clap's implicit
    /// `subcommand_required` + `arg_required_else_help`, so `main` reproduces the
    /// old help-and-exit behavior itself when the session is not interactive.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Check dependencies against the registry and OSV.
    Check(CheckArgs),
    /// List the projects in a repository and the dependencies each declares.
    List(ListArgs),
    /// Render the workspace dependency tree (Rust; offline, from Cargo.lock).
    Tree(TreeArgs),
    /// Update versions in place to the latest compatible.
    Fix(FixArgs),
    /// Explore dependencies interactively (the default when run in a terminal).
    Tui(TuiArgs),
    /// Render a self-contained HTML dependency and vulnerability report.
    #[cfg(feature = "report")]
    Report(ReportArgs),
}

impl Cli {
    /// Whether verbose logging was requested on the chosen subcommand.
    #[must_use]
    pub fn verbose(&self) -> bool {
        match &self.command {
            Some(Command::Check(args)) => args.verbose,
            Some(Command::List(args)) => args.verbose,
            Some(Command::Tree(args)) => args.verbose,
            Some(Command::Fix(args)) => args.verbose,
            Some(Command::Tui(args)) => args.verbose,
            #[cfg(feature = "report")]
            Some(Command::Report(args)) => args.verbose,
            None => false,
        }
    }
}

#[derive(Args)]
pub struct CheckArgs {
    /// Project directory to scan (default: current directory).
    pub path: Option<PathBuf>,
    /// Check a single manifest file instead of discovering them.
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Only use manifests whose path, relative to the scanned directory, matches
    /// this glob (e.g. `crates/*/Cargo.toml`). Repeatable; a manifest matching
    /// any pattern is kept. `*` and `?` do not cross `/`, `**` does.
    #[arg(long, conflicts_with = "manifest")]
    pub manifest_glob: Vec<String>,
    /// Config file path.
    #[arg(long, default_value = ".dependable.toml")]
    pub config: PathBuf,
    /// Pre-release filter: `exclude` (default), `include-always`, or
    /// `include-if-current`. Overrides `[global] unstable`.
    #[arg(long, value_enum)]
    pub unstable: Option<UnstableFilter>,
    /// Ignore `Cargo.lock`.
    #[arg(long)]
    pub no_lock_file: bool,
    /// Skip vulnerability scanning.
    #[arg(long)]
    pub no_vuln: bool,
    /// Ignore the on-disk registry cache (always fetch fresh).
    #[arg(long)]
    pub no_cache: bool,
    /// Include GHSA advisories in the vulnerability scan.
    #[arg(long)]
    pub include_ghsa: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = CheckFormat::Table)]
    pub format: CheckFormat,
    /// Exit non-zero when results match this level.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    pub fail_on: FailOn,
    /// GitHub Actions annotations and job summary: `auto` (default, on under
    /// the runner), `always`, or `never`.
    #[arg(long, value_enum, default_value_t = AnnotationMode::Auto)]
    pub annotations: AnnotationMode,
    /// How many directories deep to search.
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    /// Max concurrent HTTP requests (overrides config).
    #[arg(long)]
    pub concurrency: Option<usize>,
    /// Only print errors.
    #[arg(short, long)]
    pub quiet: bool,
    /// Verbose logging (HTTP request details).
    #[arg(short, long)]
    pub verbose: bool,
    /// Restrict to ecosystem(s) (reserved; V1 only checks Rust).
    #[arg(long)]
    pub ecosystem: Option<String>,
}

#[derive(Args)]
pub struct ListArgs {
    /// Project directory to scan (default: current directory).
    pub path: Option<PathBuf>,
    /// List a single manifest file instead of discovering them.
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Only use manifests whose path, relative to the scanned directory, matches
    /// this glob (e.g. `crates/*/Cargo.toml`). Repeatable; a manifest matching
    /// any pattern is kept. `*` and `?` do not cross `/`, `**` does.
    #[arg(long, conflicts_with = "manifest")]
    pub manifest_glob: Vec<String>,
    /// Output format: `table` for reading, `json` for the full inventory, `text` for
    /// one tab-separated line per dependency.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// How many directories deep to search.
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    /// Ignore sibling lockfiles (do not report locked versions).
    #[arg(long)]
    pub no_lock_file: bool,
    /// Show each crate's available feature flags (Rust only; fetches the
    /// crates.io sparse index, so this makes `list` hit the network).
    #[arg(long)]
    pub features: bool,
    /// Show each dependency's registry-declared license (fetches package
    /// metadata, so this makes `list` hit the network). Available for crates.io,
    /// npm, PyPI, Packagist, and Hex; Go, JSR, NuGet, and pub.dev publish none.
    /// Uses the default registry URLs — `list` reads no config file.
    #[arg(long)]
    pub licenses: bool,
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct TreeArgs {
    /// Project directory to analyze (default: current directory).
    pub path: Option<PathBuf>,
    /// Root the tree at a single crate instead of all workspace members.
    #[arg(short = 'p', long)]
    pub package: Option<String>,
    /// Invert the tree: show what depends on each root (downstream impact).
    #[arg(long)]
    pub invert: bool,
    /// Maximum depth to display (default: unlimited; `0` = roots only).
    #[arg(long)]
    pub depth: Option<usize>,
    /// Show every occurrence of a crate in full, instead of collapsing repeats
    /// to `(*)` and workspace members to `(see root)`.
    #[arg(long)]
    pub no_dedupe: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = TreeFormat::Tree)]
    pub format: TreeFormat,
    /// Verbose logging.
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct FixArgs {
    pub path: Option<PathBuf>,
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Only use manifests whose path, relative to the scanned directory, matches
    /// this glob (e.g. `crates/*/Cargo.toml`). Repeatable; a manifest matching
    /// any pattern is kept. `*` and `?` do not cross `/`, `**` does.
    #[arg(long, conflicts_with = "manifest")]
    pub manifest_glob: Vec<String>,
    #[arg(long, default_value = ".dependable.toml")]
    pub config: PathBuf,
    /// Update all, including beyond the declared constraint.
    #[arg(long)]
    pub all: bool,
    /// Print what would change without writing.
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    #[arg(long)]
    pub concurrency: Option<usize>,
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct TuiArgs {
    /// Project directory to explore (default: current directory).
    pub path: Option<PathBuf>,
    /// Config file path.
    #[arg(long, default_value = ".dependable.toml")]
    pub config: PathBuf,
    /// How many directories deep to search for manifests.
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    /// Verbose logging. Suppressed while the UI owns the screen.
    #[arg(short, long)]
    pub verbose: bool,
}

impl Default for TuiArgs {
    /// The same defaults clap applies, for a bare `dependable`.
    fn default() -> Self {
        Self {
            path: None,
            config: PathBuf::from(".dependable.toml"),
            depth: 3,
            verbose: false,
        }
    }
}

/// Arguments for `dependable report`.
///
/// Deliberately narrower than [`CheckArgs`]: there is no `--format` (HTML *is*
/// the format; SARIF is `check --format sarif`) and no `--fail-on` (a report
/// describes what is there, and exiting non-zero is `check`'s job).
#[cfg(feature = "report")]
#[derive(Args)]
pub struct ReportArgs {
    /// Project directory to report on (default: current directory).
    pub path: Option<PathBuf>,
    /// Report on a single manifest file instead of discovering them.
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Config file path.
    #[arg(long, default_value = ".dependable.toml")]
    pub config: PathBuf,
    /// How many directories deep to search.
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    /// Skip vulnerability scanning.
    #[arg(long)]
    pub no_vuln: bool,
    /// Write the document here instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Suppress the progress bar and leave run warnings out of the document.
    #[arg(short, long)]
    pub quiet: bool,
    /// Verbose logging.
    #[arg(short, long)]
    pub verbose: bool,
}

/// Output format for the `list` command.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Format {
    Table,
    Json,
    Text,
}

/// Output format for the `check` command.
///
/// Deliberately separate from [`Format`]: `check` can emit SARIF and `list`
/// cannot. Sharing one enum would make clap advertise `sarif` in `list --help`,
/// where it does nothing, and force an "unsupported" arm into the `list`
/// renderer.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CheckFormat {
    Table,
    Json,
    Text,
    /// SARIF v2.1.0, for the GitHub Security tab and IDE problem panes.
    #[cfg(feature = "report")]
    Sarif,
}

/// Output format for the `tree` command.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum TreeFormat {
    /// cargo-tree-style ASCII tree (default).
    Tree,
    /// A JSON graph of nodes and edges (for tooling / IDEs).
    Json,
    /// Graphviz DOT for a visual graph (`… --format dot | dot -Tsvg`).
    Dot,
}

/// The result level that triggers a non-zero exit (for CI).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    None,
    Outdated,
    Vulnerable,
    Any,
}

impl FailOn {
    /// Parse from an environment-variable string (`DEPENDABLE_FAIL_ON`).
    #[must_use]
    pub fn from_env(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "none" => Some(FailOn::None),
            "outdated" => Some(FailOn::Outdated),
            "vulnerable" => Some(FailOn::Vulnerable),
            "any" => Some(FailOn::Any),
            _ => None,
        }
    }
}

/// When to write GitHub Actions annotations and the job summary.
///
/// These are side channels on **stderr** and `GITHUB_STEP_SUMMARY`, not an
/// output format: they compose with every `--format`, so there is deliberately
/// no `CheckFormat::Github` variant to choose between them.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum AnnotationMode {
    /// On exactly when `GITHUB_ACTIONS` is `true` (the default).
    #[default]
    Auto,
    /// Always on — how the behaviour is reproduced and debugged locally.
    Always,
    /// Off, including the job summary. The single off-switch for all GitHub
    /// side-channel output.
    Never,
}

/// Pre-release filtering mode, selectable via `--unstable` or `[global] unstable`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnstableFilter {
    /// Hide pre-releases (default).
    #[default]
    Exclude,
    /// Always consider pre-releases.
    IncludeAlways,
    /// Consider pre-releases only when the current version is a pre-release.
    IncludeIfCurrent,
}

impl From<UnstableFilter> for dependable_fetch::UnstableFilter {
    fn from(value: UnstableFilter) -> Self {
        match value {
            UnstableFilter::Exclude => dependable_fetch::UnstableFilter::Exclude,
            UnstableFilter::IncludeAlways => dependable_fetch::UnstableFilter::IncludeAlways,
            UnstableFilter::IncludeIfCurrent => dependable_fetch::UnstableFilter::IncludeIfCurrent,
        }
    }
}
