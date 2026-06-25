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
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Check dependencies against the registry and OSV.
    Check(CheckArgs),
    /// List discovered dependencies without checking versions.
    List(ListArgs),
    /// Update versions in place to the latest compatible.
    Fix(FixArgs),
}

impl Cli {
    /// Whether verbose logging was requested on the chosen subcommand.
    #[must_use]
    pub fn verbose(&self) -> bool {
        match &self.command {
            Command::Check(args) => args.verbose,
            Command::List(args) => args.verbose,
            Command::Fix(args) => args.verbose,
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
    /// Config file path.
    #[arg(long, default_value = ".dependable.toml")]
    pub config: PathBuf,
    /// Pre-release filter (reserved; only `exclude` acts in V1).
    #[arg(long, value_enum)]
    pub unstable: Option<UnstableFilter>,
    /// Ignore `Cargo.lock`.
    #[arg(long)]
    pub no_lock_file: bool,
    /// Skip vulnerability scanning.
    #[arg(long)]
    pub no_vuln: bool,
    /// Include GHSA advisories in the vulnerability scan.
    #[arg(long)]
    pub include_ghsa: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// Exit non-zero when results match this level.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    pub fail_on: FailOn,
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
    pub path: Option<PathBuf>,
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct FixArgs {
    pub path: Option<PathBuf>,
    #[arg(long)]
    pub manifest: Option<PathBuf>,
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

/// Output format.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Format {
    Table,
    Json,
    Text,
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

/// Pre-release filtering mode (reserved for full implementation).
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum UnstableFilter {
    Exclude,
    IncludeAlways,
    IncludeIfCurrent,
}
