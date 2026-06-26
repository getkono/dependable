//! Output rendering: table (default), JSON, and machine-readable text.

use std::path::PathBuf;

use dependable_fetch::{CheckResult, DependencyStatus, Ecosystem};

use crate::cli::Format;

pub mod json;
pub mod table;
pub mod text;

/// The check results for a single manifest.
pub struct ManifestReport {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,
    pub results: Vec<CheckResult>,
}

/// Aggregate status counts across one or more reports.
#[derive(Default)]
pub struct Summary {
    pub total: usize,
    pub up_to_date: usize,
    pub patch_available: usize,
    pub update_available: usize,
    pub outdated: usize,
    pub vulnerable: usize,
    pub error: usize,
    pub local: usize,
    pub git: usize,
}

impl Summary {
    /// Tally the statuses across `reports`.
    #[must_use]
    pub fn of(reports: &[ManifestReport]) -> Self {
        let mut s = Summary::default();
        for report in reports {
            for result in &report.results {
                s.total += 1;
                match result.status {
                    DependencyStatus::UpToDate => s.up_to_date += 1,
                    DependencyStatus::PatchAvailable => s.patch_available += 1,
                    DependencyStatus::UpdateAvailable => s.update_available += 1,
                    DependencyStatus::Outdated => s.outdated += 1,
                    DependencyStatus::Vulnerable => s.vulnerable += 1,
                    DependencyStatus::Error(_) => s.error += 1,
                    DependencyStatus::Local => s.local += 1,
                    DependencyStatus::Git => s.git += 1,
                    _ => {}
                }
            }
        }
        s
    }
}

/// Render `reports` in the requested `format`.
///
/// # Errors
/// Propagates serialization / IO errors from the chosen renderer.
pub fn render(format: Format, reports: &[ManifestReport], quiet: bool) -> anyhow::Result<()> {
    match format {
        Format::Table => table::render(reports, quiet),
        Format::Json => json::render(reports),
        Format::Text => text::render(reports),
    }
}

/// The version to display as "current": the locked version, else the declared
/// constraint, else a dash.
#[must_use]
pub fn current_display(result: &CheckResult) -> String {
    result
        .item
        .locked_version
        .clone()
        .or_else(|| {
            (!result.item.version_constraint.is_empty())
                .then(|| result.item.version_constraint.clone())
        })
        .unwrap_or_else(|| "—".to_string())
}

/// The version to display as "latest": the absolute latest, else the latest
/// compatible, else a dash.
#[must_use]
pub fn latest_display(result: &CheckResult) -> String {
    result
        .latest_available
        .clone()
        .or_else(|| result.latest_compatible.clone())
        .unwrap_or_else(|| "—".to_string())
}
