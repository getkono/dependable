//! The data the TUI renders: discovered projects and per-package lookups.

use std::collections::HashMap;
use std::path::PathBuf;

use dependable_fetch::{
    DependencyGraph, DependencyStatus, Ecosystem, GraphSource, PackageMetadata,
};

/// One discovered project and its dependency graph.
#[derive(Debug, Clone)]
pub struct Project {
    /// Path to the manifest that declares the project.
    pub manifest: PathBuf,
    /// How the manifest is shown in the tree (repository-relative where possible).
    pub label: String,
    /// The ecosystem the manifest belongs to.
    pub ecosystem: Ecosystem,
    /// The resolved (or shallow) dependency graph.
    pub graph: DependencyGraph,
    /// Where the graph's edges came from, so the UI can say why a tree stops.
    pub source: GraphSource,
}

impl Project {
    /// The caveat to show about this project's graph, if any.
    ///
    /// A shallow graph is not a graph with no edges, and the difference matters:
    /// the user must not read "no dependencies" where we mean "we cannot tell".
    #[must_use]
    pub fn caveat(&self) -> Option<&'static str> {
        match self.source {
            GraphSource::Lockfile => None,
            GraphSource::Manifests => {
                Some("no lockfile found — showing directly declared dependencies only")
            }
            GraphSource::Unsupported => Some(
                "this ecosystem's lockfile records no dependency edges — \
                 showing directly declared dependencies only",
            ),
            // `GraphSource` is `#[non_exhaustive]`; a future source is unknown to us.
            _ => Some("the dependency graph may be incomplete"),
        }
    }
}

/// What is known about one package, fetched lazily when it is selected.
#[derive(Debug, Clone, Default)]
pub enum PackageData {
    /// Nothing has been requested yet.
    #[default]
    Unloaded,
    /// A request is in flight.
    Loading,
    /// The lookup succeeded. Any field may still be absent — see [`PackageFacts`].
    Ready(Box<PackageFacts>),
    /// The lookup failed; the message is shown in place of the data.
    Failed(String),
}

/// Everything the detail pane shows about one package.
#[derive(Debug, Clone, Default)]
pub struct PackageFacts {
    /// Public metadata, or `None` when the registry publishes none.
    pub metadata: Option<PackageMetadata>,
    /// The newest version the registry offers.
    pub latest: Option<String>,
    /// How the resolved version compares to what is available.
    pub status: Option<DependencyStatus>,
    /// OSV advisory IDs affecting the resolved version.
    pub vulnerabilities: Vec<String>,
    /// Non-fatal notes — a skipped vulnerability scan, a registry warning.
    pub warnings: Vec<String>,
}

/// Identifies a package across projects: the same crate in two workspaces is the
/// same lookup, so it is fetched and cached once.
pub type PackageKey = (Ecosystem, String, String);

/// Lazily-populated per-package lookups, keyed independently of the graph so that
/// revisiting a package is instant and expanding a subtree costs nothing.
pub type PackageStore = HashMap<PackageKey, PackageData>;

/// The key for a package at `version` in `ecosystem`.
#[must_use]
pub fn key(ecosystem: Ecosystem, name: &str, version: &str) -> PackageKey {
    (ecosystem, name.to_owned(), version.to_owned())
}

/// Format an RFC 3339 timestamp as an approximate age (`3 months ago`).
///
/// Returns the input unchanged when it cannot be parsed, because showing the raw
/// timestamp is more useful than showing nothing.
#[must_use]
pub fn relative_age(timestamp: &str) -> String {
    let Ok(then) = timestamp.parse::<jiff::Timestamp>() else {
        return timestamp.to_owned();
    };
    // Epoch seconds, not a `Span`: a span normalizes into calendar units, so its
    // hours component is the remainder after whole days, not the elapsed hours.
    const DAY: i64 = 24 * 60 * 60;
    let days = (jiff::Timestamp::now().as_second() - then.as_second()) / DAY;
    match days {
        d if d < 0 => timestamp.to_owned(),
        0 => "today".to_owned(),
        1 => "yesterday".to_owned(),
        d if d < 30 => format!("{d} days ago"),
        d if d < 365 => plural(d / 30, "month"),
        d => plural(d / 365, "year"),
    }
}

/// `1 month ago` / `4 months ago`.
fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{n} {unit}s ago")
    }
}

/// Format a download count compactly (`5.0M`, `12.3k`).
#[must_use]
pub fn compact_count(n: u64) -> String {
    match n {
        n if n >= 1_000_000_000 => format!("{:.1}B", n as f64 / 1_000_000_000.0),
        n if n >= 1_000_000 => format!("{:.1}M", n as f64 / 1_000_000.0),
        n if n >= 1_000 => format!("{:.1}k", n as f64 / 1_000.0),
        n => n.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_counts_read_at_a_glance() {
        assert_eq!(compact_count(42), "42");
        assert_eq!(compact_count(12_345), "12.3k");
        assert_eq!(compact_count(5_000_000), "5.0M");
        assert_eq!(compact_count(2_500_000_000), "2.5B");
    }

    #[test]
    fn an_unparseable_timestamp_is_shown_verbatim() {
        assert_eq!(relative_age("not a date"), "not a date");
    }

    #[test]
    fn a_recent_timestamp_reads_as_days() {
        let two_days_ago = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(48);
        assert_eq!(relative_age(&two_days_ago.to_string()), "2 days ago");
    }

    #[test]
    fn older_timestamps_round_to_months_and_years() {
        let now = jiff::Timestamp::now();
        let months = now - jiff::SignedDuration::from_hours(24 * 70);
        assert_eq!(relative_age(&months.to_string()), "2 months ago");
        let year = now - jiff::SignedDuration::from_hours(24 * 400);
        assert_eq!(relative_age(&year.to_string()), "1 year ago");
    }
}
