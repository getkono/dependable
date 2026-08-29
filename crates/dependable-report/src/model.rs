//! The neutral report model every renderer in this crate consumes.
//!
//! [`Report`] is the seam between the checker and the renderers: the CLI already
//! groups check results by manifest (its `output::ManifestReport`), and
//! [`ManifestResults`] mirrors that shape without depending on the CLI.

use std::path::PathBuf;

use dependable_core::{CheckResult, Ecosystem};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::ReportError;

/// Everything a renderer needs to produce a report for one project tree.
///
/// `#[non_exhaustive]`: construct via [`Report::new`] or [`Report::at`] so later
/// fields (policy outcomes, license data) don't break callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Report {
    /// The project root the report describes.
    pub root: PathBuf,
    /// When the report was generated.
    pub generated_at: OffsetDateTime,
    /// One entry per manifest found under [`Report::root`], in discovery order.
    pub manifests: Vec<ManifestResults>,
}

impl Report {
    /// An empty report for `root`, stamped with the current UTC time.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self::at(root, OffsetDateTime::now_utc())
    }

    /// An empty report for `root` with an injected timestamp.
    ///
    /// Rendering is otherwise a pure function of its input, so injecting the
    /// clock is what makes golden HTML and SARIF fixtures reproducible.
    #[must_use]
    pub fn at(root: PathBuf, generated_at: OffsetDateTime) -> Self {
        Self {
            root,
            generated_at,
            manifests: Vec::new(),
        }
    }

    /// Append one manifest's results, preserving order.
    pub fn push(&mut self, manifest: ManifestResults) {
        self.manifests.push(manifest);
    }

    /// [`Report::generated_at`] rendered as RFC 3339, the form both the HTML
    /// footer and SARIF's `invocation` timestamps expect.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Format`] if the timestamp cannot be formatted.
    #[must_use = "the formatted timestamp is the only output of this call"]
    pub fn generated_at_rfc3339(&self) -> Result<String, ReportError> {
        Ok(self.generated_at.format(&Rfc3339)?)
    }
}

/// The check results for a single manifest.
///
/// `#[non_exhaustive]`: construct via [`ManifestResults::new`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ManifestResults {
    /// Path to the manifest, as discovered.
    pub path: PathBuf,
    /// The ecosystem the manifest belongs to.
    pub ecosystem: Ecosystem,
    /// One result per declared dependency.
    pub results: Vec<CheckResult>,
}

impl ManifestResults {
    /// The results for one manifest.
    #[must_use]
    pub fn new(path: PathBuf, ecosystem: Ecosystem, results: Vec<CheckResult>) -> Self {
        Self {
            path,
            ecosystem,
            results,
        }
    }
}

#[cfg(test)]
mod tests {
    use dependable_core::{DependencyStatus, ManifestKind, parse};

    use super::*;

    /// 2023-11-14T22:13:20Z — a fixed instant, so the rendered form is a literal.
    const FIXED: i64 = 1_700_000_000;

    fn fixed_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(FIXED).expect("a valid unix timestamp")
    }

    /// `Item` is `#[non_exhaustive]` and has no constructor, so a real one is
    /// obtained the only way an external crate can: by parsing a manifest.
    /// That keeps the fixture honest — it is the same `Item` the checker emits.
    fn results(name: &str) -> Vec<CheckResult> {
        let manifest = format!("[dependencies]\n{name} = \"1.0.0\"\n");
        let parsed = parse(ManifestKind::CargoToml, &manifest).expect("parse the fixture manifest");
        parsed
            .items
            .into_iter()
            .map(|item| CheckResult::new(item, DependencyStatus::Local))
            .collect()
    }

    #[test]
    fn at_round_trips_the_injected_timestamp() {
        let report = Report::at(PathBuf::from("/proj"), fixed_time());

        assert_eq!(report.root, PathBuf::from("/proj"));
        assert_eq!(report.generated_at, fixed_time());
        assert!(report.manifests.is_empty());
    }

    #[test]
    fn an_injected_timestamp_renders_to_a_known_literal() {
        // The determinism guarantee the HTML and SARIF renderers build on.
        let report = Report::at(PathBuf::from("/proj"), fixed_time());

        assert_eq!(
            report.generated_at_rfc3339().expect("format the timestamp"),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn new_stamps_a_utc_timestamp() {
        let report = Report::new(PathBuf::from("/proj"));

        assert!(
            report.generated_at.offset().is_utc(),
            "reports are stamped in UTC so they read the same everywhere"
        );
    }

    #[test]
    fn push_accumulates_manifests_in_order() {
        let mut report = Report::at(PathBuf::from("/proj"), fixed_time());
        report.push(ManifestResults::new(
            PathBuf::from("/proj/Cargo.toml"),
            Ecosystem::Rust,
            results("serde"),
        ));
        report.push(ManifestResults::new(
            PathBuf::from("/proj/api/Cargo.toml"),
            Ecosystem::Rust,
            results("tokio"),
        ));

        let paths: Vec<_> = report.manifests.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            paths,
            [
                PathBuf::from("/proj/Cargo.toml").as_path(),
                PathBuf::from("/proj/api/Cargo.toml").as_path(),
            ]
        );
    }

    #[test]
    fn manifest_results_preserves_path_ecosystem_and_results() {
        let manifest = ManifestResults::new(
            PathBuf::from("/proj/Cargo.toml"),
            Ecosystem::Rust,
            results("serde"),
        );

        assert_eq!(manifest.path, PathBuf::from("/proj/Cargo.toml"));
        assert_eq!(manifest.ecosystem, Ecosystem::Rust);
        assert_eq!(manifest.results.len(), 1);
        assert_eq!(manifest.results[0].item.name, "serde");
    }
}
