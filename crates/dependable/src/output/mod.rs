//! Output rendering: table (default), JSON, machine-readable text, and SARIF,
//! plus the GitHub Actions side channels in [`github`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use dependable_fetch::{CheckResult, DependencyStatus, Ecosystem};

use crate::cli::CheckFormat;

pub mod github;
pub mod json;
pub mod list;
#[cfg(feature = "report")]
pub mod sarif;
pub mod table;
pub mod text;
pub mod tree;

/// The check results for a single manifest.
pub struct ManifestReport {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,
    pub results: Vec<CheckResult>,
    /// The manifest whose `[workspace.dependencies]` supplied any inherited constraint.
    /// `None` outside a workspace.
    pub workspace_root: Option<PathBuf>,
}

/// Aggregate status counts across one or more reports.
///
/// # Per occurrence, not per package
/// Every status count — [`total`](Self::total) included — counts *declarations*,
/// not distinct packages. A crate that is outdated in three workspace members is
/// three entries here, because it is three edits to make, and because
/// `--fail-on` gates on results one at a time: a deduplicated rollup would
/// disagree with the exit code it sits beside.
///
/// [`unique_packages`](Self::unique_packages) is the dedup-aware number, and it
/// sits *beside* the status counts rather than replacing any of them.
#[derive(Default)]
pub struct Summary {
    /// How many manifests were rolled up. `1` for a single-project run.
    pub manifests: usize,
    /// Distinct `(ecosystem, name)` pairs across every report, counting only
    /// dependencies that have a registry to check. What a monorepo actually
    /// depends on, as opposed to how many times it says so.
    pub unique_packages: usize,
    pub total: usize,
    pub up_to_date: usize,
    pub patch_available: usize,
    pub update_available: usize,
    pub outdated: usize,
    pub vulnerable: usize,
    pub error: usize,
    pub local: usize,
    pub git: usize,
    /// [`DependencyStatus::Undetermined`] count: declarations whose currency this
    /// run could not establish. Kept apart from [`local`](Self::local) and
    /// [`git`](Self::git), which are deliberately skipped and therefore clean,
    /// because these were not skipped on purpose — nothing was learned about them.
    pub undetermined: usize,
}

impl Summary {
    /// Tally the statuses across `reports`.
    #[must_use]
    pub fn of(reports: &[ManifestReport]) -> Self {
        let mut s = Summary::default();
        let mut unique: HashSet<(Ecosystem, &str)> = HashSet::new();
        for report in reports {
            for result in &report.results {
                if result.item.is_checkable() {
                    unique.insert((report.ecosystem, result.item.name.as_str()));
                }
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
                    DependencyStatus::Undetermined => s.undetermined += 1,
                    _ => {}
                }
            }
        }
        s.manifests = reports.len();
        s.unique_packages = unique.len();
        s
    }
}

/// Render `reports` in the requested `format`.
///
/// # Errors
/// Propagates serialization / IO errors from the chosen renderer.
pub fn render(format: CheckFormat, reports: &[ManifestReport], quiet: bool) -> anyhow::Result<()> {
    match format {
        CheckFormat::Table => table::render(reports, quiet),
        CheckFormat::Json => json::render(reports),
        CheckFormat::Text => text::render(reports),
        // `quiet` is ignored, exactly as it is for JSON: a machine-readable
        // document is either emitted whole or not at all.
        #[cfg(feature = "report")]
        CheckFormat::Sarif => sarif::render(reports),
    }
}

/// A path with `/` separators, whatever the platform uses.
///
/// Two callers need it and need it to agree: the machine-readable formats, which
/// are consumed by tooling that joins these paths with paths from elsewhere (git,
/// a config file, another tool's output), all of which speak `/`; and
/// `--manifest-glob`, whose patterns a user writes with `/` on every platform. A
/// Windows run must not produce a differently-shaped document, nor need a
/// differently-spelled glob.
#[must_use]
pub fn posix(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
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

#[cfg(test)]
mod tests {
    use dependable_fetch::core::parse;
    use dependable_fetch::{Item, ManifestKind};

    use super::*;

    /// A real [`Item`], obtained the only way another crate can — `Item` is
    /// `#[non_exhaustive]` and has no constructor, so it is parsed out of a
    /// manifest.
    fn item(declaration: &str) -> Item {
        parse(
            ManifestKind::CargoToml,
            &format!("[dependencies]\n{declaration}\n"),
        )
        .expect("parse the fixture manifest")
        .items
        .into_iter()
        .next()
        .expect("one dependency")
    }

    fn report(path: &str, declarations: &[(&str, DependencyStatus)]) -> ManifestReport {
        ManifestReport {
            path: PathBuf::from(path),
            ecosystem: Ecosystem::Rust,
            results: declarations
                .iter()
                .map(|(declaration, status)| {
                    dependable_fetch::CheckResult::new(item(declaration), status.clone())
                })
                .collect(),
            workspace_root: None,
        }
    }

    #[test]
    fn the_rollup_spans_every_manifest() {
        let reports = [
            report(
                "a/Cargo.toml",
                &[("serde = \"1\"", DependencyStatus::Outdated)],
            ),
            report(
                "b/Cargo.toml",
                &[("serde = \"1\"", DependencyStatus::Outdated)],
            ),
            report(
                "c/Cargo.toml",
                &[("tokio = \"1\"", DependencyStatus::UpToDate)],
            ),
        ];
        let summary = Summary::of(&reports);

        assert_eq!(summary.manifests, 3);
        assert_eq!(summary.unique_packages, 2, "serde is one package, not two");
        assert_eq!(summary.total, 3, "…but three declarations");
        assert_eq!(
            summary.outdated, 2,
            "an outdated crate in two members is two edits, and stays two here"
        );
        assert_eq!(summary.up_to_date, 1);
    }

    #[test]
    fn a_package_with_no_registry_is_not_a_unique_package() {
        let reports = [report(
            "Cargo.toml",
            &[
                ("serde = \"1\"", DependencyStatus::UpToDate),
                ("local = { path = \"../local\" }", DependencyStatus::Local),
                (
                    "gitdep = { git = \"https://example.com/g\" }",
                    DependencyStatus::Git,
                ),
            ],
        )];
        let summary = Summary::of(&reports);

        assert_eq!(summary.manifests, 1);
        assert_eq!(summary.unique_packages, 1, "only serde can be looked up");
        assert_eq!(summary.total, 3);
        assert_eq!(summary.local + summary.git, 2);
    }

    #[test]
    fn an_empty_run_rolls_up_to_nothing() {
        let summary = Summary::of(&[]);
        assert_eq!(summary.manifests, 0);
        assert_eq!(summary.unique_packages, 0);
        assert_eq!(summary.total, 0);
    }
}
