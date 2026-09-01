//! Aggregate counts over a whole [`Report`].
//!
//! This is a separate module from [`model`](crate::model) on purpose: the numbers
//! are wanted by more than the HTML renderer (a CI job summary needs them without
//! pulling in a template engine), and [`Report::summary`] is added here through an
//! `impl Report` block rather than by editing the model.

use std::collections::BTreeSet;

use dependable_core::result::{Advisory, Severity};
use dependable_core::{DependencyStatus, Ecosystem};

use crate::model::Report;

/// Aggregate counts across every manifest in a [`Report`].
///
/// `#[non_exhaustive]`: obtain one from [`Report::summary`] so later counters
/// (licenses, policy outcomes) don't break callers.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Summary {
    /// How many manifests the report covers.
    pub manifests: usize,
    /// How many of [`Self::manifests`] had the file that *is* their dependency list
    /// go unread — see [`crate::model::ManifestResults::dependencies_unread`].
    ///
    /// Nonzero means the counts below are drawn from fewer projects than
    /// [`Self::manifests`] names, and that the ones missing contributed no rows
    /// because none could be read — not because they had none. A renderer that
    /// ignores this presents a project nothing was established about exactly as it
    /// presents a clean one.
    pub manifests_unread: usize,
    /// Every declared dependency across every manifest.
    pub total: usize,
    /// Dependencies whose currency this run actually established:
    /// [`Self::total`] minus the path and git dependencies, and minus the ones
    /// whose version could not be read at all. The only honest denominator for an
    /// "up to date" percentage — an
    /// [`Undetermined`](DependencyStatus::Undetermined) dependency is neither up to
    /// date nor behind, so counting it below the line would quietly depress the
    /// percentage on every parent-inheriting POM.
    pub checkable: usize,
    /// [`DependencyStatus::UpToDate`] count.
    pub up_to_date: usize,
    /// [`DependencyStatus::PatchAvailable`] count.
    pub patch_available: usize,
    /// [`DependencyStatus::UpdateAvailable`] count.
    pub update_available: usize,
    /// [`DependencyStatus::Outdated`] count.
    pub outdated: usize,
    /// [`DependencyStatus::Vulnerable`] count.
    pub vulnerable: usize,
    /// [`DependencyStatus::Error`] count.
    pub error: usize,
    /// [`DependencyStatus::Local`] count.
    pub local: usize,
    /// [`DependencyStatus::Git`] count.
    pub git: usize,
    /// [`DependencyStatus::Undetermined`] count: dependencies this run could not
    /// establish anything about. Excluded from [`Self::checkable`], and kept apart
    /// from [`Self::local`] and [`Self::git`], which were skipped deliberately.
    pub undetermined: usize,
    /// Distinct `(dependency, advisory ID)` pairs — one per row a vulnerability
    /// table would print. The same advisory affecting three packages counts three
    /// times here and once in [`Self::distinct_advisories`].
    pub advisory_instances: usize,
    /// Distinct advisory IDs across the whole tree.
    pub distinct_advisories: usize,
    /// How many of [`Self::distinct_advisories`] the publisher has withdrawn.
    pub withdrawn_advisories: usize,
    /// Advisory instances bucketed by severity band.
    pub severity: SeverityCounts,
    /// The highest computed CVSS base score anywhere in the tree, if anything is
    /// scored. Deliberately not `0.0` when nothing is.
    pub max_cvss: Option<f64>,
    /// Per-ecosystem totals, sorted by descending total then display name.
    ///
    /// A `Vec` and not a map: [`Ecosystem`] has no `Ord`, so it cannot key a
    /// `BTreeMap`, and a `HashMap` would not iterate deterministically.
    pub by_ecosystem: Vec<EcosystemSummary>,
}

/// Advisory instances bucketed by severity band.
///
/// Named fields rather than a map keyed by [`Severity`]: the band vocabulary is
/// fixed by the CVSS specification (which is why `Severity` is not
/// `#[non_exhaustive]`), so an exhaustive match is correct and stays correct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    /// CVSS 9.0–10.0.
    pub critical: usize,
    /// CVSS 7.0–8.9.
    pub high: usize,
    /// CVSS 4.0–6.9.
    pub medium: usize,
    /// CVSS 0.1–3.9.
    pub low: usize,
    /// A published band of exactly "none".
    pub none: usize,
    /// Advisories carrying no usable rating at all — *not* the same as
    /// [`Self::none`].
    pub unrated: usize,
}

impl SeverityCounts {
    /// Bucket one advisory band; `None` means unrated.
    fn record(&mut self, band: Option<Severity>) {
        match band {
            Some(Severity::Critical) => self.critical += 1,
            Some(Severity::High) => self.high += 1,
            Some(Severity::Medium) => self.medium += 1,
            Some(Severity::Low) => self.low += 1,
            Some(Severity::None) => self.none += 1,
            None => self.unrated += 1,
        }
    }

    /// Every band that carries a rating (everything but [`Self::unrated`]).
    #[must_use]
    pub fn rated(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.none
    }
}

/// One ecosystem's slice of the tree.
///
/// `#[non_exhaustive]`: read these from [`Summary::by_ecosystem`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EcosystemSummary {
    /// The ecosystem being summarized.
    pub ecosystem: Ecosystem,
    /// Every dependency declared in this ecosystem's manifests.
    pub total: usize,
    /// Dependencies already on the best available version.
    pub up_to_date: usize,
    /// Dependencies with any kind of update available.
    pub outdated: usize,
    /// Dependencies with a known advisory against the current version.
    pub vulnerable: usize,
    /// Path, git, and errored dependencies — everything with no version verdict.
    pub other: usize,
}

impl EcosystemSummary {
    /// An empty tally for `ecosystem`.
    fn new(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            total: 0,
            up_to_date: 0,
            outdated: 0,
            vulnerable: 0,
            other: 0,
        }
    }

    /// Fold one dependency's status in.
    fn record(&mut self, status: &DependencyStatus) {
        self.total += 1;
        match status {
            DependencyStatus::UpToDate => self.up_to_date += 1,
            DependencyStatus::PatchAvailable
            | DependencyStatus::UpdateAvailable
            | DependencyStatus::Outdated => self.outdated += 1,
            DependencyStatus::Vulnerable => self.vulnerable += 1,
            _ => self.other += 1,
        }
    }
}

impl Summary {
    /// The share of checkable dependencies that are up to date, in `0.0..=100.0`.
    ///
    /// `None` when nothing is checkable, so a renderer can print "n/a" rather
    /// than dividing by zero and emitting `NaN%`.
    #[must_use]
    pub fn up_to_date_percent(&self) -> Option<f64> {
        if self.checkable == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some((self.up_to_date as f64 / self.checkable as f64) * 100.0)
    }

    /// Whether anything in the tree has an advisory against it.
    #[must_use]
    pub fn has_advisories(&self) -> bool {
        self.advisory_instances > 0
    }
}

impl Report {
    /// Aggregate counts over every manifest in this report.
    ///
    /// Pure and allocation-light: one pass over the results, plus a set of
    /// advisory IDs for the distinct counts.
    #[must_use = "computing a summary has no other effect"]
    pub fn summary(&self) -> Summary {
        let mut summary = Summary {
            manifests: self.manifests.len(),
            ..Summary::default()
        };
        let mut seen_advisories: BTreeSet<&str> = BTreeSet::new();
        let mut withdrawn: BTreeSet<&str> = BTreeSet::new();
        let mut by_ecosystem: Vec<EcosystemSummary> = Vec::new();

        for manifest in &self.manifests {
            if manifest.dependencies_unread {
                summary.manifests_unread += 1;
            }
            let slot = by_ecosystem
                .iter()
                .position(|e| e.ecosystem == manifest.ecosystem)
                .unwrap_or_else(|| {
                    by_ecosystem.push(EcosystemSummary::new(manifest.ecosystem));
                    by_ecosystem.len() - 1
                });

            for result in &manifest.results {
                summary.total += 1;
                by_ecosystem[slot].record(&result.status);
                match &result.status {
                    DependencyStatus::UpToDate => summary.up_to_date += 1,
                    DependencyStatus::PatchAvailable => summary.patch_available += 1,
                    DependencyStatus::UpdateAvailable => summary.update_available += 1,
                    DependencyStatus::Outdated => summary.outdated += 1,
                    DependencyStatus::Vulnerable => summary.vulnerable += 1,
                    DependencyStatus::Error(_) => summary.error += 1,
                    DependencyStatus::Local => summary.local += 1,
                    DependencyStatus::Git => summary.git += 1,
                    DependencyStatus::Undetermined => summary.undetermined += 1,
                    // `DependencyStatus` is `#[non_exhaustive]`; an unrecognized
                    // status still counts toward the total and nothing else.
                    _ => {}
                }

                // `current_vulnerabilities` is the authoritative ID list;
                // `advisories` is only its enrichment, so an unenriched ID still
                // has to be counted — as unrated.
                let mut ids_here: BTreeSet<&str> = BTreeSet::new();
                for id in &result.current_vulnerabilities {
                    if !ids_here.insert(id.as_str()) {
                        continue;
                    }
                    summary.advisory_instances += 1;
                    seen_advisories.insert(id.as_str());
                    let advisory = result.advisory(id);
                    summary
                        .severity
                        .record(advisory.and_then(|a| a.severity.band));
                    if advisory.is_some_and(Advisory::is_withdrawn) {
                        withdrawn.insert(id.as_str());
                    }
                }
                if let Some(score) = result.max_cvss() {
                    summary.max_cvss =
                        Some(summary.max_cvss.map_or(score, |best: f64| best.max(score)));
                }
            }
        }

        summary.checkable = summary.total - summary.local - summary.git - summary.undetermined;
        summary.distinct_advisories = seen_advisories.len();
        summary.withdrawn_advisories = withdrawn.len();
        // The same key the HTML pie chart sorts its slices by, so the chart and
        // the table can never disagree about order.
        by_ecosystem.sort_by(|a, b| {
            b.total
                .cmp(&a.total)
                .then_with(|| a.ecosystem.display_name().cmp(b.ecosystem.display_name()))
        });
        summary.by_ecosystem = by_ecosystem;
        summary
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use dependable_core::result::AdvisorySeverity;
    use dependable_core::{CheckResult, ManifestKind, parse};

    use super::*;
    use crate::model::ManifestResults;

    /// `Item` has no public constructor, so real ones are obtained the only way
    /// an external crate can: by parsing a manifest.
    fn results(specs: &[(&str, DependencyStatus)]) -> Vec<CheckResult> {
        specs
            .iter()
            .map(|(name, status)| {
                let manifest = format!("[dependencies]\n{name} = \"1.0.0\"\n");
                let parsed = parse(ManifestKind::CargoToml, &manifest).expect("parse the fixture");
                let item = parsed.items.into_iter().next().expect("one item");
                CheckResult::new(item, status.clone())
            })
            .collect()
    }

    fn report(manifests: Vec<ManifestResults>) -> Report {
        let mut report = Report::new(PathBuf::from("/proj"));
        for manifest in manifests {
            report.push(manifest);
        }
        report
    }

    /// A manifest that contributed no rows because none could be read is not the
    /// same as one that contributed none because it declares none, and the counts
    /// alone cannot tell them apart — both are zero. Only this counter can, and a
    /// renderer that has it can say so however quiet the run was.
    #[test]
    fn an_unread_manifest_is_counted_apart_from_an_empty_one() {
        let unread = report(vec![
            ManifestResults::new(
                PathBuf::from("a/Package.swift"),
                Ecosystem::Swift,
                Vec::new(),
            )
            .with_dependencies_unread(true),
        ]);
        let empty = report(vec![ManifestResults::new(
            PathBuf::from("b/Package.swift"),
            Ecosystem::Swift,
            Vec::new(),
        )]);

        assert_eq!(unread.summary().manifests_unread, 1);
        assert_eq!(empty.summary().manifests_unread, 0);
        assert_eq!(
            unread.summary().total,
            empty.summary().total,
            "the dependency counts are identical, which is exactly why the caveat has to be \
             carried separately"
        );
    }

    #[test]
    fn counts_every_status_and_only_counts_checkable_once() {
        let report = report(vec![ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results(&[
                ("serde", DependencyStatus::UpToDate),
                ("tokio", DependencyStatus::PatchAvailable),
                ("time", DependencyStatus::UpdateAvailable),
                ("regex", DependencyStatus::Outdated),
                ("openssl", DependencyStatus::Vulnerable),
                ("broken", DependencyStatus::Error("502".into())),
                ("mine", DependencyStatus::Local),
                ("forked", DependencyStatus::Git),
                ("unread", DependencyStatus::Undetermined),
            ]),
        )]);

        let summary = report.summary();

        assert_eq!(summary.manifests, 1);
        assert_eq!(summary.total, 9);
        assert_eq!(summary.up_to_date, 1);
        assert_eq!(summary.patch_available, 1);
        assert_eq!(summary.update_available, 1);
        assert_eq!(summary.outdated, 1);
        assert_eq!(summary.vulnerable, 1);
        assert_eq!(summary.error, 1);
        assert_eq!(summary.local, 1);
        assert_eq!(summary.git, 1);
        assert_eq!(summary.undetermined, 1);
        // Path and git dependencies have no registry verdict, and an undetermined
        // one produced none, so none of the three is part of the denominator — an
        // unread version is neither up to date nor behind, and counting it below
        // the line would depress the percentage on every parent-inheriting POM.
        assert_eq!(summary.checkable, 6);
    }

    /// A run that read nothing is not a run that is 100% up to date.
    #[test]
    fn an_undetermined_dependency_is_outside_the_up_to_date_denominator() {
        let report = report(vec![ManifestResults::new(
            PathBuf::from("pom.xml"),
            Ecosystem::Jvm,
            results(&[
                ("serde", DependencyStatus::UpToDate),
                ("tokio", DependencyStatus::Undetermined),
            ]),
        )]);

        let summary = report.summary();

        assert_eq!(summary.checkable, 1);
        assert_eq!(summary.up_to_date_percent(), Some(100.0));
    }

    #[test]
    fn up_to_date_percent_is_none_when_nothing_is_checkable() {
        let report = report(vec![ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results(&[
                ("mine", DependencyStatus::Local),
                ("forked", DependencyStatus::Git),
            ]),
        )]);

        let summary = report.summary();

        assert_eq!(summary.checkable, 0);
        assert_eq!(summary.up_to_date_percent(), None);
    }

    #[test]
    fn up_to_date_percent_divides_by_the_checkable_count() {
        let report = report(vec![ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results(&[
                ("serde", DependencyStatus::UpToDate),
                ("tokio", DependencyStatus::Outdated),
                ("mine", DependencyStatus::Local),
            ]),
        )]);

        let percent = report.summary().up_to_date_percent().expect("a percentage");

        assert!(
            (percent - 50.0).abs() < f64::EPSILON,
            "1 of 2 checkable, not 1 of 3: {percent}"
        );
    }

    #[test]
    fn an_empty_report_summarizes_to_zero() {
        let summary = report(Vec::new()).summary();

        assert_eq!(summary, Summary::default());
        assert!(!summary.has_advisories());
        assert!(summary.by_ecosystem.is_empty());
    }

    #[test]
    fn advisory_instances_count_pairs_and_distinct_counts_ids() {
        let mut results = results(&[
            ("openssl", DependencyStatus::Vulnerable),
            ("tokio", DependencyStatus::Vulnerable),
        ]);
        results[0].current_vulnerabilities = vec!["RUSTSEC-1".into(), "RUSTSEC-2".into()];
        results[0].advisories = vec![
            Advisory::new("RUSTSEC-1").with_severity(AdvisorySeverity::from_score(9.8)),
            Advisory::new("RUSTSEC-2"),
        ];
        // The same advisory again, against a second package.
        results[1].current_vulnerabilities = vec!["RUSTSEC-1".into()];
        results[1].advisories =
            vec![Advisory::new("RUSTSEC-1").with_severity(AdvisorySeverity::from_score(9.8))];
        let report = report(vec![ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results,
        )]);

        let summary = report.summary();

        assert_eq!(summary.advisory_instances, 3, "three (dep, advisory) rows");
        assert_eq!(summary.distinct_advisories, 2, "two distinct IDs");
        assert_eq!(summary.severity.critical, 2);
        assert_eq!(summary.severity.unrated, 1, "RUSTSEC-2 carries no rating");
        assert_eq!(summary.severity.rated(), 2);
        assert_eq!(summary.max_cvss, Some(9.8));
    }

    #[test]
    fn an_unenriched_advisory_id_still_counts_as_unrated() {
        let mut results = results(&[("openssl", DependencyStatus::Vulnerable)]);
        results[0].current_vulnerabilities = vec!["GHSA-xxxx".into()];
        let report = report(vec![ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results,
        )]);

        let summary = report.summary();

        assert_eq!(summary.advisory_instances, 1);
        assert_eq!(summary.severity.unrated, 1);
        assert_eq!(summary.max_cvss, None, "unrated is not a score of zero");
    }

    #[test]
    fn withdrawn_advisories_are_counted_once_per_id() {
        let mut results = results(&[("openssl", DependencyStatus::Vulnerable)]);
        results[0].current_vulnerabilities = vec!["RUSTSEC-1".into()];
        let mut advisory = Advisory::new("RUSTSEC-1");
        advisory.withdrawn = Some("2024-01-01T00:00:00Z".into());
        results[0].advisories = vec![advisory];
        let report = report(vec![ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results,
        )]);

        assert_eq!(report.summary().withdrawn_advisories, 1);
    }

    #[test]
    fn by_ecosystem_sorts_by_descending_total_then_name() {
        let report = report(vec![
            ManifestResults::new(
                PathBuf::from("package.json"),
                Ecosystem::Npm,
                results(&[("left-pad", DependencyStatus::UpToDate)]),
            ),
            ManifestResults::new(
                PathBuf::from("Cargo.toml"),
                Ecosystem::Rust,
                results(&[
                    ("serde", DependencyStatus::UpToDate),
                    ("tokio", DependencyStatus::Outdated),
                    ("openssl", DependencyStatus::Vulnerable),
                ]),
            ),
        ]);

        let summary = report.summary();

        let order: Vec<_> = summary
            .by_ecosystem
            .iter()
            .map(|e| e.ecosystem.display_name())
            .collect();
        assert_eq!(order, ["Rust", "npm"], "biggest first, ties by name");
        assert_eq!(summary.by_ecosystem[0].total, 3);
        assert_eq!(summary.by_ecosystem[0].up_to_date, 1);
        assert_eq!(summary.by_ecosystem[0].outdated, 1);
        assert_eq!(summary.by_ecosystem[0].vulnerable, 1);
    }

    #[test]
    fn two_manifests_in_one_ecosystem_share_a_tally() {
        let report = report(vec![
            ManifestResults::new(
                PathBuf::from("Cargo.toml"),
                Ecosystem::Rust,
                results(&[("serde", DependencyStatus::UpToDate)]),
            ),
            ManifestResults::new(
                PathBuf::from("api/Cargo.toml"),
                Ecosystem::Rust,
                results(&[("tokio", DependencyStatus::Local)]),
            ),
        ]);

        let summary = report.summary();

        assert_eq!(summary.by_ecosystem.len(), 1);
        assert_eq!(summary.by_ecosystem[0].total, 2);
        assert_eq!(summary.by_ecosystem[0].other, 1);
    }
}
