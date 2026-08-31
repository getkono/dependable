//! The output of the version checker for a single dependency, plus the advisory
//! model the vulnerability data is reported through.
//!
//! The advisory types are plain data — strings, numbers, vectors, and fieldless
//! enums. They live here rather than in the fetch layer because [`CheckResult`]
//! carries them and `dependable-fetch` depends on this crate, not the other way
//! round; parsing OSV responses and computing CVSS scores stays in the fetch
//! layer, so this module remains IO-free and async-free.

use std::collections::HashMap;

use crate::item::Item;
use crate::semver::Evaluation;

/// The result of checking one dependency against the registry + OSV.
///
/// `#[non_exhaustive]`: construct via [`CheckResult::new`] or
/// [`CheckResult::from_evaluation`] so future fields don't break callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CheckResult {
    /// The dependency this result describes.
    pub item: Item,
    /// The classified status of the dependency.
    pub status: DependencyStatus,
    /// Best version satisfying the declared constraint.
    pub latest_compatible: Option<String>,
    /// Absolute latest available version (may be outside the constraint).
    pub latest_available: Option<String>,
    /// Whether a patch-level update exists within the constraint.
    pub patch_available: bool,
    /// Vulnerability IDs affecting the current/locked version.
    pub current_vulnerabilities: Vec<String>,
    /// All vulnerabilities by version, for "upgrading fixes N issues" reporting.
    pub all_vulnerabilities: HashMap<String, Vec<String>>,
    /// Enriched advisory records for [`Self::current_vulnerabilities`].
    ///
    /// Empty unless advisory enrichment was requested — a plain check leaves it
    /// so. `current_vulnerabilities` stays the authoritative ID list; this is its
    /// enrichment, and an ID with no matching record here simply was not enriched.
    pub advisories: Vec<Advisory>,
}

impl CheckResult {
    /// A bare result carrying only an item and a status (the `Local`/`Git`/`Error`
    /// cases, where no version data is available).
    #[must_use]
    pub fn new(item: Item, status: DependencyStatus) -> Self {
        Self {
            item,
            status,
            latest_compatible: None,
            latest_available: None,
            patch_available: false,
            current_vulnerabilities: Vec::new(),
            all_vulnerabilities: HashMap::new(),
            advisories: Vec::new(),
        }
    }

    /// Build a result from a registry [`Evaluation`]. Vulnerability fields start
    /// empty; the fetch layer fills them after querying OSV.
    #[must_use]
    pub fn from_evaluation(item: Item, eval: Evaluation) -> Self {
        Self {
            item,
            status: eval.status,
            latest_compatible: eval.latest_compatible,
            latest_available: eval.latest_available,
            patch_available: eval.patch_available,
            current_vulnerabilities: Vec::new(),
            all_vulnerabilities: HashMap::new(),
            advisories: Vec::new(),
        }
    }

    /// The highest CVSS base score across the enriched advisories, if any carries
    /// a computed score. `None` when nothing was enriched or every advisory is
    /// unrated — which is deliberately *not* the same as a score of `0.0`.
    #[must_use]
    pub fn max_cvss(&self) -> Option<f64> {
        Advisory::max_cvss(&self.advisories)
    }

    /// The highest severity band across the enriched advisories, if any is rated.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        Advisory::max_severity(&self.advisories)
    }

    /// The enriched advisory with this ID, if it was fetched.
    ///
    /// A consumer reporting one row per `(dependency, advisory ID)` walks
    /// [`Self::current_vulnerabilities`] and looks each ID up here, falling back
    /// to the bare ID when no record is present.
    #[must_use]
    pub fn advisory(&self, id: &str) -> Option<&Advisory> {
        self.advisories.iter().find(|a| a.id == id)
    }
}

/// The status of a single dependency.
///
/// `#[non_exhaustive]`: match with a wildcard arm so new statuses are additive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DependencyStatus {
    UpToDate,
    PatchAvailable,
    UpdateAvailable,
    Outdated,
    Vulnerable,
    Error(String),
    Local,
    Git,
}

impl DependencyStatus {
    /// A short human-readable label.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            DependencyStatus::UpToDate => "up to date",
            DependencyStatus::PatchAvailable => "patch available",
            DependencyStatus::UpdateAvailable => "update available",
            DependencyStatus::Outdated => "outdated",
            DependencyStatus::Vulnerable => "vulnerable",
            DependencyStatus::Error(_) => "error",
            DependencyStatus::Local => "local",
            DependencyStatus::Git => "git",
        }
    }

    /// A stable uppercase token for machine-readable output.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            DependencyStatus::UpToDate => "OK",
            DependencyStatus::PatchAvailable => "PATCH",
            DependencyStatus::UpdateAvailable => "UPDATE",
            DependencyStatus::Outdated => "OUTDATED",
            DependencyStatus::Vulnerable => "VULN",
            DependencyStatus::Error(_) => "ERROR",
            DependencyStatus::Local => "LOCAL",
            DependencyStatus::Git => "GIT",
        }
    }
}

/// A CVSS severity band.
///
/// The derived `Ord` **is** the severity ordering: `None < Low < Medium < High <
/// Critical`, so `max()` over a set of bands is the worst of them.
///
/// Deliberately *not* `#[non_exhaustive]`: the band vocabulary is fixed by the
/// CVSS specification, and consumers want exhaustive matches over it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// No impact: a base score of exactly 0.0.
    #[default]
    None,
    /// 0.1 – 3.9.
    Low,
    /// 4.0 – 6.9.
    Medium,
    /// 7.0 – 8.9.
    High,
    /// 9.0 – 10.0.
    Critical,
}

impl Severity {
    /// The band a CVSS base score falls in. The score is clamped to `0.0..=10.0`
    /// first, so an out-of-range input still yields a band rather than a panic.
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        let score = score.clamp(0.0, 10.0);
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score >= 0.1 {
            Severity::Low
        } else {
            Severity::None
        }
    }

    /// Parse a named band, case-insensitively.
    ///
    /// Accepts the four CVSS band names plus `none`, and the GitHub Security
    /// Advisory alias `moderate` for [`Severity::Medium`]. Returns `None` for
    /// anything else rather than guessing — an unrecognized label must not be
    /// silently downgraded to a real band.
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "none" => Some(Severity::None),
            _ => None,
        }
    }

    /// A short human-readable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// A stable uppercase token for machine-readable output.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Severity::None => "NONE",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// The lowest CVSS base score in this band.
    #[must_use]
    pub fn min_score(&self) -> f64 {
        match self {
            Severity::None => 0.0,
            Severity::Low => 0.1,
            Severity::Medium => 4.0,
            Severity::High => 7.0,
            Severity::Critical => 9.0,
        }
    }
}

/// Which revision of the CVSS specification a vector string is written in.
///
/// `#[non_exhaustive]`: CVSS revisions keep arriving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CvssVersion {
    /// CVSS v2 — a prefix-less vector such as `AV:N/AC:L/Au:N/C:P/I:P/A:P`.
    V2,
    /// CVSS v3.0 or v3.1 — a `CVSS:3.x/...` vector.
    V3,
    /// CVSS v4.0 — a `CVSS:4.0/...` vector.
    V4,
}

/// How severe an advisory is, as far as its publisher says.
///
/// OSV never publishes a numeric CVSS score — only a vector string — so
/// [`Self::score`] is *computed* from [`Self::vector`] where the vector is one
/// this crate's consumers can score. An advisory that carries neither a scorable
/// vector nor a recognized label is **unrated** (see [`Self::is_unrated`]): both
/// `score` and `band` stay `None` rather than being filled in with `0.0`, which
/// would be indistinguishable from a genuinely harmless advisory.
///
/// `#[non_exhaustive]`: build with [`Self::unrated`], [`Self::from_score`], or
/// [`Self::from_label`] and refine with the `with_*` methods.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct AdvisorySeverity {
    /// The computed CVSS base score, in `0.0..=10.0`.
    pub score: Option<f64>,
    /// The band: derived from [`Self::score`] when there is one, else parsed
    /// from [`Self::label`].
    pub band: Option<Severity>,
    /// The CVSS vector [`Self::score`] was computed from, verbatim.
    pub vector: Option<String>,
    /// Which CVSS revision [`Self::vector`] is written in.
    pub cvss_version: Option<CvssVersion>,
    /// The publisher's own severity word, verbatim (`"MODERATE"`), so a report
    /// can show what was actually published rather than a normalized guess.
    pub label: Option<String>,
}

impl AdvisorySeverity {
    /// An advisory with no severity information at all.
    #[must_use]
    pub fn unrated() -> Self {
        Self::default()
    }

    /// A severity carrying a computed CVSS base score, with the band derived
    /// from it.
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        Self {
            score: Some(score),
            band: Some(Severity::from_score(score)),
            ..Self::default()
        }
    }

    /// A severity known only by its publisher's label. The band is set only if
    /// the label is one [`Severity::parse`] recognizes.
    #[must_use]
    pub fn from_label(label: impl Into<String>) -> Self {
        Self::unrated().with_label(label)
    }

    /// Record the vector the score came from and the revision it is written in.
    #[must_use]
    pub fn with_vector(mut self, vector: impl Into<String>, version: CvssVersion) -> Self {
        self.vector = Some(vector.into());
        self.cvss_version = Some(version);
        self
    }

    /// Record the publisher's severity label verbatim, filling in the band from
    /// it only when no band has been established yet — a computed score always
    /// outranks a published word.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        let label = label.into();
        if self.band.is_none() {
            self.band = Severity::parse(&label);
        }
        self.label = Some(label);
        self
    }

    /// Whether this advisory carries no usable rating: no computed score and no
    /// band. A report should print "unrated" for these rather than "none".
    #[must_use]
    pub fn is_unrated(&self) -> bool {
        self.score.is_none() && self.band.is_none()
    }
}

/// One affected version range for the queried package.
///
/// A range is half-open: affected from [`Self::introduced`] (inclusive) up to
/// [`Self::fixed`] (exclusive), or through [`Self::last_affected`] (inclusive).
/// An absent bound means "unbounded in that direction".
///
/// `#[non_exhaustive]`: build with [`Self::default`] and assign fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AffectedRange {
    /// First affected version (`"0"` in OSV means "from the beginning").
    pub introduced: Option<String>,
    /// First version that is *not* affected.
    pub fixed: Option<String>,
    /// Last version that *is* affected, where the publisher gives one instead of
    /// a fix.
    pub last_affected: Option<String>,
}

impl AffectedRange {
    /// Set the first affected version.
    #[must_use]
    pub fn with_introduced(mut self, version: impl Into<String>) -> Self {
        self.introduced = Some(version.into());
        self
    }

    /// Set the first version that is no longer affected.
    #[must_use]
    pub fn with_fixed(mut self, version: impl Into<String>) -> Self {
        self.fixed = Some(version.into());
        self
    }

    /// Set the last version that is still affected.
    #[must_use]
    pub fn with_last_affected(mut self, version: impl Into<String>) -> Self {
        self.last_affected = Some(version.into());
        self
    }
}

/// What an advisory reference points at.
///
/// `#[non_exhaustive]`: OSV's reference vocabulary can grow. Unknown types map
/// to [`ReferenceKind::Web`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceKind {
    /// A published security advisory.
    Advisory,
    /// An article or blog post about the issue.
    Article,
    /// A tool or signature that detects the issue.
    Detection,
    /// A discussion thread.
    Discussion,
    /// A vulnerability report (an issue tracker entry).
    Report,
    /// The commit or patch that fixes the issue.
    Fix,
    /// The commit that introduced the issue.
    Introduced,
    /// The package's home on its registry.
    Package,
    /// Evidence of exploitation.
    Evidence,
    /// A source repository.
    Git,
    /// Anything else (the default for an unrecognized type).
    #[default]
    Web,
}

impl ReferenceKind {
    /// A stable lowercase token for machine-readable output.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            ReferenceKind::Advisory => "advisory",
            ReferenceKind::Article => "article",
            ReferenceKind::Detection => "detection",
            ReferenceKind::Discussion => "discussion",
            ReferenceKind::Report => "report",
            ReferenceKind::Fix => "fix",
            ReferenceKind::Introduced => "introduced",
            ReferenceKind::Package => "package",
            ReferenceKind::Evidence => "evidence",
            ReferenceKind::Git => "git",
            ReferenceKind::Web => "web",
        }
    }
}

/// One link published with an advisory.
///
/// `#[non_exhaustive]`: build with [`Self::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdvisoryReference {
    /// What the link points at.
    pub kind: ReferenceKind,
    /// The link itself.
    pub url: String,
}

impl AdvisoryReference {
    /// A reference of `kind` pointing at `url`.
    #[must_use]
    pub fn new(kind: ReferenceKind, url: impl Into<String>) -> Self {
        Self {
            kind,
            url: url.into(),
        }
    }
}

/// A full advisory record for one vulnerability affecting one package version.
///
/// This is the enriched form of an ID in [`CheckResult::current_vulnerabilities`]:
/// the same identity, plus everything a report needs to explain and act on it.
/// The version fields describe the **queried package only** — ranges for other
/// packages the same advisory affects are dropped.
///
/// `#[non_exhaustive]`: build with [`Advisory::new`] and the `with_*` methods, or
/// assign the public fields directly.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Advisory {
    /// The advisory's own ID (`RUSTSEC-2020-0071`, `GHSA-xxxx-xxxx-xxxx`).
    pub id: String,
    /// Other IDs naming the same vulnerability (CVE, GHSA, …).
    pub aliases: Vec<String>,
    /// One-line summary.
    pub summary: Option<String>,
    /// Long-form description, as published (Markdown).
    pub details: Option<String>,
    /// How severe the publisher says this is.
    pub severity: AdvisorySeverity,
    /// Affected version ranges for the queried package.
    pub ranges: Vec<AffectedRange>,
    /// The versions that fix this advisory, deduplicated, in record order.
    pub fixed_versions: Vec<String>,
    /// Published links.
    pub references: Vec<AdvisoryReference>,
    /// CWE identifiers (`CWE-416`), where the publisher classifies the weakness.
    pub cwe_ids: Vec<String>,
    /// Publication timestamp, RFC 3339, **unparsed** — this crate has no date
    /// dependency, so a consumer that needs a date parses it.
    pub published: Option<String>,
    /// Last-modified timestamp, RFC 3339, unparsed.
    pub modified: Option<String>,
    /// Withdrawal timestamp, RFC 3339, unparsed. Present only if withdrawn.
    pub withdrawn: Option<String>,
}

impl Advisory {
    /// An advisory known only by its ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            aliases: Vec::new(),
            summary: None,
            details: None,
            severity: AdvisorySeverity::unrated(),
            ranges: Vec::new(),
            fixed_versions: Vec::new(),
            references: Vec::new(),
            cwe_ids: Vec::new(),
            published: None,
            modified: None,
            withdrawn: None,
        }
    }

    /// Attach the one-line summary.
    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Attach the long-form description.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Attach the severity.
    #[must_use]
    pub fn with_severity(mut self, severity: AdvisorySeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Attach the fixing versions.
    #[must_use]
    pub fn with_fixed_versions(mut self, versions: Vec<String>) -> Self {
        self.fixed_versions = versions;
        self
    }

    /// Attach the published links.
    #[must_use]
    pub fn with_references(mut self, references: Vec<AdvisoryReference>) -> Self {
        self.references = references;
        self
    }

    /// Attach the alias IDs.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Attach the affected version ranges.
    #[must_use]
    pub fn with_ranges(mut self, ranges: Vec<AffectedRange>) -> Self {
        self.ranges = ranges;
        self
    }

    /// A non-empty display title: the summary if there is one, else the ID.
    #[must_use]
    pub fn title(&self) -> &str {
        self.summary.as_deref().unwrap_or(&self.id)
    }

    /// The advisory's canonical page: the first [`ReferenceKind::Advisory`] link.
    #[must_use]
    pub fn advisory_url(&self) -> Option<&str> {
        self.references
            .iter()
            .find(|r| r.kind == ReferenceKind::Advisory)
            .map(|r| r.url.as_str())
    }

    /// Whether the publisher has withdrawn this advisory.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_some()
    }

    /// The highest computed CVSS base score across `advisories`, if any is
    /// scored.
    #[must_use]
    pub fn max_cvss(advisories: &[Advisory]) -> Option<f64> {
        advisories
            .iter()
            .filter_map(|a| a.severity.score)
            .fold(None, |acc: Option<f64>, s| {
                Some(acc.map_or(s, |best| best.max(s)))
            })
    }

    /// The highest severity band across `advisories`, if any is rated.
    #[must_use]
    pub fn max_severity(advisories: &[Advisory]) -> Option<Severity> {
        advisories.iter().filter_map(|a| a.severity.band).max()
    }

    /// How many of `advisories` carry no usable rating.
    #[must_use]
    pub fn unrated_count(advisories: &[Advisory]) -> usize {
        advisories
            .iter()
            .filter(|a| a.severity.is_unrated())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{DependencyKind, PackageSource};

    fn item(name: &str) -> Item {
        Item {
            name: name.to_string(),
            version_constraint: "1".to_string(),
            source: PackageSource::Registry,
            version_line: 0,
            version_col_start: 0,
            version_col_end: 0,
            registry: None,
            locked_version: None,
            kind: DependencyKind::Normal,
        }
    }

    #[test]
    fn severity_bands_follow_the_cvss_boundaries() {
        assert_eq!(Severity::from_score(10.0), Severity::Critical);
        assert_eq!(Severity::from_score(9.0), Severity::Critical);
        assert_eq!(Severity::from_score(8.9), Severity::High);
        assert_eq!(Severity::from_score(7.0), Severity::High);
        assert_eq!(Severity::from_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_score(4.0), Severity::Medium);
        assert_eq!(Severity::from_score(3.9), Severity::Low);
        assert_eq!(Severity::from_score(0.1), Severity::Low);
        assert_eq!(Severity::from_score(0.0), Severity::None);
    }

    #[test]
    fn severity_from_score_clamps_out_of_range_input() {
        assert_eq!(Severity::from_score(99.0), Severity::Critical);
        assert_eq!(Severity::from_score(-1.0), Severity::None);
    }

    #[test]
    fn severity_parse_is_case_insensitive_and_knows_moderate() {
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("moderate"), Some(Severity::Medium));
        assert_eq!(Severity::parse("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::parse(" critical "), Some(Severity::Critical));
        assert_eq!(Severity::parse("none"), Some(Severity::None));
        assert_eq!(Severity::parse("nope"), None);
    }

    #[test]
    fn severity_min_scores_match_the_bands() {
        assert!((Severity::Critical.min_score() - 9.0).abs() < f64::EPSILON);
        assert!((Severity::High.min_score() - 7.0).abs() < f64::EPSILON);
        assert!((Severity::Medium.min_score() - 4.0).abs() < f64::EPSILON);
        assert!((Severity::Low.min_score() - 0.1).abs() < f64::EPSILON);
        assert!((Severity::None.min_score() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn severity_orders_from_none_up_to_critical() {
        let mut bands = vec![
            Severity::High,
            Severity::None,
            Severity::Critical,
            Severity::Low,
            Severity::Medium,
        ];
        bands.sort();
        assert_eq!(
            bands,
            vec![
                Severity::None,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
        );
        assert_eq!(bands.iter().copied().max(), Some(Severity::Critical));
    }

    #[test]
    fn severity_labels_and_tokens_are_stable() {
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Medium.token(), "MEDIUM");
    }

    #[test]
    fn a_computed_score_outranks_a_published_label() {
        let severity = AdvisorySeverity::from_score(9.8).with_label("MODERATE");
        assert_eq!(severity.band, Some(Severity::Critical));
        assert_eq!(severity.label.as_deref(), Some("MODERATE"));
        assert!(!severity.is_unrated());
    }

    #[test]
    fn a_label_alone_still_yields_a_band() {
        let severity = AdvisorySeverity::from_label("MODERATE");
        assert_eq!(severity.score, None);
        assert_eq!(severity.band, Some(Severity::Medium));
        assert!(!severity.is_unrated());
    }

    #[test]
    fn an_unrecognized_label_leaves_the_advisory_unrated() {
        let severity = AdvisorySeverity::from_label("SPICY");
        assert_eq!(severity.band, None);
        assert_eq!(severity.label.as_deref(), Some("SPICY"));
        assert!(severity.is_unrated());
    }

    #[test]
    fn a_recorded_vector_keeps_its_version() {
        let severity =
            AdvisorySeverity::from_score(6.2).with_vector("CVSS:3.1/AV:L", CvssVersion::V3);
        assert_eq!(severity.vector.as_deref(), Some("CVSS:3.1/AV:L"));
        assert_eq!(severity.cvss_version, Some(CvssVersion::V3));
    }

    #[test]
    fn advisory_title_falls_back_to_the_id() {
        assert_eq!(
            Advisory::new("RUSTSEC-2020-0071").title(),
            "RUSTSEC-2020-0071"
        );
        assert_eq!(
            Advisory::new("RUSTSEC-2020-0071")
                .with_summary("Use-after-free")
                .title(),
            "Use-after-free"
        );
    }

    #[test]
    fn advisory_url_picks_the_advisory_reference() {
        let advisory = Advisory::new("X").with_references(vec![
            AdvisoryReference::new(ReferenceKind::Web, "https://example.test/blog"),
            AdvisoryReference::new(ReferenceKind::Advisory, "https://example.test/advisory"),
            AdvisoryReference::new(ReferenceKind::Advisory, "https://example.test/second"),
        ]);
        assert_eq!(
            advisory.advisory_url(),
            Some("https://example.test/advisory")
        );
        assert_eq!(Advisory::new("X").advisory_url(), None);
    }

    #[test]
    fn withdrawal_is_reported_from_the_timestamp() {
        let mut advisory = Advisory::new("X");
        assert!(!advisory.is_withdrawn());
        advisory.withdrawn = Some("2024-01-01T00:00:00Z".to_string());
        assert!(advisory.is_withdrawn());
    }

    #[test]
    fn rollups_ignore_unrated_advisories() {
        let advisories = vec![
            Advisory::new("A").with_severity(AdvisorySeverity::from_score(6.2)),
            Advisory::new("B").with_severity(AdvisorySeverity::from_label("CRITICAL")),
            Advisory::new("C"),
        ];
        assert_eq!(Advisory::max_cvss(&advisories), Some(6.2));
        assert_eq!(
            Advisory::max_severity(&advisories),
            Some(Severity::Critical)
        );
        assert_eq!(Advisory::unrated_count(&advisories), 1);
    }

    #[test]
    fn rollups_over_nothing_are_none() {
        assert_eq!(Advisory::max_cvss(&[]), None);
        assert_eq!(Advisory::max_severity(&[]), None);
        assert_eq!(Advisory::unrated_count(&[]), 0);
    }

    #[test]
    fn a_fresh_result_carries_no_advisories() {
        let bare = CheckResult::new(item("serde"), DependencyStatus::Local);
        assert!(bare.advisories.is_empty());
        assert_eq!(bare.max_cvss(), None);
        assert_eq!(bare.max_severity(), None);

        let evaluated = CheckResult::from_evaluation(
            item("serde"),
            Evaluation {
                status: DependencyStatus::UpToDate,
                latest_compatible: Some("1.0.0".to_string()),
                latest_available: Some("1.0.0".to_string()),
                patch_available: false,
            },
        );
        assert!(evaluated.advisories.is_empty());
    }

    #[test]
    fn a_result_looks_up_an_advisory_by_id() {
        let mut result = CheckResult::new(item("time"), DependencyStatus::Vulnerable);
        result.advisories = vec![
            Advisory::new("RUSTSEC-2020-0071").with_severity(AdvisorySeverity::from_score(6.2)),
        ];
        assert!(result.advisory("RUSTSEC-2020-0071").is_some());
        assert!(result.advisory("GHSA-nope").is_none());
        assert_eq!(result.max_cvss(), Some(6.2));
        assert_eq!(result.max_severity(), Some(Severity::Medium));
    }
}
