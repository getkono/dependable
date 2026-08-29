//! Mapping OSV wire records onto the core [`Advisory`] model.
//!
//! Two things happen here that the wire format leaves to the consumer. First,
//! severity: OSV publishes a CVSS *vector*, and a large minority of advisories
//! publish only a severity *word* (or nothing at all), so the numeric score is
//! computed and the band is resolved through a fixed precedence. Second, version
//! ranges: an advisory describes every package it affects, so the ranges are
//! filtered down to the one package that was queried.

use dependable_core::result::{
    Advisory, AdvisoryReference, AdvisorySeverity, AffectedRange, CvssVersion, ReferenceKind,
    Severity,
};
use serde_json::Value;

use super::cvss;
use super::types;

/// Convert one OSV record into an [`Advisory`] describing `(ecosystem, name)`.
///
/// Version data for every other package the advisory affects is discarded: a
/// consumer is looking at one dependency, and a range for a different package
/// would be actively misleading next to it.
pub(super) fn advisory_from_wire(vuln: types::Vuln, ecosystem: &str, name: &str) -> Advisory {
    let matched = matched_affected(&vuln.affected, ecosystem, name);
    let ranges = ranges_of(&matched);
    let fixed_versions = fixed_versions_of(&ranges);
    let severity = severity_of(&vuln, &matched);
    let cwe_ids = cwe_ids_of(&vuln.database_specific);
    let references = vuln
        .references
        .iter()
        .filter(|r| !r.url.is_empty())
        .map(|r| AdvisoryReference::new(reference_kind(&r.kind), r.url.clone()))
        .collect();

    let mut advisory = Advisory::new(vuln.id)
        .with_aliases(vuln.aliases)
        .with_severity(severity)
        .with_ranges(ranges)
        .with_fixed_versions(fixed_versions)
        .with_references(references);
    advisory.summary = vuln.summary.filter(|s| !s.is_empty());
    advisory.details = vuln.details.filter(|s| !s.is_empty());
    advisory.cwe_ids = cwe_ids;
    advisory.published = vuln.published;
    advisory.modified = vuln.modified;
    advisory.withdrawn = vuln.withdrawn;
    advisory
}

/// The `affected` entries describing the queried package.
///
/// Matched on name *and* ecosystem, comparing the ecosystem up to its first
/// `':'` because OSV qualifies some ecosystems with a distribution (`Debian:11`).
/// If nothing matches on both, the name alone is used — an advisory that names
/// the right package under an ecosystem spelling we do not recognize is still
/// about that package. If nothing matches at all, no version data is reported
/// rather than another package's.
fn matched_affected<'a>(
    affected: &'a [types::Affected],
    ecosystem: &str,
    name: &str,
) -> Vec<&'a types::Affected> {
    let exact: Vec<&types::Affected> = affected
        .iter()
        .filter(|a| a.package.name == name && base_ecosystem(&a.package.ecosystem) == ecosystem)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    affected.iter().filter(|a| a.package.name == name).collect()
}

/// An OSV ecosystem name with any distribution suffix removed.
fn base_ecosystem(ecosystem: &str) -> &str {
    ecosystem.split(':').next().unwrap_or(ecosystem)
}

/// Fold each range's ordered events into closed [`AffectedRange`]s.
///
/// `introduced` opens a range and `fixed`/`last_affected` closes it. A `fixed`
/// with nothing open still yields a range (unbounded below), which is how a
/// publisher writes "everything before this". `GIT` ranges are dropped outright:
/// their bounds are commit hashes, not versions, and a consumer comparing them
/// to a dependency's version would get nonsense.
fn ranges_of(affected: &[&types::Affected]) -> Vec<AffectedRange> {
    let mut out = Vec::new();
    for entry in affected {
        for range in &entry.ranges {
            if range.kind.eq_ignore_ascii_case("GIT") {
                continue;
            }
            let mut open: Option<AffectedRange> = None;
            for event in &range.events {
                if let Some(introduced) = &event.introduced {
                    if let Some(previous) = open.take() {
                        out.push(previous);
                    }
                    open = Some(AffectedRange::default().with_introduced(introduced.clone()));
                } else if let Some(fixed) = &event.fixed {
                    out.push(open.take().unwrap_or_default().with_fixed(fixed.clone()));
                } else if let Some(last) = &event.last_affected {
                    out.push(
                        open.take()
                            .unwrap_or_default()
                            .with_last_affected(last.clone()),
                    );
                }
            }
            if let Some(dangling) = open.take() {
                out.push(dangling);
            }
        }
    }
    out
}

/// The fixing versions, deduplicated, in the order the record lists them.
fn fixed_versions_of(ranges: &[AffectedRange]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for version in ranges.iter().filter_map(|r| r.fixed.as_ref()) {
        if !out.iter().any(|seen| seen == version) {
            out.push(version.clone());
        }
    }
    out
}

/// Resolve the advisory's severity.
///
/// Score: every scorable vector is scored and the **maximum** is kept, along
/// with the vector that produced it — deterministic whatever order the publisher
/// listed them in, and fail-safe for a security gate. A vector that cannot be
/// scored (v2, v4) is still recorded so the revision is visible.
///
/// Band, in strict order: the computed score, then the advisory's own severity
/// word, then the matched `affected` entry's. If none of those resolves, the
/// advisory is left **unrated** — no score is invented, because a fabricated
/// `0.0` is indistinguishable from a genuinely harmless advisory.
fn severity_of(vuln: &types::Vuln, matched: &[&types::Affected]) -> AdvisorySeverity {
    let mut best: Option<(f64, &str, CvssVersion)> = None;
    let mut first: Option<(&str, CvssVersion)> = None;
    for entry in &vuln.severity {
        let vector = entry.score.trim();
        if vector.is_empty() {
            continue;
        }
        let Some(version) = cvss::version_of(vector).or_else(|| version_from_kind(&entry.kind))
        else {
            continue;
        };
        if first.is_none() {
            first = Some((vector, version));
        }
        if let Some(score) = cvss::base_score(vector)
            && best.is_none_or(|(best_score, _, _)| score > best_score)
        {
            best = Some((score, vector, version));
        }
    }

    let mut severity = match (best, first) {
        (Some((score, vector, version)), _) => {
            AdvisorySeverity::from_score(score).with_vector(vector, version)
        }
        (None, Some((vector, version))) => AdvisorySeverity::unrated().with_vector(vector, version),
        (None, None) => AdvisorySeverity::unrated(),
    };

    // The advisory's own label first, the matched affected entry's second; a
    // label that parses beats one that does not, so an unrecognized word never
    // shadows a usable band.
    let labels: Vec<String> = label_of(&vuln.database_specific)
        .into_iter()
        .chain(
            matched
                .iter()
                .filter_map(|a| label_of(&a.database_specific)),
        )
        .collect();
    let chosen = labels
        .iter()
        .find(|label| Severity::parse(label).is_some())
        .or_else(|| labels.first());
    if let Some(label) = chosen {
        severity = severity.with_label(label.clone());
    }
    severity
}

/// The `database_specific.severity` word, if the publisher set one.
fn label_of(database_specific: &Value) -> Option<String> {
    database_specific
        .get("severity")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|label| !label.is_empty())
}

/// The `database_specific.cwe_ids` list, if the publisher classified the weakness.
fn cwe_ids_of(database_specific: &Value) -> Vec<String> {
    database_specific
        .get("cwe_ids")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The CVSS revision an OSV severity `type` names, for a vector whose own shape
/// did not identify it.
fn version_from_kind(kind: &str) -> Option<CvssVersion> {
    match kind.to_ascii_uppercase().as_str() {
        "CVSS_V2" => Some(CvssVersion::V2),
        "CVSS_V3" => Some(CvssVersion::V3),
        "CVSS_V4" => Some(CvssVersion::V4),
        _ => None,
    }
}

/// Map an OSV reference `type` onto [`ReferenceKind`], defaulting unknown types
/// to [`ReferenceKind::Web`] rather than dropping the link.
fn reference_kind(kind: &str) -> ReferenceKind {
    match kind.to_ascii_uppercase().as_str() {
        "ADVISORY" => ReferenceKind::Advisory,
        "ARTICLE" => ReferenceKind::Article,
        "DETECTION" => ReferenceKind::Detection,
        "DISCUSSION" => ReferenceKind::Discussion,
        "REPORT" => ReferenceKind::Report,
        "FIX" => ReferenceKind::Fix,
        "INTRODUCED" => ReferenceKind::Introduced,
        "PACKAGE" => ReferenceKind::Package,
        "EVIDENCE" => ReferenceKind::Evidence,
        "GIT" => ReferenceKind::Git,
        _ => ReferenceKind::Web,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(json: &str) -> types::Vuln {
        serde_json::from_str(json).expect("fixture should parse")
    }

    #[test]
    fn folds_events_into_ranges_and_drops_git() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [{
                "package": {"name": "foo", "ecosystem": "crates.io"},
                "ranges": [
                  {"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "1.0.0"},
                    {"introduced": "2.0.0"}, {"last_affected": "2.3.0"}
                  ]},
                  {"type": "SEMVER", "events": [{"fixed": "3.1.0"}]},
                  {"type": "SEMVER", "events": [{"introduced": "4.0.0"}]},
                  {"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}
                ]
              }]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert_eq!(
            advisory.ranges,
            vec![
                AffectedRange::default()
                    .with_introduced("0")
                    .with_fixed("1.0.0"),
                AffectedRange::default()
                    .with_introduced("2.0.0")
                    .with_last_affected("2.3.0"),
                // An orphan `fixed`: unbounded below.
                AffectedRange::default().with_fixed("3.1.0"),
                // An `introduced` with no close: unbounded above.
                AffectedRange::default().with_introduced("4.0.0"),
            ]
        );
        assert_eq!(advisory.fixed_versions, vec!["1.0.0", "3.1.0"]);
    }

    #[test]
    fn fixed_versions_are_deduplicated_in_record_order() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [{
                "package": {"name": "foo", "ecosystem": "crates.io"},
                "ranges": [
                  {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]},
                  {"type": "ECOSYSTEM", "events": [{"introduced": "1"}, {"fixed": "2.0.0"}]},
                  {"type": "SEMVER", "events": [{"introduced": "3"}, {"fixed": "1.0.0"}]}
                ]
              }]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert_eq!(advisory.fixed_versions, vec!["2.0.0", "1.0.0"]);
    }

    #[test]
    fn keeps_only_the_queried_packages_ranges() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [
                {"package": {"name": "foo", "ecosystem": "npm"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
                {"package": {"name": "foo", "ecosystem": "crates.io"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]},
                {"package": {"name": "bar", "ecosystem": "crates.io"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "5.5.5"}]}]}
              ]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert_eq!(advisory.fixed_versions, vec!["1.0.0"]);
    }

    #[test]
    fn truncates_a_distribution_suffix_from_the_ecosystem() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [{
                "package": {"name": "foo", "ecosystem": "Debian:11"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
              }]
            }"#,
        );
        let advisory = advisory_from_wire(record, "Debian", "foo");
        assert_eq!(advisory.fixed_versions, vec!["1.2.3"]);
    }

    #[test]
    fn falls_back_to_a_name_only_match() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [{
                "package": {"name": "foo", "ecosystem": "SomethingElse"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
              }]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert_eq!(advisory.fixed_versions, vec!["1.2.3"]);
    }

    #[test]
    fn reports_no_versions_when_nothing_matches() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [{
                "package": {"name": "other", "ecosystem": "crates.io"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
              }]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert!(advisory.ranges.is_empty());
        assert!(advisory.fixed_versions.is_empty());
    }

    #[test]
    fn a_computed_score_sets_the_band() {
        let record = vuln(
            r#"{
              "id": "RUSTSEC-2020-0071",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "time");
        assert_eq!(advisory.severity.score, Some(6.2));
        assert_eq!(advisory.severity.band, Some(Severity::Medium));
        assert_eq!(advisory.severity.cvss_version, Some(CvssVersion::V3));
        assert!(advisory.severity.label.is_none());
    }

    #[test]
    fn the_highest_scorable_vector_wins() {
        let record = vuln(
            r#"{
              "id": "X",
              "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                {"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}
              ]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "x");
        assert_eq!(advisory.severity.score, Some(9.8));
        assert_eq!(
            advisory.severity.vector.as_deref(),
            Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
    }

    #[test]
    fn an_unscorable_vector_is_still_recorded() {
        let record = vuln(
            r#"{
              "id": "X",
              "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "x");
        assert_eq!(advisory.severity.score, None);
        assert_eq!(advisory.severity.cvss_version, Some(CvssVersion::V4));
        assert!(advisory.severity.vector.is_some());
        assert!(advisory.severity.is_unrated());
    }

    #[test]
    fn a_label_supplies_the_band_when_there_is_no_vector() {
        let record = vuln(r#"{"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}}"#);
        let advisory = advisory_from_wire(record, "crates.io", "x");
        assert_eq!(advisory.severity.score, None);
        assert_eq!(advisory.severity.band, Some(Severity::Medium));
        assert_eq!(advisory.severity.label.as_deref(), Some("MODERATE"));
    }

    #[test]
    fn a_computed_score_outranks_a_published_label() {
        let record = vuln(
            r#"{
              "id": "X",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
              "database_specific": {"severity": "MODERATE"}
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "x");
        assert_eq!(advisory.severity.band, Some(Severity::Critical));
        assert_eq!(advisory.severity.label.as_deref(), Some("MODERATE"));
    }

    #[test]
    fn the_matched_affected_entry_supplies_a_band_of_last_resort() {
        let record = vuln(
            r#"{
              "id": "X",
              "affected": [
                {"package": {"name": "other", "ecosystem": "crates.io"},
                 "database_specific": {"severity": "CRITICAL"}},
                {"package": {"name": "foo", "ecosystem": "crates.io"},
                 "database_specific": {"severity": "LOW"}}
              ]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert_eq!(advisory.severity.band, Some(Severity::Low));
    }

    #[test]
    fn an_unparseable_label_does_not_shadow_a_usable_one() {
        let record = vuln(
            r#"{
              "id": "X",
              "database_specific": {"severity": "SPICY"},
              "affected": [{"package": {"name": "foo", "ecosystem": "crates.io"},
                            "database_specific": {"severity": "HIGH"}}]
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "foo");
        assert_eq!(advisory.severity.band, Some(Severity::High));
        assert_eq!(advisory.severity.label.as_deref(), Some("HIGH"));
    }

    #[test]
    fn an_advisory_with_no_rating_at_all_is_unrated() {
        let advisory = advisory_from_wire(vuln(r#"{"id": "X"}"#), "crates.io", "x");
        assert!(advisory.severity.is_unrated());
        assert_eq!(advisory.severity.score, None);
        assert_eq!(advisory.severity.band, None);
        assert_eq!(advisory.severity.label, None);
    }

    #[test]
    fn maps_metadata_references_and_weaknesses() {
        let record = vuln(
            r#"{
              "id": "GHSA-x",
              "aliases": ["CVE-2021-1", "RUSTSEC-2021-0001"],
              "summary": "A summary",
              "details": "Long **markdown**.",
              "published": "2021-01-01T00:00:00Z",
              "modified": "2021-02-01T00:00:00Z",
              "withdrawn": "2021-03-01T00:00:00Z",
              "references": [
                {"type": "ADVISORY", "url": "https://example.test/advisory"},
                {"type": "WEB", "url": "https://example.test/web"},
                {"type": "SOMETHING_NEW", "url": "https://example.test/new"},
                {"type": "FIX", "url": ""}
              ],
              "database_specific": {"cwe_ids": ["CWE-416", "CWE-400"]}
            }"#,
        );
        let advisory = advisory_from_wire(record, "crates.io", "x");
        assert_eq!(advisory.title(), "A summary");
        assert_eq!(advisory.details.as_deref(), Some("Long **markdown**."));
        assert_eq!(advisory.aliases, vec!["CVE-2021-1", "RUSTSEC-2021-0001"]);
        assert_eq!(advisory.cwe_ids, vec!["CWE-416", "CWE-400"]);
        assert!(advisory.is_withdrawn());
        assert_eq!(advisory.modified.as_deref(), Some("2021-02-01T00:00:00Z"));
        assert_eq!(
            advisory.advisory_url(),
            Some("https://example.test/advisory")
        );
        // The empty URL is dropped; the unknown type degrades to `Web`.
        assert_eq!(advisory.references.len(), 3);
        assert_eq!(advisory.references[2].kind, ReferenceKind::Web);
    }
}
