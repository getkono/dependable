//! The view model the HTML templates render, and the pure functions that build it.
//!
//! Everything a template interpolates is prepared here: numbers are formatted to
//! strings, `Option`s are collapsed to placeholders, URLs are scheme-checked, and
//! every SVG coordinate is computed and formatted with `{:.4}`. Two reasons, both
//! load-bearing:
//!
//! - **Determinism.** No float formatting, no sorting, and no arithmetic happens
//!   in Jinja, so the same [`Report`] renders byte-for-byte identically. That is
//!   what makes the golden tests meaningful.
//! - **Safety.** [`safe_url`] is the only thing standing between an advisory's
//!   `javascript:` reference and an `href`; HTML escaping does not stop a scheme.
//!
//! ## Ordering
//!
//! Nothing here iterates a `HashMap`, and nothing relies on the order advisories
//! happened to arrive in. `CheckResult::all_vulnerabilities` (a `HashMap`) is not
//! read at all — `current_vulnerabilities` is the authoritative list. Explicit
//! keys: the vulnerability table sorts by
//! `(Reverse(score_key), Reverse(band), package, advisory_id)`, where `score_key`
//! is `(score * 10.0).round() as i64` so `f64`'s missing `Ord` never matters; the
//! timeline by `(published.is_none(), Reverse(published), package, advisory_id)`;
//! ecosystems by `(Reverse(total), display_name)`; and the dependency table not at
//! all — it keeps manifest order, which is the order of the file the reader will
//! open next.

use std::f64::consts::TAU;

use dependable_core::result::{Advisory, Severity};
use dependable_core::{CheckResult, DependencyStatus, Ecosystem};
use serde::Serialize;

use crate::html::HtmlOptions;
use crate::model::{ManifestResults, Report};
use crate::summary::Summary;

/// Printed wherever a value is genuinely absent, so no cell is ever blank and no
/// template ever has to decide what "missing" looks like.
const ABSENT: &str = "—";

/// How much of an advisory's `details` is carried into the document.
///
/// A pathological advisory must not turn a "self-contained" report into a
/// multi-megabyte file. Truncation happens here, on a character boundary, and not
/// in a template filter.
const DETAILS_MAX_CHARS: usize = 4000;

/// Pie centre X, in the SVG's own user units.
const PIE_CX: f64 = 110.0;
/// Pie centre Y.
const PIE_CY: f64 = 110.0;
/// Pie radius. `viewBox="0 0 220 220"` follows from these three.
const PIE_R: f64 = 100.0;

/// Width of a legend row's stacked health bar, in user units.
const BAR_WIDTH: f64 = 120.0;

/// A URL that is safe to put in an `href`, or `None`.
///
/// Accepts **only** `http://` and `https://`, case-insensitively, after trimming
/// ASCII whitespace *and* control characters from both ends. Everything else —
/// `javascript:`, `data:`, `vbscript:`, a protocol-relative `//host`, a scheme
/// split by an embedded newline — comes back `None`, and the caller renders the
/// raw text inertly instead of linking it.
///
/// HTML escaping does not help here: `javascript:alert(1)` contains no character
/// an escaper touches, so an escaped `javascript:` URL in an `href` is a working
/// `javascript:` URL. The filter has to be a scheme check, and it has to be in
/// Rust.
fn safe_url(raw: &str) -> Option<&str> {
    let trimmed = raw.trim_matches(|c: char| c.is_ascii_whitespace() || c.is_control());
    let starts_with = |scheme: &[u8]| {
        let bytes = trimmed.as_bytes();
        bytes.len() > scheme.len() && bytes[..scheme.len()].eq_ignore_ascii_case(scheme)
    };
    (starts_with(b"http://") || starts_with(b"https://")).then_some(trimmed)
}

/// [`safe_url`], owned.
fn safe_url_owned(raw: &str) -> Option<String> {
    safe_url(raw).map(ToOwned::to_owned)
}

/// `text` cut to at most `max` characters, on a character boundary.
///
/// When it is cut, an ellipsis is appended, followed by `link` where one survived
/// [`safe_url`] — so a reader who needs the rest is told where the rest lives.
fn truncate_chars(text: &str, max: usize, link: Option<&str>) -> String {
    let mut chars = text.char_indices();
    let Some((cut, _)) = chars.nth(max) else {
        return text.to_owned();
    };
    let mut out = String::with_capacity(cut + 64);
    out.push_str(&text[..cut]);
    out.push('…');
    match link {
        Some(url) => out.push_str(&format!("\n\n[truncated — full advisory at {url}]")),
        None => out.push_str("\n\n[truncated]"),
    }
    out
}

/// A colour for each ecosystem's slice, legend swatch, and table swatch.
///
/// `Ecosystem` is `#[non_exhaustive]`, so the fallback arm is required and is a
/// real colour rather than a panic — a new ecosystem must render, not abort.
fn ecosystem_color(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Rust => "#b7410e",
        Ecosystem::Go => "#00add8",
        Ecosystem::Npm => "#cb3837",
        Ecosystem::Python => "#3572a5",
        Ecosystem::Php => "#4f5d95",
        Ecosystem::Dart => "#00b4ab",
        Ecosystem::CSharp => "#178600",
        Ecosystem::Elixir => "#6e4a7e",
        _ => "#6b7280",
    }
}

/// The version reported for a dependency: its locked version where a lockfile
/// supplied one, else the constraint it declares.
fn current_version(result: &CheckResult) -> String {
    result
        .item
        .locked_version
        .clone()
        .unwrap_or_else(|| result.item.version_constraint.clone())
}

/// `Some(value)` or the [`ABSENT`] placeholder.
fn or_absent(value: Option<&String>) -> String {
    value.map_or_else(|| ABSENT.to_owned(), Clone::clone)
}

/// A CSS-class-safe token for a severity band.
fn severity_token(band: Option<Severity>) -> &'static str {
    band.as_ref().map_or("UNRATED", Severity::token)
}

/// A human label for a severity band; unrated is not the same as "none".
fn severity_label(band: Option<Severity>) -> &'static str {
    band.as_ref().map_or("unrated", Severity::label)
}

/// The integer sort key for a CVSS score.
///
/// `f64` has no `Ord`, and a report that reorders itself between runs is a report
/// with no golden test. Scaling by ten and rounding gives an exactly reproducible
/// total order; an unrated advisory sorts below every rated one.
fn score_key(score: Option<f64>) -> i64 {
    match score {
        #[allow(clippy::cast_possible_truncation)]
        Some(score) if score.is_finite() => (score * 10.0).round() as i64,
        _ => i64::MIN,
    }
}

/// Everything `report.html` and its includes read.
#[derive(Debug, Serialize)]
pub(crate) struct View {
    /// Document `<title>` and `<h1>`.
    pub title: String,
    /// The project root the report covers, as given.
    pub root: String,
    /// RFC 3339 generation timestamp, or `None` when stamping is off.
    pub generated_at: Option<String>,
    /// `dependable-report`'s own version, for provenance.
    pub version: String,
    /// Caller-supplied banner notes (skips and warnings the console would swallow).
    pub notes: Vec<String>,
    pub summary: SummaryView,
    pub vulnerabilities: Vec<VulnRow>,
    pub manifests: Vec<ManifestView>,
    pub timeline: Vec<TimelineRow>,
    pub ecosystems: ChartView,
}

/// §1 Executive Summary.
#[derive(Debug, Serialize)]
pub(crate) struct SummaryView {
    pub manifests: usize,
    pub total: usize,
    pub checkable: usize,
    pub up_to_date: usize,
    pub patch_available: usize,
    pub update_available: usize,
    pub outdated: usize,
    pub vulnerable: usize,
    pub error: usize,
    pub local: usize,
    pub git: usize,
    pub advisory_instances: usize,
    pub distinct_advisories: usize,
    pub withdrawn_advisories: usize,
    pub severity: SeverityView,
    /// Formatted in Rust: `"9.8"`, or [`ABSENT`] when nothing is scored.
    pub max_cvss: String,
    /// Formatted in Rust: `"87.5%"`, or [`ABSENT`] when nothing is checkable —
    /// so no template can divide by zero or print `NaN%`.
    pub up_to_date_percent: String,
}

/// Advisory instances per severity band.
#[derive(Debug, Serialize)]
pub(crate) struct SeverityView {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub none: usize,
    pub unrated: usize,
}

/// One `(dependency, advisory)` row of §2.
#[derive(Debug, Serialize)]
pub(crate) struct VulnRow {
    pub manifest: String,
    pub package: String,
    pub current: String,
    pub constraint: String,
    pub advisory_id: String,
    /// `None` when the advisory has no link that survived [`safe_url`].
    pub advisory_url: Option<String>,
    pub title: String,
    pub severity_label: String,
    pub severity_token: String,
    pub score: String,
    /// The CVSS vector verbatim, or `None` — the template branches on it rather
    /// than string-comparing a placeholder.
    pub vector: Option<String>,
    pub published: String,
    pub fixed: String,
    pub withdrawn: bool,
    pub aliases: Vec<String>,
    pub cwe_ids: Vec<String>,
    /// The published description, **escaped and pre-wrapped, never rendered**:
    /// it is third-party Markdown, and Markdown permits raw inline HTML.
    pub details: Option<String>,
    pub references: Vec<RefView>,
}

/// One published link on an advisory.
#[derive(Debug, Serialize)]
pub(crate) struct RefView {
    pub kind: String,
    /// `None` when the URL's scheme is not `http`/`https`; the template then
    /// prints [`Self::text`] as inert text instead of linking it.
    pub url: Option<String>,
    pub text: String,
}

/// One manifest's block in §3.
#[derive(Debug, Serialize)]
pub(crate) struct ManifestView {
    pub path: String,
    pub ecosystem: String,
    pub total: usize,
    pub rows: Vec<DepRow>,
}

/// One dependency row of §3.
#[derive(Debug, Serialize)]
pub(crate) struct DepRow {
    pub name: String,
    pub constraint: String,
    pub current: String,
    pub status_label: String,
    pub status_token: String,
    /// The error text for [`DependencyStatus::Error`] — a server response, and so
    /// untrusted like everything else here.
    pub note: Option<String>,
    pub latest_compatible: String,
    pub latest_available: String,
    pub advisories: Vec<String>,
}

/// One row of §4, the Advisory Timeline.
#[derive(Debug, Serialize)]
pub(crate) struct TimelineRow {
    pub published: String,
    pub advisory_id: String,
    pub advisory_url: Option<String>,
    pub title: String,
    pub package: String,
    pub current: String,
    pub first_fix: String,
    pub latest_available: String,
    pub withdrawn: bool,
}

/// §5, the ecosystem pie plus its equivalent table.
#[derive(Debug, Serialize)]
pub(crate) struct ChartView {
    pub total: usize,
    pub slices: Vec<Slice>,
    pub rows: Vec<EcoRow>,
}

/// One wedge of the pie.
///
/// A single-slice chart sets [`Self::full_circle`] and leaves [`Self::path`]
/// empty: an arc sweeping a full 360° starts and ends at the same point and
/// renders *nothing*, so the one-slice case has to be a `<circle>`.
#[derive(Debug, Serialize)]
pub(crate) struct Slice {
    pub label: String,
    pub color: String,
    pub count: usize,
    pub percent: String,
    pub full_circle: bool,
    pub path: String,
}

/// One legend and table row beneath the pie.
#[derive(Debug, Serialize)]
pub(crate) struct EcoRow {
    pub label: String,
    pub color: String,
    pub count: usize,
    pub percent: String,
    pub up_to_date: usize,
    pub outdated: usize,
    pub vulnerable: usize,
    pub other: usize,
    pub bar: Vec<BarSeg>,
}

/// One `<rect>` of a legend row's stacked health bar.
#[derive(Debug, Serialize)]
pub(crate) struct BarSeg {
    pub x: String,
    pub width: String,
    pub class: String,
    pub label: String,
}

impl View {
    /// Build the whole view model from a report and the caller's options.
    ///
    /// # Errors
    ///
    /// Propagates [`crate::ReportError::Format`] if the timestamp cannot be
    /// formatted, which is the only fallible step.
    pub(crate) fn build(
        report: &Report,
        options: &HtmlOptions,
    ) -> Result<Self, crate::ReportError> {
        let summary = report.summary();
        let generated_at = if options.timestamp {
            Some(report.generated_at_rfc3339()?)
        } else {
            None
        };
        Ok(Self {
            title: options.title.clone(),
            root: report.root.display().to_string(),
            generated_at,
            version: crate::VERSION.to_owned(),
            notes: options.notes.clone(),
            summary: summary_view(&summary),
            vulnerabilities: vulnerability_rows(report),
            manifests: manifest_views(report),
            timeline: timeline_rows(report),
            ecosystems: chart_view(&summary),
        })
    }
}

fn summary_view(summary: &Summary) -> SummaryView {
    SummaryView {
        manifests: summary.manifests,
        total: summary.total,
        checkable: summary.checkable,
        up_to_date: summary.up_to_date,
        patch_available: summary.patch_available,
        update_available: summary.update_available,
        outdated: summary.outdated,
        vulnerable: summary.vulnerable,
        error: summary.error,
        local: summary.local,
        git: summary.git,
        advisory_instances: summary.advisory_instances,
        distinct_advisories: summary.distinct_advisories,
        withdrawn_advisories: summary.withdrawn_advisories,
        severity: SeverityView {
            critical: summary.severity.critical,
            high: summary.severity.high,
            medium: summary.severity.medium,
            low: summary.severity.low,
            none: summary.severity.none,
            unrated: summary.severity.unrated,
        },
        max_cvss: summary
            .max_cvss
            .map_or_else(|| ABSENT.to_owned(), |score| format!("{score:.1}")),
        up_to_date_percent: summary
            .up_to_date_percent()
            .map_or_else(|| ABSENT.to_owned(), |pct| format!("{pct:.1}%")),
    }
}

/// Every `(dependency, advisory ID)` pair in the tree, worst first.
fn vulnerability_rows(report: &Report) -> Vec<VulnRow> {
    let mut rows: Vec<(i64, Option<Severity>, VulnRow)> = Vec::new();
    for manifest in &report.manifests {
        let path = manifest.path.display().to_string();
        for result in &manifest.results {
            let mut seen: Vec<&str> = Vec::new();
            for id in &result.current_vulnerabilities {
                if seen.contains(&id.as_str()) {
                    continue;
                }
                seen.push(id.as_str());
                let advisory = result.advisory(id);
                let band = advisory.and_then(|a| a.severity.band);
                let key = score_key(advisory.and_then(|a| a.severity.score));
                rows.push((key, band, vuln_row(&path, result, id, advisory)));
            }
        }
    }
    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.package.cmp(&b.2.package))
            .then_with(|| a.2.advisory_id.cmp(&b.2.advisory_id))
    });
    rows.into_iter().map(|(_, _, row)| row).collect()
}

fn vuln_row(
    manifest: &str,
    result: &CheckResult,
    id: &str,
    advisory: Option<&Advisory>,
) -> VulnRow {
    let advisory_url = advisory.and_then(Advisory::advisory_url).and_then(safe_url);
    VulnRow {
        manifest: manifest.to_owned(),
        package: result.item.name.clone(),
        current: current_version(result),
        constraint: result.item.version_constraint.clone(),
        advisory_id: id.to_owned(),
        advisory_url: advisory_url.map(ToOwned::to_owned),
        title: advisory.map_or_else(|| id.to_owned(), |a| a.title().to_owned()),
        severity_label: severity_label(advisory.and_then(|a| a.severity.band)).to_owned(),
        severity_token: severity_token(advisory.and_then(|a| a.severity.band)).to_owned(),
        score: advisory
            .and_then(|a| a.severity.score)
            .map_or_else(|| ABSENT.to_owned(), |s| format!("{s:.1}")),
        vector: advisory.and_then(|a| a.severity.vector.clone()),
        published: advisory
            .and_then(|a| a.published.clone())
            .unwrap_or_else(|| ABSENT.to_owned()),
        fixed: advisory
            .map(|a| a.fixed_versions.join(", "))
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| ABSENT.to_owned()),
        withdrawn: advisory.is_some_and(Advisory::is_withdrawn),
        aliases: advisory.map(|a| a.aliases.clone()).unwrap_or_default(),
        cwe_ids: advisory.map(|a| a.cwe_ids.clone()).unwrap_or_default(),
        details: advisory
            .and_then(|a| a.details.as_deref())
            .map(|d| truncate_chars(d, DETAILS_MAX_CHARS, advisory_url)),
        references: advisory.map(references).unwrap_or_default(),
    }
}

fn references(advisory: &Advisory) -> Vec<RefView> {
    advisory
        .references
        .iter()
        .map(|reference| RefView {
            kind: reference.kind.token().to_owned(),
            url: safe_url_owned(&reference.url),
            text: reference.url.clone(),
        })
        .collect()
}

/// §3 keeps manifest and parser order: it mirrors the file the reader will edit.
fn manifest_views(report: &Report) -> Vec<ManifestView> {
    report.manifests.iter().map(manifest_view).collect()
}

fn manifest_view(manifest: &ManifestResults) -> ManifestView {
    ManifestView {
        path: manifest.path.display().to_string(),
        ecosystem: manifest.ecosystem.display_name().to_owned(),
        total: manifest.results.len(),
        rows: manifest.results.iter().map(dep_row).collect(),
    }
}

fn dep_row(result: &CheckResult) -> DepRow {
    let mut advisories = result.current_vulnerabilities.clone();
    advisories.sort();
    advisories.dedup();
    DepRow {
        name: result.item.name.clone(),
        constraint: result.item.version_constraint.clone(),
        current: current_version(result),
        status_label: result.status.label().to_owned(),
        status_token: result.status.token().to_owned(),
        note: match &result.status {
            DependencyStatus::Error(why) => Some(why.clone()),
            _ => None,
        },
        latest_compatible: or_absent(result.latest_compatible.as_ref()),
        latest_available: or_absent(result.latest_available.as_ref()),
        advisories,
    }
}

/// §4: every advisory affecting the tree, newest first.
///
/// `published` is an unparsed RFC 3339 string and this crate has no date parser,
/// so the sort is **lexicographic**, descending. For OSV's uniform
/// `2021-08-25T20:52:00Z` form that *is* chronological; for anything malformed it
/// is still a stable total order, which is all determinism needs. Advisories with
/// no publication date sort last rather than interleaving unpredictably.
fn timeline_rows(report: &Report) -> Vec<TimelineRow> {
    let mut rows: Vec<TimelineRow> = Vec::new();
    for manifest in &report.manifests {
        for result in &manifest.results {
            let mut seen: Vec<&str> = Vec::new();
            for id in &result.current_vulnerabilities {
                if seen.contains(&id.as_str()) {
                    continue;
                }
                seen.push(id.as_str());
                rows.push(timeline_row(result, id, result.advisory(id)));
            }
        }
    }
    rows.sort_by(|a, b| {
        let undated = |row: &TimelineRow| row.published == ABSENT;
        undated(a)
            .cmp(&undated(b))
            .then_with(|| b.published.cmp(&a.published))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    });
    rows
}

fn timeline_row(result: &CheckResult, id: &str, advisory: Option<&Advisory>) -> TimelineRow {
    TimelineRow {
        published: advisory
            .and_then(|a| a.published.clone())
            .unwrap_or_else(|| ABSENT.to_owned()),
        advisory_id: id.to_owned(),
        advisory_url: advisory
            .and_then(Advisory::advisory_url)
            .and_then(safe_url)
            .map(ToOwned::to_owned),
        title: advisory.map_or_else(|| id.to_owned(), |a| a.title().to_owned()),
        package: result.item.name.clone(),
        current: current_version(result),
        first_fix: advisory
            .and_then(|a| a.fixed_versions.first().cloned())
            .unwrap_or_else(|| ABSENT.to_owned()),
        latest_available: or_absent(result.latest_available.as_ref()),
        withdrawn: advisory.is_some_and(Advisory::is_withdrawn),
    }
}

/// §5: the pie and the table that carries the same numbers without it.
fn chart_view(summary: &Summary) -> ChartView {
    let total: usize = summary.by_ecosystem.iter().map(|e| e.total).sum();
    let slices = pie_slices(summary, total);
    let rows = summary
        .by_ecosystem
        .iter()
        .map(|eco| EcoRow {
            label: eco.ecosystem.display_name().to_owned(),
            color: ecosystem_color(eco.ecosystem).to_owned(),
            count: eco.total,
            percent: percent(eco.total, total),
            up_to_date: eco.up_to_date,
            outdated: eco.outdated,
            vulnerable: eco.vulnerable,
            other: eco.other,
            bar: health_bar(eco.up_to_date, eco.outdated, eco.vulnerable, eco.other),
        })
        .collect();
    ChartView {
        total,
        slices,
        rows,
    }
}

/// `count / total` as a one-decimal percentage.
///
/// No largest-remainder reconciliation and no forcing the parts to sum to 100:
/// the raw counts are printed next to every percentage, so the reader can check
/// the arithmetic rather than being handed an adjusted number.
fn percent(count: usize, total: usize) -> String {
    if total == 0 {
        return format!("{:.1}%", 0.0);
    }
    #[allow(clippy::cast_precision_loss)]
    let pct = (count as f64 / total as f64) * 100.0;
    format!("{pct:.1}%")
}

/// The pie's wedges, in [`Summary::by_ecosystem`] order — the same order as the
/// table below it, so the two views cannot disagree.
///
/// Zero ecosystems yields no slices at all (the template then draws no `<svg>`);
/// exactly one yields a single `full_circle` slice.
fn pie_slices(summary: &Summary, total: usize) -> Vec<Slice> {
    if total == 0 || summary.by_ecosystem.is_empty() {
        return Vec::new();
    }
    let single = summary.by_ecosystem.len() == 1;
    let mut offset = 0.0_f64;
    summary
        .by_ecosystem
        .iter()
        .map(|eco| {
            #[allow(clippy::cast_precision_loss)]
            let fraction = eco.total as f64 / total as f64;
            let start = offset;
            offset += fraction;
            Slice {
                label: eco.ecosystem.display_name().to_owned(),
                color: ecosystem_color(eco.ecosystem).to_owned(),
                count: eco.total,
                percent: percent(eco.total, total),
                full_circle: single,
                path: if single {
                    String::new()
                } else {
                    slice_path(start, offset)
                },
            }
        })
        .collect()
}

/// The `d` attribute for a wedge spanning `start..end` of the circle, where both
/// are fractions in `0.0..=1.0`.
///
/// Slices begin at twelve o'clock (−90°) and sweep clockwise (SVG sweep-flag 1,
/// which is the positive angular direction in a y-down coordinate system). The
/// large-arc flag is set once the wedge passes a half turn. Coordinates are
/// formatted with `{:.4}`, which is both plenty for a 220-unit box and exactly
/// reproducible.
fn slice_path(start: f64, end: f64) -> String {
    let quarter = TAU / 4.0;
    let (a0, a1) = (start * TAU - quarter, end * TAU - quarter);
    let (x0, y0) = (PIE_CX + PIE_R * a0.cos(), PIE_CY + PIE_R * a0.sin());
    let (x1, y1) = (PIE_CX + PIE_R * a1.cos(), PIE_CY + PIE_R * a1.sin());
    let large = usize::from(end - start > 0.5);
    format!(
        "M {PIE_CX:.4} {PIE_CY:.4} L {x0:.4} {y0:.4} A {PIE_R:.4} {PIE_R:.4} 0 {large} 1 {x1:.4} {y1:.4} Z"
    )
}

/// A legend row's stacked health bar: one `<rect>` per non-empty band.
///
/// Widths are proportional and cumulative, so the segments always tile exactly
/// [`BAR_WIDTH`] with no gap from rounding each independently.
fn health_bar(up_to_date: usize, outdated: usize, vulnerable: usize, other: usize) -> Vec<BarSeg> {
    let total = up_to_date + outdated + vulnerable + other;
    if total == 0 {
        return Vec::new();
    }
    let bands = [
        (up_to_date, "bar-ok", "up to date"),
        (outdated, "bar-outdated", "outdated"),
        (vulnerable, "bar-vulnerable", "vulnerable"),
        (other, "bar-other", "not checkable"),
    ];
    let mut done = 0_usize;
    let mut segments = Vec::new();
    for (count, class, label) in bands {
        if count == 0 {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let x = BAR_WIDTH * (done as f64 / total as f64);
        done += count;
        #[allow(clippy::cast_precision_loss)]
        let end = BAR_WIDTH * (done as f64 / total as f64);
        segments.push(BarSeg {
            x: format!("{x:.4}"),
            width: format!("{:.4}", end - x),
            class: class.to_owned(),
            label: format!("{label}: {count}"),
        });
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_url_accepts_http_and_https_in_any_case() {
        assert_eq!(
            safe_url("https://osv.dev/vulnerability/RUSTSEC-2020-0071"),
            Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071")
        );
        assert_eq!(
            safe_url("HTTP://example.com/a"),
            Some("HTTP://example.com/a")
        );
        assert_eq!(
            safe_url("  https://example.com/a  "),
            Some("https://example.com/a")
        );
    }

    #[test]
    fn safe_url_rejects_every_script_bearing_scheme() {
        // Escaping cannot save any of these: none of them contain a character an
        // HTML escaper touches, so the filter has to reject the scheme outright.
        for hostile in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "\u{1}javascript:alert(1)",
            "  \t javascript:alert(1)",
            "java\nscript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "//evil.example.com/x",
            "/relative/path",
            "mailto:someone@example.com",
            "file:///etc/passwd",
            "",
            "https://",
            "http://",
        ] {
            assert_eq!(safe_url(hostile), None, "must not be linkable: {hostile:?}");
        }
    }

    #[test]
    fn truncate_leaves_short_text_alone() {
        assert_eq!(truncate_chars("short", 4000, None), "short");
    }

    #[test]
    fn truncate_cuts_on_a_character_boundary_not_a_byte_one() {
        // Four-byte characters: a byte-indexed cut would panic or split one.
        let text = "🦀🦀🦀🦀🦀";

        let cut = truncate_chars(text, 2, None);

        assert!(cut.starts_with("🦀🦀…"), "{cut}");
        assert!(!cut.contains("🦀🦀🦀"), "{cut}");
        assert!(cut.contains("[truncated]"), "{cut}");
    }

    #[test]
    fn truncation_points_at_the_advisory_when_there_is_a_safe_link() {
        let cut = truncate_chars("abcdef", 3, Some("https://osv.dev/x"));

        assert!(cut.contains("https://osv.dev/x"), "{cut}");
    }

    #[test]
    fn score_key_orders_rated_above_unrated_and_is_exact() {
        assert!(score_key(Some(9.8)) > score_key(Some(9.7)));
        assert_eq!(score_key(Some(9.8)), 98);
        assert_eq!(score_key(None), i64::MIN);
        assert_eq!(score_key(Some(f64::NAN)), i64::MIN);
        assert_eq!(score_key(Some(f64::INFINITY)), i64::MIN);
    }

    #[test]
    fn a_single_slice_is_a_circle_because_a_full_arc_draws_nothing() {
        let summary = Summary {
            by_ecosystem: vec![eco(Ecosystem::Rust, 7)],
            ..Summary::default()
        };

        let slices = pie_slices(&summary, 7);

        assert_eq!(slices.len(), 1);
        assert!(slices[0].full_circle, "one slice must render as a <circle>");
        assert!(slices[0].path.is_empty());
        assert_eq!(slices[0].percent, "100.0%");
    }

    #[test]
    fn no_ecosystems_means_no_slices_at_all() {
        assert!(pie_slices(&Summary::default(), 0).is_empty());
    }

    #[test]
    fn three_slices_are_paths_that_close_the_circle() {
        let summary = Summary {
            by_ecosystem: vec![
                eco(Ecosystem::Rust, 6),
                eco(Ecosystem::Npm, 3),
                eco(Ecosystem::Go, 1),
            ],
            ..Summary::default()
        };

        let slices = pie_slices(&summary, 10);

        assert_eq!(slices.len(), 3);
        assert!(slices.iter().all(|s| !s.full_circle && !s.path.is_empty()));
        // 60% sweeps more than a half turn, so it — and only it — sets the
        // large-arc flag.
        assert!(slices[0].path.contains(" 1 1 "), "{}", slices[0].path);
        assert!(slices[1].path.contains(" 0 1 "), "{}", slices[1].path);
        assert!(slices[2].path.contains(" 0 1 "), "{}", slices[2].path);
        // The last wedge ends where the first began: twelve o'clock.
        let start = format!("L {:.4} {:.4}", PIE_CX, PIE_CY - PIE_R);
        assert!(slices[0].path.contains(&start), "{}", slices[0].path);
        let end = format!("{:.4} {:.4} Z", PIE_CX, PIE_CY - PIE_R);
        assert!(slices[2].path.ends_with(&end), "{}", slices[2].path);
    }

    #[test]
    fn slice_coordinates_contain_nothing_html_escaping_would_touch() {
        let path = slice_path(0.0, 0.25);

        assert!(
            path.chars()
                .all(|c| c.is_ascii_digit() || " .-MLAZ".contains(c)),
            "{path}"
        );
    }

    #[test]
    fn a_health_bar_tiles_the_full_width_without_gaps() {
        let bar = health_bar(3, 1, 1, 0);

        assert_eq!(bar.len(), 3, "empty bands are skipped");
        let last = bar.last().expect("a segment");
        let end: f64 = last.x.parse::<f64>().unwrap() + last.width.parse::<f64>().unwrap();
        assert!((end - BAR_WIDTH).abs() < 1e-9, "{end}");
        assert_eq!(bar[0].x, "0.0000");
    }

    #[test]
    fn an_empty_health_bar_has_no_segments() {
        assert!(health_bar(0, 0, 0, 0).is_empty());
    }

    #[test]
    fn percentages_are_formatted_in_rust_and_never_divide_by_zero() {
        assert_eq!(percent(1, 3), "33.3%");
        assert_eq!(percent(0, 0), "0.0%");
    }

    /// `EcosystemSummary` is `#[non_exhaustive]`, so one is obtained the way a
    /// caller must: by summarizing a real report of `total` healthy dependencies.
    fn eco(ecosystem: Ecosystem, total: usize) -> crate::summary::EcosystemSummary {
        let body = (0..total)
            .map(|i| format!("dep{i} = \"1.0.0\""))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = dependable_core::parse(
            dependable_core::ManifestKind::CargoToml,
            &format!("[dependencies]\n{body}\n"),
        )
        .expect("parse the fixture");
        let results = parsed
            .items
            .into_iter()
            .map(|item| CheckResult::new(item, DependencyStatus::UpToDate))
            .collect();
        let mut report = Report::new(std::path::PathBuf::from("."));
        report.push(ManifestResults::new(
            std::path::PathBuf::from("Cargo.toml"),
            ecosystem,
            results,
        ));
        report
            .summary()
            .by_ecosystem
            .into_iter()
            .next()
            .expect("one ecosystem")
    }
}
