//! The detail pane's freshness verdict in an ecosystem whose versions are not
//! semver as written.
//!
//! `data::lookup` hands the registry's published list and the selected row's
//! version to `data::freshness`. Both are in the registry's own dialect — Maven,
//! NuGet, PEP 440 — and the pane used to compare them untranslated, so any string
//! that was not strict semver was dropped without a word: a newest release spelled
//! `6.6.0.Final` was invisible, and a current version spelled `4.12` was read as no
//! version at all and reported up to date.

use dependable_fetch::{DependencyStatus, Ecosystem};
use dependable_tui::data::freshness;

fn list(versions: &[&str]) -> Vec<String> {
    versions.iter().map(|v| (*v).to_owned()).collect()
}

/// Not one of these is a `semver::Version` as written. Untranslated, the pane
/// found no parseable versions at all and reported an error.
#[test]
fn a_jvm_list_with_no_strict_semver_reports_the_real_newest_release() {
    let published = list(&["6.6.0.Final", "6.5.2.Final", "6.4.4.Final"]);
    let evaluation = freshness(Ecosystem::Jvm, &published, "6.4.4.Final");
    assert_eq!(evaluation.status, DependencyStatus::UpdateAvailable);
    assert_eq!(
        evaluation.latest_available.as_deref(),
        Some("6.6.0.Final"),
        "the newest release, under the spelling Maven Central publishes"
    );
}

/// A four-segment NuGet revision is the newest artifact of its release. Read
/// untranslated it was dropped, and the pane named `8.0.32` instead.
#[test]
fn a_nuget_revision_is_reported_as_the_newest_release() {
    let published = list(&["8.0.32.1", "8.0.32", "8.0.31"]);
    let evaluation = freshness(Ecosystem::CSharp, &published, "8.0.31");
    assert_eq!(evaluation.status, DependencyStatus::PatchAvailable);
    assert_eq!(evaluation.latest_available.as_deref(), Some("8.0.32.1"));
}

/// Two-segment PEP 440 releases are the norm on PyPI, and none of them parses
/// as semver as written.
#[test]
fn a_pep440_list_reports_the_real_newest_release() {
    let published = list(&["2.1", "2.1rc1", "2.0"]);
    let evaluation = freshness(Ecosystem::Python, &published, "2.0");
    assert_eq!(evaluation.status, DependencyStatus::UpdateAvailable);
    assert_eq!(evaluation.latest_available.as_deref(), Some("2.1"));
}

/// The current version is compared as Maven reads it. `4.12` used to be read as
/// no current version, which fell back to the newest release and rendered a green
/// `ok` for a dependency three releases behind.
#[test]
fn a_current_version_in_the_ecosystems_own_dialect_is_compared_not_dropped() {
    let published = list(&["4.13.2", "4.13.1", "4.13", "4.12", "4.11"]);

    let behind = freshness(Ecosystem::Jvm, &published, "4.12");
    assert_eq!(
        behind.status,
        DependencyStatus::UpdateAvailable,
        "`4.12` is behind `4.13.2`, not up to date"
    );
    assert_eq!(behind.latest_available.as_deref(), Some("4.13.2"));

    let current = freshness(Ecosystem::Jvm, &published, "4.13.2");
    assert_eq!(current.status, DependencyStatus::UpToDate);
}

/// The same for PEP 440: a pre-release in use is behind its final release, and a
/// two-segment release that is the newest is current.
#[test]
fn a_pep440_current_version_is_compared_as_pypi_reads_it() {
    let published = list(&["2.1", "2.1rc1", "2.0"]);

    let rc = freshness(Ecosystem::Python, &published, "2.1rc1");
    assert!(
        rc.status.has_update(),
        "`2.1rc1` is behind `2.1`, got {:?}",
        rc.status
    );
    assert_eq!(rc.latest_available.as_deref(), Some("2.1"));

    let newest = freshness(Ecosystem::Python, &published, "2.1");
    assert_eq!(newest.status, DependencyStatus::UpToDate);
}

/// An ecosystem that publishes semver is untouched by the translation.
#[test]
fn a_semver_ecosystem_is_compared_as_before() {
    let published = list(&["1.0.200", "1.0.100"]);
    let evaluation = freshness(Ecosystem::Rust, &published, "1.0.100");
    assert_eq!(evaluation.status, DependencyStatus::PatchAvailable);
    assert_eq!(evaluation.latest_available.as_deref(), Some("1.0.200"));
}
