//! Golden HTML documents.
//!
//! Three fixtures pin the whole rendered document byte-for-byte: the full report,
//! the empty one, and a single-ecosystem one. Between them they cover every
//! section, every empty state, and all three shapes of the ecosystem pie —
//! several slices, one slice (which must be a `<circle>`, because a 360° arc
//! draws nothing), and none at all (no `<svg>`).
//!
//! Regenerate after a deliberate change:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test -p dependable-report --test html_golden
//! ```
//!
//! The crate version is substituted with `0.0.0-test` before comparing, so a
//! release bump does not rewrite three files. The *timestamp* is deliberately not
//! substituted: the fixtures use [`Report::at`] with a fixed instant, so the
//! golden pins the literal string and proves the stamping path works.

use std::path::{Path, PathBuf};

use dependable_core::result::{
    Advisory, AdvisoryReference, AdvisorySeverity, AffectedRange, CvssVersion, ReferenceKind,
};
use dependable_core::{CheckResult, DependencyStatus, Ecosystem, ManifestKind, parse};
use dependable_report::html::{HtmlOptions, render};
use dependable_report::{ManifestResults, Report};
use time::OffsetDateTime;

/// 2023-11-14T22:13:20Z — fixed, so `generated_at` is a literal in the golden.
const FIXED: i64 = 1_700_000_000;

/// What the crate's own version is replaced with before comparing.
const VERSION_PLACEHOLDER: &str = "0.0.0-test";

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(FIXED).expect("a valid unix timestamp")
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.html"))
}

/// Compare `html` against the golden named `name`, or rewrite it under
/// `UPDATE_GOLDEN=1`.
fn assert_golden(name: &str, html: &str) {
    let normalized = html.replace(dependable_report::VERSION, VERSION_PLACEHOLDER);
    let path = golden_path(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("a parent directory"))
            .expect("create the golden directory");
        std::fs::write(&path, &normalized).expect("write the golden");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden {}: {e}. Regenerate with UPDATE_GOLDEN=1.",
            path.display()
        )
    });
    assert_eq!(
        normalized,
        expected,
        "{} is out of date; regenerate with UPDATE_GOLDEN=1",
        path.display()
    );
}

/// Real [`Item`](dependable_core::Item)s, obtained the only way an external crate
/// can: by parsing a manifest.
fn items(kind: ManifestKind, source: &str) -> Vec<dependable_core::Item> {
    parse(kind, source)
        .expect("parse the fixture manifest")
        .items
}

fn full_report() -> Report {
    let rust = items(
        ManifestKind::CargoToml,
        "[dependencies]\n\
         time = \"0.2.7\"\n\
         serde = \"1.0.228\"\n\
         regex = \"1.5\"\n\
         dependable-core = { path = \"../dependable-core\" }\n\
         brokenpkg = \"2\"\n",
    );
    let mut rust_results: Vec<CheckResult> = Vec::new();

    // Vulnerable, two advisories: one Critical with a vector, one unrated.
    let mut vulnerable = CheckResult::new(rust[0].clone(), DependencyStatus::Vulnerable);
    vulnerable.item.locked_version = Some("0.2.7".to_owned());
    vulnerable.latest_compatible = Some("0.2.27".to_owned());
    vulnerable.latest_available = Some("0.3.51".to_owned());
    vulnerable.current_vulnerabilities = vec![
        "RUSTSEC-2020-0071".to_owned(),
        "GHSA-wcg3-cvx6-7396".to_owned(),
    ];
    vulnerable.advisories = vec![
        Advisory::new("RUSTSEC-2020-0071")
            .with_summary("Potential segfault in the time crate")
            .with_details(
                "Unix-like operating systems may segfault due to dereferencing a \
                 dangling pointer in specific circumstances.\n\n\
                 ## Workarounds\n\n\
                 Do not set the environment from more than one thread.",
            )
            .with_severity(
                AdvisorySeverity::from_score(9.8)
                    .with_vector(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        CvssVersion::V3,
                    )
                    .with_label("CRITICAL"),
            )
            .with_aliases(vec!["CVE-2020-26235".to_owned()])
            .with_fixed_versions(vec!["0.2.23".to_owned()])
            .with_ranges(vec![
                AffectedRange::default()
                    .with_introduced("0.2.7")
                    .with_fixed("0.2.23"),
            ])
            .with_references(vec![
                AdvisoryReference::new(
                    ReferenceKind::Advisory,
                    "https://rustsec.org/advisories/RUSTSEC-2020-0071.html",
                ),
                // Rejected in Rust: escaping does not disarm a scheme.
                AdvisoryReference::new(ReferenceKind::Web, "javascript:alert(1)"),
            ]),
        Advisory::new("GHSA-wcg3-cvx6-7396")
            .with_summary("Unrated advisory with no publication date"),
    ];
    if let Some(advisory) = vulnerable.advisories.first_mut() {
        advisory.published = Some("2020-11-18T00:00:00Z".to_owned());
        advisory.modified = Some("2023-06-01T00:00:00Z".to_owned());
        advisory.cwe_ids = vec!["CWE-416".to_owned()];
    }
    rust_results.push(vulnerable);

    // Up to date.
    let mut healthy = CheckResult::new(rust[1].clone(), DependencyStatus::UpToDate);
    healthy.item.locked_version = Some("1.0.228".to_owned());
    healthy.latest_compatible = Some("1.0.228".to_owned());
    healthy.latest_available = Some("1.0.228".to_owned());
    rust_results.push(healthy);

    // Outdated.
    let mut outdated = CheckResult::new(rust[2].clone(), DependencyStatus::Outdated);
    outdated.item.locked_version = Some("1.5.4".to_owned());
    outdated.latest_compatible = Some("1.5.6".to_owned());
    outdated.latest_available = Some("1.12.4".to_owned());
    rust_results.push(outdated);

    // A path dependency, and one the registry refused to answer for.
    rust_results.push(CheckResult::new(rust[3].clone(), DependencyStatus::Local));
    rust_results.push(CheckResult::new(
        rust[4].clone(),
        DependencyStatus::Error("502 Bad Gateway from the index".to_owned()),
    ));

    let npm = items(
        ManifestKind::PackageJson,
        "{\"dependencies\":{\"left-pad\":\"^1.3.0\",\"lodash\":\"4.17.20\"}}",
    );
    let mut npm_results: Vec<CheckResult> = Vec::new();
    let mut left_pad = CheckResult::new(npm[0].clone(), DependencyStatus::PatchAvailable);
    left_pad.item.locked_version = Some("1.3.0".to_owned());
    left_pad.latest_compatible = Some("1.3.1".to_owned());
    left_pad.latest_available = Some("1.3.1".to_owned());
    left_pad.patch_available = true;
    npm_results.push(left_pad);

    let mut lodash = CheckResult::new(npm[1].clone(), DependencyStatus::Vulnerable);
    lodash.item.locked_version = Some("4.17.20".to_owned());
    lodash.latest_compatible = Some("4.17.21".to_owned());
    lodash.latest_available = Some("4.17.21".to_owned());
    lodash.current_vulnerabilities = vec!["GHSA-35jh-r3h4-6jhm".to_owned()];
    let mut withdrawn = Advisory::new("GHSA-35jh-r3h4-6jhm")
        .with_summary("Command injection in lodash")
        .with_severity(AdvisorySeverity::from_score(7.2))
        .with_fixed_versions(vec!["4.17.21".to_owned()])
        .with_references(vec![AdvisoryReference::new(
            ReferenceKind::Advisory,
            "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        )]);
    withdrawn.published = Some("2021-02-15T00:00:00Z".to_owned());
    withdrawn.withdrawn = Some("2021-03-01T00:00:00Z".to_owned());
    lodash.advisories = vec![withdrawn];
    npm_results.push(lodash);

    let mut report = Report::at(PathBuf::from("/proj"), fixed_time());
    report.push(ManifestResults::new(
        PathBuf::from("Cargo.toml"),
        Ecosystem::Rust,
        rust_results,
    ));
    report.push(ManifestResults::new(
        PathBuf::from("web/package.json"),
        Ecosystem::Npm,
        npm_results,
    ));
    report
}

#[test]
fn full_report_matches_the_golden() {
    let options = HtmlOptions::new()
        .with_title("dependable report")
        .with_note("Elixir is disabled in config; mix.exs was skipped.");

    let html = render(&full_report(), &options).expect("render the full report");

    // Sanity checks the golden alone would not make obvious.
    assert!(html.contains("<path d=\"M 110.0000 110.0000"), "{html}");
    assert!(!html.contains("href=\"javascript:"), "{html}");
    assert_golden("full", &html);
}

#[test]
fn an_empty_report_matches_the_golden() {
    let report = Report::at(PathBuf::from("/proj"), fixed_time());

    let html = render(&report, &HtmlOptions::new()).expect("render an empty report");

    assert!(!html.contains("<svg class=\"pie\""), "no data, no chart");
    assert!(html.contains("No dependencies to chart."));
    assert_golden("empty", &html);
}

#[test]
fn a_single_ecosystem_report_matches_the_golden() {
    let rust = items(
        ManifestKind::CargoToml,
        "[dependencies]\nserde = \"1\"\nanyhow = \"1\"\n",
    );
    let results = rust
        .into_iter()
        .map(|item| {
            let mut result = CheckResult::new(item, DependencyStatus::UpToDate);
            result.item.locked_version = Some("1.0.0".to_owned());
            result.latest_compatible = Some("1.0.0".to_owned());
            result.latest_available = Some("1.0.0".to_owned());
            result
        })
        .collect();
    let mut report = Report::at(PathBuf::from("."), fixed_time());
    report.push(ManifestResults::new(
        PathBuf::from("Cargo.toml"),
        Ecosystem::Rust,
        results,
    ));

    let html = render(&report, &HtmlOptions::new()).expect("render");

    // The classic one-slice bug: a 0-to-360-degree arc has identical endpoints
    // and paints nothing, so a lone slice has to be a circle.
    assert!(
        html.contains("<circle cx=\"110\" cy=\"110\" r=\"100\""),
        "{html}"
    );
    assert!(!html.contains("<path d="), "{html}");
    assert_golden("single_ecosystem", &html);
}

#[test]
fn the_goldens_load_nothing_over_the_network() {
    for name in ["full", "empty", "single_ecosystem"] {
        let html = std::fs::read_to_string(golden_path(name)).expect("read the golden");
        for vector in ["<script", "<link", "<img", "<iframe", "@import", "url("] {
            assert!(
                !html.contains(vector),
                "{name}.html contains `{vector}`, an external load vector"
            );
        }
    }
}
