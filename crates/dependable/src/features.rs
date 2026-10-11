//! Feature-flag collection for `dependable list --features`.
//!
//! Feature flags are not in a manifest — they are declared by each published
//! version on the crates.io sparse index — so showing them is opt-in and hits the
//! network, exactly as `--licenses` does.
//!
//! The whole point of collecting them in one pass, after every manifest has been
//! parsed, is that a monorepo declares the same crate in several members: the
//! union of names across *all* reports is fetched once, then handed back to each
//! report that asked for it. Fetching inside the per-manifest loop asked the
//! registry the same question once per member.
//!
//! The concurrency lives in `dependable-fetch`
//! ([`dependable_fetch::registries::fetch_features`]); this module only decides
//! which names to ask about and where the answers belong.

use std::collections::BTreeMap;

use anyhow::Context as _;
use dependable_fetch::registries::fetch_features;
use dependable_fetch::{CratesIoFetcher, Ecosystem, build_client};

use crate::output::list::ProjectReport;

/// How many index requests to have in flight at once, matching the checker's own
/// default and [`crate::licenses`].
const CONCURRENCY: usize = 20;

/// Fill in [`ProjectReport::features`] for every Rust report, in place.
///
/// One HTTP client and one fetch per distinct crate serve every manifest, so a
/// workspace whose members all depend on `serde` costs exactly one request for
/// it. Feature data is crates.io-only, so reports in other ecosystems are left
/// empty; a per-package failure is swallowed, because an inventory listing must
/// still print.
///
/// The default registry URL is used: `list` reads no config file, so a private
/// index is not consulted.
///
/// # Errors
/// Returns an error only if the HTTP client itself cannot be built.
pub async fn fetch_all(reports: &mut [ProjectReport]) -> anyhow::Result<()> {
    let names = rust_package_names(reports);
    if names.is_empty() {
        return Ok(());
    }
    let client = build_client().context("building HTTP client")?;
    let fetcher = CratesIoFetcher::new(client);
    let fetched = fetch_features(&fetcher, &names, CONCURRENCY).await;
    apply(reports, &fetched);
    Ok(())
}

/// Every distinct crate name declared by a Rust report, sorted.
///
/// Deduplicated **across manifests**, not just within one: two workspace members
/// declaring the same crate is the ordinary case in a monorepo and must cost one
/// request, not two. Only checkable items are included — a path or git
/// dependency has no registry to ask.
fn rust_package_names(reports: &[ProjectReport]) -> Vec<String> {
    let mut names: Vec<String> = reports
        .iter()
        .filter(|report| report.ecosystem == Ecosystem::Rust)
        .flat_map(|report| report.items.iter())
        .filter(|item| item.is_checkable())
        .map(|item| item.name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Hand each Rust report the feature lists for the crates *it* declares.
///
/// The fetched map is shared; the per-manifest map is not, so a report only ever
/// carries entries for its own dependencies.
fn apply(reports: &mut [ProjectReport], fetched: &BTreeMap<String, Vec<String>>) {
    for report in reports {
        if report.ecosystem != Ecosystem::Rust {
            continue;
        }
        for item in &report.items {
            if !item.is_checkable() {
                continue;
            }
            if let Some(features) = fetched.get(&item.name) {
                report.features.insert(item.name.clone(), features.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use dependable_fetch::ManifestKind;
    use dependable_fetch::core::{ProjectRole, parse};

    use super::*;

    /// A report over the dependencies `manifest` declares.
    fn report(manifest: &str) -> ProjectReport {
        ProjectReport {
            relative: PathBuf::from("Cargo.toml"),
            ecosystem: Ecosystem::Rust,
            name: None,
            version: None,
            version_inherited: false,
            role: ProjectRole::Package,
            lockfile: None,
            dependencies_unread: false,
            inherited: Vec::new(),
            items: parse(ManifestKind::CargoToml, manifest)
                .expect("fixture should parse")
                .items,
            features: BTreeMap::new(),
            licenses: BTreeMap::new(),
        }
    }

    #[test]
    fn a_crate_declared_by_two_manifests_is_asked_about_once() {
        let reports = vec![
            report("[dependencies]\nleftpad = \"1\"\nserde = \"1\"\n"),
            report("[dependencies]\nleftpad = \"1\"\n"),
        ];
        assert_eq!(
            rust_package_names(&reports),
            vec!["leftpad".to_string(), "serde".to_string()],
            "leftpad is declared twice and must be fetched once"
        );
    }

    #[test]
    fn unfetchable_and_non_rust_declarations_are_never_asked_about() {
        let mut reports = vec![report(
            "[dependencies]\nlocal-thing = { path = \"../local\" }\ngitdep = { git = \"https://example.com/g\" }\n",
        )];
        assert!(rust_package_names(&reports).is_empty());

        reports[0].ecosystem = Ecosystem::Npm;
        reports[0].items = parse(ManifestKind::CargoToml, "[dependencies]\nserde = \"1\"\n")
            .expect("fixture should parse")
            .items;
        assert!(rust_package_names(&reports).is_empty());
    }

    #[test]
    fn each_report_receives_only_the_crates_it_declares() {
        let mut reports = vec![
            report("[dependencies]\nleftpad = \"1\"\nserde = \"1\"\n"),
            report("[dependencies]\nleftpad = \"1\"\n"),
        ];
        let fetched = BTreeMap::from([
            ("leftpad".to_string(), vec!["pad".to_string()]),
            ("serde".to_string(), vec!["derive".to_string()]),
        ]);

        apply(&mut reports, &fetched);

        assert_eq!(
            reports[0].features.keys().collect::<Vec<_>>(),
            vec!["leftpad", "serde"]
        );
        assert_eq!(
            reports[1].features.keys().collect::<Vec<_>>(),
            vec!["leftpad"],
            "a report must not inherit a sibling's dependencies"
        );
        assert_eq!(reports[1].features["leftpad"], vec!["pad".to_string()]);
    }
}
