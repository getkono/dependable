//! License collection for `dependable list --licenses`.
//!
//! `list` is offline by construction: it renders parsed manifest data and nothing
//! else. A dependency's license is not in its manifest — it lives on the
//! registry's metadata endpoint — so showing it is opt-in and hits the network,
//! exactly as `--features` does.
//!
//! The concurrency lives in `dependable-fetch`
//! ([`dependable_fetch::registries::fetch_licenses`]); this module only picks the
//! right fetcher per ecosystem and fills the reports in.

use anyhow::Context as _;
use dependable_fetch::registries::{fetch_licenses, publishes_metadata};
use dependable_fetch::{
    CratesIoFetcher, Ecosystem, HexFetcher, NpmFetcher, PackagistFetcher, PyPiFetcher,
    RegistryFetcher, build_client,
};

use crate::output::list::ProjectReport;

/// How many metadata requests to have in flight at once, matching the checker's
/// own default.
const CONCURRENCY: usize = 20;

/// Fill in [`ProjectReport::licenses`] for every report, in place.
///
/// One HTTP client is shared across every manifest, so a repository with several
/// projects reuses one connection pool. Reports in an ecosystem whose registry
/// publishes no metadata — Go, JSR, NuGet, pub.dev — are left empty; a per-package
/// failure is swallowed, because an inventory listing must still print.
///
/// The default registry URLs are used: `list` reads no config file, so a private
/// index is not consulted.
///
/// # Errors
/// Returns an error only if the HTTP client itself cannot be built.
pub async fn fetch_all(reports: &mut [ProjectReport]) -> anyhow::Result<()> {
    let client = build_client().context("building HTTP client")?;
    for report in reports {
        if !publishes_metadata(report.ecosystem) {
            continue;
        }
        let fetcher: Box<dyn RegistryFetcher> = match report.ecosystem {
            Ecosystem::Rust => Box::new(CratesIoFetcher::new(client.clone())),
            Ecosystem::Npm => Box::new(NpmFetcher::new(client.clone())),
            Ecosystem::Python => Box::new(PyPiFetcher::new(client.clone())),
            Ecosystem::Php => Box::new(PackagistFetcher::new(client.clone())),
            Ecosystem::Elixir => Box::new(HexFetcher::new(client.clone())),
            _ => continue,
        };

        // Deduplicated: a name declared in two sections is one lookup.
        let mut names: Vec<String> = report
            .items
            .iter()
            .filter(|item| item.is_checkable())
            .map(|item| item.name.clone())
            .collect();
        names.sort();
        names.dedup();

        report.licenses = fetch_licenses(fetcher.as_ref(), &names, CONCURRENCY).await;
    }
    Ok(())
}
