//! The enriched dependency produced after fetching (lives here, not in core, so
//! the core stays IO-free).

use std::collections::HashMap;

use dependable_core::Item;

/// A vulnerability identifier (e.g. `RUSTSEC-2020-0001`, `CVE-...`, `GHSA-...`).
pub type VulnerabilityId = String;

/// An [`Item`] enriched with registry + OSV data.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub item: Item,
    /// All available versions, newest-first.
    pub available_versions: Vec<String>,
    /// Known vulnerabilities by version.
    pub vulnerabilities: HashMap<String, Vec<VulnerabilityId>>,
    /// A fetch error message, if the registry/OSV lookup failed.
    pub fetch_error: Option<String>,
    /// The registry's explicit "latest" tag, where available.
    pub latest_version: Option<String>,
}
