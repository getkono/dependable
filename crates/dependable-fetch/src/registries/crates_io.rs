//! The crates.io sparse-index fetcher.

use std::collections::BTreeMap;

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_INDEX: &str = "https://index.crates.io";

/// Fetches crate versions from a crates.io-compatible sparse index.
#[derive(Clone)]
pub struct CratesIoFetcher {
    client: reqwest::Client,
    base_url: String,
    auth: Option<String>,
}

#[derive(Deserialize)]
struct IndexLine {
    vers: String,
    #[serde(default)]
    yanked: bool,
    /// Feature name → the features/deps it enables.
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    /// Newer index table for features that enable optional dependencies; merged
    /// with `features` so the full set is reported.
    #[serde(default)]
    features2: BTreeMap<String, Vec<String>>,
}

impl IndexLine {
    /// The sorted, de-duplicated feature-flag names this version declares.
    fn feature_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .features
            .keys()
            .chain(self.features2.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

impl CratesIoFetcher {
    /// A fetcher against the public crates.io index.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_INDEX.to_string(),
            auth: None,
        }
    }

    /// A fetcher against an alternate sparse index, with an optional auth token.
    #[must_use]
    pub fn with_registry(
        client: reqwest::Client,
        index_url: impl Into<String>,
        auth: Option<String>,
    ) -> Self {
        Self {
            client,
            base_url: index_url.into().trim_end_matches('/').to_string(),
            auth,
        }
    }
}

impl RegistryFetcher for CratesIoFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let url = format!("{}/{}", self.base_url, index_path(name));
            let mut req = self.client.get(&url);
            if let Some(token) = &self.auth {
                req = req.header(reqwest::header::AUTHORIZATION, token);
            }
            let resp = req.send().await?;
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(FetchError::NotFound(name.to_string()));
            }
            if !status.is_success() {
                return Err(FetchError::Status {
                    code: status.as_u16(),
                    package: name.to_string(),
                });
            }
            let body = resp.text().await?;
            Ok(parse_index(&body))
        }
        .boxed()
    }
}

/// Parse the newline-delimited JSON index body into versions, newest-first, with
/// yanked releases filtered out. The newest version's declared feature flags are
/// attached for `list --features`.
fn parse_index(body: &str) -> FetchedVersions {
    let mut entries: Vec<IndexLine> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<IndexLine>(line).ok())
        .filter(|line| !line.yanked)
        .collect();
    entries.sort_by(|a, b| cmp_vers_desc(&a.vers, &b.vers));
    let features = entries
        .first()
        .map(IndexLine::feature_names)
        .unwrap_or_default();
    let versions: Vec<String> = entries.into_iter().map(|line| line.vers).collect();
    FetchedVersions::new(versions).with_features(features)
}

/// Order two version strings newest-first, falling back to reverse lexical order
/// for anything that does not parse as semver.
fn cmp_vers_desc(a: &str, b: &str) -> std::cmp::Ordering {
    match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => vb.cmp(&va),
        _ => b.cmp(a),
    }
}

/// Compute the crates.io sparse-index path for a crate name (PRD §5.4).
#[must_use]
pub fn index_path(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.len() {
        0 => lower,
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{}", &lower[0..1], lower),
        _ => format!("{}/{}/{}", &lower[0..2], &lower[2..4], lower),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_paths_follow_prefix_rules() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("serde"), "se/rd/serde");
        assert_eq!(index_path("tokio"), "to/ki/tokio");
        assert_eq!(index_path("Serde"), "se/rd/serde"); // lowercased
    }

    #[test]
    fn parses_ndjson_and_filters_yanked() {
        let body = concat!(
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"x\",\"vers\":\"1.1.0\",\"yanked\":true}\n",
            "{\"name\":\"x\",\"vers\":\"1.2.0\",\"yanked\":false}\n",
        );
        let fetched = parse_index(body);
        assert_eq!(fetched.versions, vec!["1.2.0", "1.0.0"]);
        assert_eq!(fetched.latest_tag.as_deref(), Some("1.2.0"));
        assert!(fetched.features.is_empty()); // no features declared
    }

    #[test]
    fn parses_features_from_the_newest_version() {
        let body = concat!(
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"yanked\":false,\"features\":{\"legacy\":[]}}\n",
            "{\"name\":\"x\",\"vers\":\"2.0.0\",\"yanked\":false,\"features\":{\"default\":[\"std\"],\"derive\":[\"x-derive\"]},\"features2\":{\"rc\":[\"dep:rc\"]}}\n",
        );
        let fetched = parse_index(body);
        assert_eq!(fetched.versions, vec!["2.0.0", "1.0.0"]);
        // Newest version (2.0.0) only, merging `features` + `features2`, sorted.
        assert_eq!(fetched.features, vec!["default", "derive", "rc"]);
    }
}
