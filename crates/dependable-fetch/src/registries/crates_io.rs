//! The crates.io sparse-index fetcher.

use std::collections::BTreeMap;

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, Owner, OwnerKind, PackageMetadata, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_INDEX: &str = "https://index.crates.io";

/// The crates.io web API, which serves the metadata the sparse index does not
/// carry (repository, license, homepage, owners, downloads).
const DEFAULT_API: &str = "https://crates.io/api/v1";

/// Fetches crate versions from a crates.io-compatible sparse index.
#[derive(Clone)]
pub struct CratesIoFetcher {
    client: reqwest::Client,
    base_url: String,
    auth: Option<String>,
    /// The crates.io web API base, or `None` for an alternate registry, which
    /// serves a sparse index but no such API.
    api_url: Option<String>,
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
            api_url: Some(DEFAULT_API.to_string()),
        }
    }

    /// A fetcher against an alternate sparse index, with an optional auth token.
    ///
    /// A Cargo `sparse+` scheme prefix (as stored in `config.toml`, e.g.
    /// `sparse+https://…/index/`) is accepted and stripped; a trailing slash is
    /// trimmed. The token, when present, is sent verbatim in the `Authorization`
    /// header on every request.
    #[must_use]
    pub fn with_registry(
        client: reqwest::Client,
        index_url: impl Into<String>,
        auth: Option<String>,
    ) -> Self {
        let raw = index_url.into();
        let base_url = raw
            .strip_prefix("sparse+")
            .unwrap_or(&raw)
            .trim_end_matches('/')
            .to_string();
        // The crates.io API describes crates.io. Pointing at the public index —
        // which is what the default config does — still means crates.io, so the
        // API applies; any other index is a different registry, and asking
        // crates.io about its crates would return the wrong package entirely.
        let api_url = (base_url == DEFAULT_INDEX).then(|| DEFAULT_API.to_string());
        Self {
            client,
            base_url,
            auth,
            api_url,
        }
    }

    /// Whether this fetcher can serve package metadata, i.e. whether its index is
    /// crates.io itself rather than an alternate registry.
    #[must_use]
    pub fn has_metadata_api(&self) -> bool {
        self.api_url.is_some()
    }

    /// Point the metadata client at a different crates.io API base (for testing).
    #[must_use]
    pub fn with_api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = Some(api_url.into().trim_end_matches('/').to_string());
        self
    }
}

/// The `GET /api/v1/crates/{name}` response, narrowed to what we render.
#[derive(Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    krate: CrateInfo,
    #[serde(default)]
    versions: Vec<VersionInfo>,
}

#[derive(Deserialize)]
struct CrateInfo {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    downloads: Option<u64>,
}

#[derive(Deserialize)]
struct VersionInfo {
    #[serde(default)]
    num: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    rust_version: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

/// The `GET /api/v1/crates/{name}/owners` response.
///
/// crates.io splits ownership across two arrays. A crate owned only by a team
/// has an empty `users`, so reading just that array reports a well-owned crate
/// as having no owners at all.
#[derive(Deserialize)]
struct OwnersResponse {
    #[serde(default)]
    users: Vec<ApiOwner>,
    #[serde(default)]
    teams: Vec<ApiOwner>,
}

#[derive(Deserialize)]
struct ApiOwner {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

impl ApiOwner {
    fn into_owner(self, kind: OwnerKind) -> Owner {
        Owner {
            name: self.name,
            login: self.login,
            // crates.io does not publish owner emails on this endpoint.
            email: None,
            url: self.url,
            kind,
        }
    }
}

impl RegistryFetcher for CratesIoFetcher {
    fn registry_root(&self) -> Option<&str> {
        Some(&self.base_url)
    }

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

    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<PackageMetadata>, FetchError>> {
        async move {
            // An alternate registry serves an index but no crates.io API.
            let Some(api) = self.api_url.as_deref() else {
                return Ok(None);
            };

            let resp = self
                .client
                .get(format!("{api}/crates/{name}"))
                .send()
                .await?;
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
            let body: CrateResponse = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            // Every listed release is dated in this same response, so the whole
            // version -> date map costs nothing beyond what we already fetched.
            let published: BTreeMap<String, String> = body
                .versions
                .iter()
                .filter_map(|v| Some((v.num.clone()?, v.created_at.clone()?)))
                .collect();

            // Per-version fields come from the newest release the API lists first.
            let newest = body.versions.first();
            let mut meta = PackageMetadata {
                description: body.krate.description,
                repository: body.krate.repository,
                homepage: body.krate.homepage,
                documentation: body.krate.documentation,
                license: newest.and_then(|v| v.license.clone()),
                owners: Vec::new(),
                downloads: body.krate.downloads,
                latest_published: newest.and_then(|v| v.created_at.clone()),
                published,
                yanked: newest.is_some_and(|v| v.yanked),
                msrv: newest.and_then(|v| v.rust_version.clone()),
            };

            // Owners are a second endpoint. They are enrichment, not the point:
            // a failure here must not cost the caller everything else.
            if let Ok(resp) = self
                .client
                .get(format!("{api}/crates/{name}/owners"))
                .send()
                .await
                && resp.status().is_success()
                && let Ok(owners) = resp.json::<OwnersResponse>().await
            {
                meta.owners = owners
                    .users
                    .into_iter()
                    .map(|o| o.into_owner(OwnerKind::User))
                    .chain(
                        owners
                            .teams
                            .into_iter()
                            .map(|o| o.into_owner(OwnerKind::Team)),
                    )
                    .filter(|o| !o.is_anonymous())
                    .collect();
            }

            Ok(Some(meta))
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
