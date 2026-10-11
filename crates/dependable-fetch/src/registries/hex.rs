//! The Hex fetcher for Elixir (`hex.pm/api/packages/<name>`).

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, Owner, PackageMetadata, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://hex.pm";

/// Fetches package versions from a Hex-compatible API.
#[derive(Clone)]
pub struct HexFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Package {
    #[serde(default)]
    releases: Vec<Release>,
}

#[derive(Deserialize)]
struct Release {
    version: String,
}

impl HexFetcher {
    /// A fetcher against the public Hex API.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate Hex-compatible API.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

/// The Hex package response, narrowed to what we render.
#[derive(Deserialize)]
struct PackageMeta {
    #[serde(default)]
    meta: HexMeta,
    #[serde(default)]
    downloads: HexDownloads,
    #[serde(default)]
    releases: Vec<DatedRelease>,
    #[serde(default)]
    docs_html_url: Option<String>,
}

#[derive(Deserialize, Default)]
struct HexMeta {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    licenses: Vec<String>,
    #[serde(default)]
    links: std::collections::HashMap<String, String>,
    #[serde(default)]
    maintainers: Vec<String>,
}

#[derive(Deserialize, Default)]
struct HexDownloads {
    #[serde(default)]
    all: Option<u64>,
}

#[derive(Deserialize)]
struct DatedRelease {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    inserted_at: Option<String>,
}

/// The `links` key naming a source repository, by Hex convention.
fn hex_repository(links: &std::collections::HashMap<String, String>) -> Option<String> {
    ["GitHub", "Github", "github", "Source", "Repository"]
        .iter()
        .find_map(|key| links.get(*key).cloned())
}

impl RegistryFetcher for HexFetcher {
    fn registry_root(&self) -> Option<&str> {
        Some(&self.base_url)
    }

    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let url = format!("{}/api/packages/{name}", self.base_url);
            let resp = self.client.get(&url).send().await?;
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
            let package: Package = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            let mut versions: Vec<String> = package
                .releases
                .into_iter()
                .map(|r| r.version)
                .filter(|v| Version::parse(v).is_ok())
                .collect();
            sort_desc(&mut versions);
            Ok(FetchedVersions::new(versions))
        }
        .boxed()
    }

    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<PackageMetadata>, FetchError>> {
        async move {
            let url = format!("{}/api/packages/{name}", self.base_url);
            let resp = self.client.get(&url).send().await?;
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
            let body: PackageMeta = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            Ok(Some(PackageMetadata {
                description: body.meta.description,
                repository: hex_repository(&body.meta.links),
                homepage: body.meta.links.get("Homepage").cloned(),
                documentation: body.docs_html_url,
                license: (!body.meta.licenses.is_empty()).then(|| body.meta.licenses.join(" OR ")),
                // Hex publishes maintainers as bare strings and nothing more.
                owners: body
                    .meta
                    .maintainers
                    .into_iter()
                    .filter(|m| !m.trim().is_empty())
                    .map(Owner::named)
                    .collect(),
                downloads: body.downloads.all,
                // Hex lists releases newest-first.
                latest_published: body.releases.iter().find_map(|r| r.inserted_at.clone()),
                published: body
                    .releases
                    .into_iter()
                    .filter_map(|r| Some((r.version?, r.inserted_at?)))
                    .collect(),
                yanked: false,
                msrv: None,
            }))
        }
        .boxed()
    }
}

/// Sort raw versions newest-first.
///
/// The comparison is **total**: versions that compare equal are ordered by their
/// own strings, so a list built in a nondeterministic order (a `HashMap`'s
/// iteration, pages appended as their fetches complete) cannot come out of here in
/// a nondeterministic one.
fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => vb.cmp(&va).then_with(|| b.cmp(a)),
        _ => b.cmp(a),
    });
}
