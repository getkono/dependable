//! The pub.dev fetcher for Dart / Flutter (`pub.dev/api/packages/<name>`).

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://pub.dev";

/// Fetches package versions from a pub.dev-compatible repository.
#[derive(Clone)]
pub struct PubDevFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Package {
    #[serde(default)]
    versions: Vec<VersionEntry>,
    #[serde(default)]
    latest: Option<VersionEntry>,
}

#[derive(Deserialize)]
struct VersionEntry {
    version: String,
}

impl PubDevFetcher {
    /// A fetcher against the public pub.dev repository.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate pub repository.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for PubDevFetcher {
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
                .versions
                .into_iter()
                .map(|v| v.version)
                .filter(|v| Version::parse(v).is_ok())
                .collect();
            sort_desc(&mut versions);
            let fetched = FetchedVersions::new(versions);
            Ok(match package.latest {
                Some(latest) => fetched.with_latest_tag(latest.version),
                None => fetched,
            })
        }
        .boxed()
    }
}

fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => vb.cmp(&va),
        _ => b.cmp(a),
    });
}
