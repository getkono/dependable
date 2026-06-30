//! The Packagist fetcher for PHP/Composer (`repo.packagist.org` metadata v2).

use std::collections::HashMap;

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://repo.packagist.org";

/// Fetches package versions from a Packagist-compatible repository.
#[derive(Clone)]
pub struct PackagistFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Metadata {
    #[serde(default)]
    packages: HashMap<String, Vec<Release>>,
}

#[derive(Deserialize)]
struct Release {
    version: String,
}

impl PackagistFetcher {
    /// A fetcher against the public Packagist repository.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate Composer repository.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for PackagistFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let url = format!("{}/p2/{name}.json", self.base_url);
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
            let metadata: Metadata = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            let mut versions: Vec<String> = metadata
                .packages
                .get(name)
                .into_iter()
                .flatten()
                .map(|r| strip_v(&r.version))
                .filter(|v| Version::parse(v).is_ok())
                .collect();
            sort_desc(&mut versions);
            Ok(FetchedVersions::new(versions))
        }
        .boxed()
    }
}

/// Strip a single leading `v` from a composer version tag.
fn strip_v(version: &str) -> String {
    version.strip_prefix('v').unwrap_or(version).to_string()
}

fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => vb.cmp(&va),
        _ => b.cmp(a),
    });
}
