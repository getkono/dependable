//! The npm registry fetcher (`registry.npmjs.org` and compatible registries).

use std::collections::HashMap;

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";
/// The abbreviated-metadata Accept header — far smaller than the full packument.
const ABBREVIATED: &str = "application/vnd.npm.install-v1+json";

/// Fetches package versions from an npm-compatible registry.
#[derive(Clone)]
pub struct NpmFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Packument {
    #[serde(default)]
    versions: HashMap<String, serde::de::IgnoredAny>,
    #[serde(default, rename = "dist-tags")]
    dist_tags: DistTags,
}

#[derive(Deserialize, Default)]
struct DistTags {
    latest: Option<String>,
}

impl NpmFetcher {
    /// A fetcher against the public npm registry.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate npm-compatible registry.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for NpmFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let url = format!("{}/{}", self.base_url, encode_name(name));
            let resp = self
                .client
                .get(&url)
                .header(reqwest::header::ACCEPT, ABBREVIATED)
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
            let packument: Packument = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            let mut versions: Vec<String> = packument.versions.into_keys().collect();
            sort_desc(&mut versions);
            let mut fetched = FetchedVersions::new(versions);
            if let Some(latest) = packument.dist_tags.latest {
                fetched = fetched.with_latest_tag(latest);
            }
            Ok(fetched)
        }
        .boxed()
    }
}

/// URL-encode a package name: scoped names have their `/` percent-encoded
/// (`@scope/pkg` → `@scope%2fpkg`).
fn encode_name(name: &str) -> String {
    name.replace('/', "%2f")
}

fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => vb.cmp(&va),
        _ => b.cmp(a),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_scoped_names() {
        assert_eq!(encode_name("react"), "react");
        assert_eq!(encode_name("@scope/pkg"), "@scope%2fpkg");
        assert_eq!(encode_name("@jsr/std__path"), "@jsr%2fstd__path");
    }
}
