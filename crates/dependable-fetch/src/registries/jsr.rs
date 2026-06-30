//! The JSR registry fetcher (`jsr.io`), for Deno `jsr:` dependencies.

use std::collections::HashMap;

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://jsr.io";

/// Fetches package versions from JSR (`jsr.io/<@scope/name>/meta.json`).
#[derive(Clone)]
pub struct JsrFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Meta {
    latest: Option<String>,
    #[serde(default)]
    versions: HashMap<String, VersionMeta>,
}

#[derive(Deserialize, Default)]
struct VersionMeta {
    #[serde(default)]
    yanked: bool,
}

impl JsrFetcher {
    /// A fetcher against the public JSR registry.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate JSR-compatible registry.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for JsrFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            // `name` is `@scope/pkg`; the path keeps the slash.
            let url = format!("{}/{name}/meta.json", self.base_url);
            let resp = self
                .client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
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
            let meta: Meta = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            let mut versions: Vec<String> = meta
                .versions
                .into_iter()
                .filter(|(_, m)| !m.yanked)
                .map(|(v, _)| v)
                .collect();
            sort_desc(&mut versions);
            let mut fetched = FetchedVersions::new(versions);
            if let Some(latest) = meta.latest {
                fetched = fetched.with_latest_tag(latest);
            }
            Ok(fetched)
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
