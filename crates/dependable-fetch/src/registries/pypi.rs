//! The PyPI fetcher (the JSON API at `pypi.org/pypi/<name>/json`).
//!
//! Versions are returned as raw PEP 440 strings (so pre-release detection sees the
//! real markers); they are sorted newest-first by their semver interpretation. The
//! evaluation layer converts them to semver for comparison.

use std::collections::HashMap;

use ::semver::Version;
use dependable_core::semver::python::pep440_to_semver;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, PackageMetadata, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://pypi.org/pypi";

/// Fetches package versions from a PyPI-compatible JSON API.
#[derive(Clone)]
pub struct PyPiFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    releases: HashMap<String, Vec<FileEntry>>,
}

#[derive(Deserialize)]
struct FileEntry {
    #[serde(default)]
    yanked: bool,
}

impl PyPiFetcher {
    /// A fetcher against the public PyPI JSON API.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate PyPI-compatible JSON API.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

/// The `info` block of a PyPI project response, narrowed to what we render.
#[derive(Deserialize)]
struct InfoResponse {
    #[serde(default)]
    info: Info,
    #[serde(default)]
    urls: Vec<UploadedFile>,
}

#[derive(Deserialize, Default)]
struct Info {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    home_page: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    project_urls: HashMap<String, String>,
}

#[derive(Deserialize)]
struct UploadedFile {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
}

/// The `project_urls` key naming a source repository, by PyPI convention.
fn repository_url(urls: &HashMap<String, String>) -> Option<String> {
    ["Source", "Source Code", "Repository", "Code", "Homepage"]
        .iter()
        .find_map(|key| urls.get(*key).cloned())
}

impl RegistryFetcher for PyPiFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let url = format!("{}/{name}/json", self.base_url);
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
            let body: Response = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            // Keep a release if it has at least one non-yanked file (or no files at
            // all — some sdist-only releases list none but are installable).
            let mut versions: Vec<String> = body
                .releases
                .into_iter()
                .filter(|(_, files)| files.is_empty() || files.iter().any(|f| !f.yanked))
                .map(|(v, _)| v)
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
            let url = format!("{}/{name}/json", self.base_url);
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
            let body: InfoResponse = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            Ok(Some(PackageMetadata {
                description: body.info.summary,
                repository: repository_url(&body.info.project_urls),
                homepage: body.info.home_page,
                documentation: body.info.project_urls.get("Documentation").cloned(),
                license: body.info.license.filter(|l| !l.is_empty()),
                authors: body.info.author.into_iter().collect(),
                downloads: None,
                last_published: body.urls.into_iter().find_map(|f| f.upload_time_iso_8601),
                yanked: body.info.yanked,
                msrv: None,
            }))
        }
        .boxed()
    }
}

/// Sort raw PEP 440 versions newest-first by their semver interpretation.
fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| {
        let va = pep440_to_semver(a).and_then(|s| Version::parse(&s).ok());
        let vb = pep440_to_semver(b).and_then(|s| Version::parse(&s).ok());
        match (va, vb) {
            (Some(va), Some(vb)) => vb.cmp(&va),
            _ => b.cmp(a),
        }
    });
}
