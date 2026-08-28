//! The npm registry fetcher (`registry.npmjs.org` and compatible registries).

use std::collections::HashMap;

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, PackageMetadata, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";
/// The abbreviated-metadata Accept header — far smaller than the full packument.
const ABBREVIATED: &str = "application/vnd.npm.install-v1+json";

/// A private npm registry configured for a package scope (`@scope`): its base URL
/// and an optional bearer token. Built from `.npmrc` by the CLI.
#[derive(Clone, Debug)]
pub struct ScopedRegistry {
    /// The registry base URL for packages in this scope.
    pub registry: String,
    /// The bearer token to send, when the scope's registry is authenticated.
    pub token: Option<String>,
}

/// Fetches package versions from an npm-compatible registry.
///
/// Optionally carries `.npmrc`-derived auth: a bearer token for the default
/// registry and per-`@scope` private registries. Scoped packages route to their
/// scope's registry (with its token); everything else uses the default registry.
#[derive(Clone)]
pub struct NpmFetcher {
    client: reqwest::Client,
    base_url: String,
    default_token: Option<String>,
    scopes: HashMap<String, ScopedRegistry>,
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
            default_token: None,
            scopes: HashMap::new(),
        }
    }

    /// A fetcher against an alternate npm-compatible registry.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
            default_token: None,
            scopes: HashMap::new(),
        }
    }

    /// Attach `.npmrc`-derived authentication: a bearer `default_token` for the
    /// base registry, and per-`@scope` private registries. Scoped packages route
    /// to their scope's registry (with its own token); everything else uses the
    /// base registry and `default_token`.
    #[must_use]
    pub fn with_auth(
        mut self,
        default_token: Option<String>,
        scopes: HashMap<String, ScopedRegistry>,
    ) -> Self {
        self.default_token = default_token;
        self.scopes = scopes;
        self
    }

    /// The `(registry base URL, bearer token)` to use for `name`: a scoped package
    /// (`@scope/pkg`) uses its scope's private registry when one is configured,
    /// otherwise the default registry and token.
    fn resolve(&self, name: &str) -> (&str, Option<&str>) {
        if let Some(scope) = package_scope(name)
            && let Some(scoped) = self.scopes.get(scope)
        {
            return (
                scoped.registry.trim_end_matches('/'),
                scoped.token.as_deref(),
            );
        }
        (&self.base_url, self.default_token.as_deref())
    }
}

/// The **full** packument, narrowed to what we render.
///
/// Version checking asks for the abbreviated document, which omits all of this;
/// metadata therefore needs its own request without that `Accept` header.
#[derive(Deserialize)]
struct FullPackument {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    repository: Option<Repository>,
    #[serde(default)]
    maintainers: Vec<Maintainer>,
    #[serde(default)]
    time: HashMap<String, String>,
    #[serde(default, rename = "dist-tags")]
    dist_tags: DistTags,
}

/// npm writes `repository` either as an object or as a bare shorthand string.
#[derive(Deserialize)]
#[serde(untagged)]
enum Repository {
    Url { url: String },
    Shorthand(String),
}

impl Repository {
    fn into_url(self) -> String {
        match self {
            Self::Url { url } => url,
            Self::Shorthand(s) => s,
        }
    }
}

#[derive(Deserialize)]
struct Maintainer {
    #[serde(default)]
    name: Option<String>,
}

impl RegistryFetcher for NpmFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let (registry, token) = self.resolve(name);
            let url = format!("{}/{}", registry, encode_name(name));
            let mut req = self
                .client
                .get(&url)
                .header(reqwest::header::ACCEPT, ABBREVIATED);
            if let Some(token) = token {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
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

    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<PackageMetadata>, FetchError>> {
        async move {
            let (registry, token) = self.resolve(name);
            let url = format!("{}/{}", registry, encode_name(name));
            // No abbreviated `Accept` header: that form carries none of this.
            let mut req = self.client.get(&url);
            if let Some(token) = token {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
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
            let body: FullPackument = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            // `time` is keyed by version, plus `created`/`modified` entries; the
            // publish date we want is the one for the version tagged `latest`.
            let last_published = body
                .dist_tags
                .latest
                .as_deref()
                .and_then(|v| body.time.get(v).cloned())
                .or_else(|| body.time.get("modified").cloned());

            Ok(Some(PackageMetadata {
                description: body.description,
                repository: body.repository.map(Repository::into_url),
                homepage: body.homepage,
                documentation: None,
                license: body.license,
                authors: body
                    .maintainers
                    .into_iter()
                    .filter_map(|m| m.name)
                    .collect(),
                downloads: None,
                last_published,
                yanked: false,
                msrv: None,
            }))
        }
        .boxed()
    }
}

/// URL-encode a package name: scoped names have their `/` percent-encoded
/// (`@scope/pkg` → `@scope%2fpkg`).
fn encode_name(name: &str) -> String {
    name.replace('/', "%2f")
}

/// The `@scope` of a scoped package name (`@scope/pkg` → `@scope`), if any.
fn package_scope(name: &str) -> Option<&str> {
    if !name.starts_with('@') {
        return None;
    }
    name.split_once('/').map(|(scope, _)| scope)
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

    #[test]
    fn detects_package_scope() {
        assert_eq!(package_scope("@corp/widget"), Some("@corp"));
        assert_eq!(package_scope("react"), None);
        assert_eq!(package_scope("@corp"), None); // no `/` -> not a scoped path
    }
}
