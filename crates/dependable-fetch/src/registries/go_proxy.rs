//! The Go module proxy fetcher (the `proxy.golang.org` protocol).

use ::semver::Version;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_PROXY: &str = "https://proxy.golang.org";

/// Fetches module versions from a Go module proxy.
#[derive(Clone)]
pub struct GoProxyFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct LatestInfo {
    #[serde(rename = "Version")]
    version: String,
}

impl GoProxyFetcher {
    /// A fetcher against the public `proxy.golang.org`.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_PROXY.to_string(),
        }
    }

    /// A fetcher against an alternate Go module proxy.
    #[must_use]
    pub fn with_proxy(client: reqwest::Client, proxy_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: proxy_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for GoProxyFetcher {
    fn registry_root(&self) -> Option<&str> {
        Some(&self.base_url)
    }

    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let escaped = escape_module_path(name);

            // Primary: the version list.
            let list_url = format!("{}/{escaped}/@v/list", self.base_url);
            let resp = self.client.get(&list_url).send().await?;
            let status = resp.status();
            if status.is_success() {
                let body = resp.text().await?;
                let versions = parse_list(&body);
                if !versions.is_empty() {
                    return Ok(FetchedVersions::new(versions));
                }
                // Empty list (e.g. a module with only pseudo-versions): fall back.
            } else if !is_absent(status) {
                return Err(FetchError::Status {
                    code: status.as_u16(),
                    package: name.to_string(),
                });
            }

            // Fallback: the single latest version.
            let latest_url = format!("{}/{escaped}/@latest", self.base_url);
            let resp = self.client.get(&latest_url).send().await?;
            let status = resp.status();
            if is_absent(status) {
                return Err(FetchError::NotFound(name.to_string()));
            }
            if !status.is_success() {
                return Err(FetchError::Status {
                    code: status.as_u16(),
                    package: name.to_string(),
                });
            }
            let info: LatestInfo = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;
            Ok(FetchedVersions::new(vec![strip_v(&info.version)]))
        }
        .boxed()
    }
}

/// Whether a proxy response means "this module is not here", as opposed to the proxy
/// failing to answer.
///
/// The Go module proxy protocol names **both** `404` and `410` as the not-found
/// responses, and `410 Gone` is the canonical `proxy.golang.org` answer for a module it
/// will not serve — the private or internal path a repository excludes with `GOPRIVATE`,
/// or one the proxy has been asked to forget. Reading it as a transport failure marked
/// the whole registry unreachable, and a `--fail-on` gate cannot be honoured through
/// that: one private module turned a passing run into exit 2, which is exactly the CI
/// break the 404 carve-out exists to prevent.
fn is_absent(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
    )
}

/// Parse the newline-delimited `@v/list` body into clean (no leading `v`) semver
/// versions, newest-first, dropping anything unparseable.
fn parse_list(body: &str) -> Vec<String> {
    let mut versions: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(strip_v)
        .filter(|v| Version::parse(v).is_ok())
        .collect();
    sort_desc(&mut versions);
    versions
}

/// Strip a single leading `v` from a Go version (`v1.2.3` → `1.2.3`).
fn strip_v(version: &str) -> String {
    let trimmed = version.trim();
    trimmed.strip_prefix('v').unwrap_or(trimmed).to_string()
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

/// Encode a module path for the proxy: every uppercase letter becomes `!` plus
/// its lowercase form (the Go module proxy's case-encoding).
fn escape_module_path(module: &str) -> String {
    let mut out = String::with_capacity(module.len());
    for c in module.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_strips_v_and_sorts() {
        let body = "v1.0.0\nv1.2.0\nv1.1.0\n";
        assert_eq!(parse_list(body), vec!["1.2.0", "1.1.0", "1.0.0"]);
    }

    #[test]
    fn parse_list_drops_unparseable() {
        let body = "v1.0.0\ngarbage\n\n";
        assert_eq!(parse_list(body), vec!["1.0.0"]);
    }

    /// The protocol's two not-found answers, and nothing else. A `410` reaching the
    /// `Status` arm made a private module unreachable-registry rather than absent.
    #[test]
    fn both_not_found_statuses_mean_absent() {
        assert!(is_absent(reqwest::StatusCode::NOT_FOUND));
        assert!(is_absent(reqwest::StatusCode::GONE));
        assert!(!is_absent(reqwest::StatusCode::FORBIDDEN));
        assert!(!is_absent(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_absent(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn escapes_uppercase_letters() {
        assert_eq!(
            escape_module_path("github.com/Azure/azure-sdk"),
            "github.com/!azure/azure-sdk"
        );
        assert_eq!(escape_module_path("golang.org/x/text"), "golang.org/x/text");
    }
}
