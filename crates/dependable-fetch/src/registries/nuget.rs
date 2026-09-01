//! The NuGet fetcher for C#/.NET (the V3 registration API at `api.nuget.org`).
//!
//! The registration index (`registration5-gz-semver2/<id>/index.json`, gzip —
//! transparently decompressed by the shared client) is paginated: each page either
//! inlines its version leaves or references them by `@id`. Referenced pages are
//! fetched concurrently via a [`JoinSet`]. Versions are returned as raw NuGet
//! strings, sorted newest-first by their semver interpretation; the evaluation
//! layer converts them to semver for comparison.

use ::semver::Version;
use dependable_core::semver::nuget::nuget_to_semver;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;
use tokio::task::JoinSet;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://api.nuget.org";

/// Fetches package versions from a NuGet V3 registration API.
#[derive(Clone)]
pub struct NuGetFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct RegistrationIndex {
    #[serde(default)]
    items: Vec<RegistrationPage>,
}

#[derive(Deserialize)]
struct RegistrationPage {
    /// The page's own URL, present when its leaves are not inlined.
    #[serde(rename = "@id")]
    id: Option<String>,
    /// Inlined version leaves (present on small packages).
    items: Option<Vec<RegistrationLeaf>>,
}

#[derive(Deserialize)]
struct PageResponse {
    #[serde(default)]
    items: Vec<RegistrationLeaf>,
}

#[derive(Deserialize)]
struct RegistrationLeaf {
    #[serde(rename = "catalogEntry")]
    catalog_entry: CatalogEntry,
}

#[derive(Deserialize)]
struct CatalogEntry {
    version: String,
}

impl NuGetFetcher {
    /// A fetcher against the public NuGet gallery.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate NuGet V3 source.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for NuGetFetcher {
    fn registry_root(&self) -> Option<&str> {
        Some(&self.base_url)
    }

    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let id = name.to_ascii_lowercase();
            let url = format!(
                "{}/v3/registration5-gz-semver2/{id}/index.json",
                self.base_url
            );
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
            let index: RegistrationIndex = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            let mut versions: Vec<String> = Vec::new();
            let mut set: JoinSet<Result<Vec<String>, FetchError>> = JoinSet::new();
            for page in index.items {
                if let Some(leaves) = page.items {
                    versions.extend(leaves.into_iter().map(|l| l.catalog_entry.version));
                } else if let Some(page_url) = page.id {
                    let client = self.client.clone();
                    let pkg = name.to_string();
                    set.spawn(async move { fetch_page(&client, &page_url, &pkg).await });
                }
            }
            while let Some(joined) = set.join_next().await {
                match joined {
                    Ok(Ok(page_versions)) => versions.extend(page_versions),
                    Ok(Err(e)) => return Err(e),
                    Err(join_err) => {
                        return Err(FetchError::Decode {
                            package: name.to_string(),
                            detail: join_err.to_string(),
                        });
                    }
                }
            }

            sort_desc(&mut versions);
            Ok(FetchedVersions::new(versions))
        }
        .boxed()
    }
}

/// Fetch one referenced registration page and collect its version strings.
async fn fetch_page(
    client: &reqwest::Client,
    url: &str,
    package: &str,
) -> Result<Vec<String>, FetchError> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(FetchError::Status {
            code: resp.status().as_u16(),
            package: package.to_string(),
        });
    }
    let page: PageResponse = resp.json().await.map_err(|e| FetchError::Decode {
        package: package.to_string(),
        detail: e.to_string(),
    })?;
    Ok(page
        .items
        .into_iter()
        .map(|l| l.catalog_entry.version)
        .collect())
}

/// Sort raw NuGet versions newest-first by their semver interpretation.
///
/// The comparison is **total**: versions that compare equal are ordered by their
/// own strings, so a list built in a nondeterministic order (a `HashMap`'s
/// iteration, pages appended as their fetches complete) cannot come out of here in
/// a nondeterministic one.
fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| {
        let va = nuget_to_semver(a).and_then(|s| Version::parse(&s).ok());
        let vb = nuget_to_semver(b).and_then(|s| Version::parse(&s).ok());
        match (va, vb) {
            (Some(va), Some(vb)) => vb.cmp(&va).then_with(|| b.cmp(a)),
            _ => b.cmp(a),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NuGet appends remote registration pages in the order their fetches complete,
    /// and `AWSSDK.Core` — 24 remote pages — has its `4.0.7` group straddling a page
    /// boundary.
    ///
    /// The sort compares translations, and two versions can translate alike, so a
    /// stable sort left every tie group in the order it arrived in. Breaking the tie
    /// on the version string makes the order **total**, so one input set has exactly
    /// one sorted form however it was assembled.
    #[test]
    fn sorting_is_total_so_the_arrival_order_cannot_survive_it() {
        let published = ["4.0.7.2", "4.0.7.1", "4.0.7", "4.0.6"];
        let expected = {
            let mut first: Vec<String> = published.iter().map(|v| (*v).to_string()).collect();
            sort_desc(&mut first);
            first
        };
        // Every ordering of the same set, so nothing positional can survive.
        let mut order: Vec<usize> = (0..published.len()).collect();
        let mut seen = 0;
        loop {
            let mut shuffled: Vec<String> =
                order.iter().map(|i| published[*i].to_string()).collect();
            sort_desc(&mut shuffled);
            assert_eq!(shuffled, expected, "arrived as {order:?}");
            seen += 1;
            // Next permutation, in place.
            let Some(pivot) = (0..order.len() - 1)
                .rev()
                .find(|i| order[*i] < order[i + 1])
            else {
                break;
            };
            let swap = (pivot + 1..order.len())
                .rev()
                .find(|i| order[*i] > order[pivot])
                .expect("a successor above the pivot");
            order.swap(pivot, swap);
            order[pivot + 1..].reverse();
        }
        assert_eq!(seen, 24, "every ordering was tried");
    }
}
