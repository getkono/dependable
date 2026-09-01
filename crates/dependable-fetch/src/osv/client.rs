//! The OSV client: a batched "is this version affected?" query and a detailed
//! "tell me everything about it" query, each with its own in-process cache.
//!
//! The two endpoints answer different questions at very different costs, so they
//! are kept separate. `querybatch` returns bare IDs for up to 500 versions in one
//! request and is what every check runs. `query` returns the *full* records for
//! one exact version — one request per package version, not per advisory — and is
//! only issued when a caller asks for enriched advisories.

use std::sync::Arc;
use std::time::Duration;

use dependable_core::result::Advisory;
use moka::future::Cache;

use super::advisory::advisory_from_wire;
use super::types::{BatchRequest, BatchResponse, DetailRequest, DetailResponse, Package, Query};
use crate::cache::{OsvCache, osv_cache};
use crate::error::FetchError;

const DEFAULT_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// Default OSV detail endpoint, used when the client is built with defaults.
const DEFAULT_QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// Maximum version-entries per batch request (PRD §5.6).
const MAX_BATCH: usize = 500;

/// Maximum detail pages followed for one package version. OSV has never paginated
/// a single-version query in practice; the bound exists so a server that starts
/// doing so cannot spin a check indefinitely.
const MAX_DETAIL_PAGES: usize = 10;

/// Caches full advisory records, keyed exactly like [`OsvCache`] by
/// `(ecosystem, name, version)` so the two stay aligned.
///
/// Declared here rather than beside the other caches because it is the detail
/// query's own concern. The value is behind an [`Arc`] because a record carries
/// multi-kilobyte Markdown and the cache clones on every read, and the capacity
/// is two orders of magnitude below the ID cache's for the same reason.
type OsvDetailCache = Cache<(String, String, String), Arc<Vec<Advisory>>>;

/// A fresh advisory-detail cache with a 10-minute TTL, matching the ID cache.
fn osv_detail_cache() -> OsvDetailCache {
    Cache::builder()
        .time_to_live(Duration::from_secs(600))
        .max_capacity(1_000)
        .build()
}

/// Derive the detail endpoint from a batch endpoint.
///
/// The two differ by a suffix (`/v1/querybatch` vs `/v1/query`), so a caller that
/// has already pointed the client at a batch URL — every test, and the CLI's
/// `--osv-url` — gets a working detail URL without configuring a second one.
fn derive_query_url(batch_url: &str) -> String {
    if let Some(stripped) = batch_url.strip_suffix("batch") {
        return stripped.to_string();
    }
    match batch_url.rfind('/') {
        Some(index) => format!("{}/query", &batch_url[..index]),
        None => DEFAULT_QUERY_URL.to_string(),
    }
}

/// A single OSV query: does `(ecosystem, name, version)` have known vulns?
#[derive(Debug, Clone)]
pub struct OsvQuery {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// Queries the OSV `querybatch` and `query` endpoints, caching results in-process.
pub struct OsvClient {
    client: reqwest::Client,
    batch_url: String,
    query_url: String,
    cache: OsvCache,
    detail_cache: OsvDetailCache,
    include_ghsa: bool,
}

impl OsvClient {
    /// A client against the public OSV API.
    #[must_use]
    pub fn new(client: reqwest::Client, include_ghsa: bool) -> Self {
        Self {
            client,
            batch_url: DEFAULT_BATCH_URL.to_string(),
            query_url: DEFAULT_QUERY_URL.to_string(),
            cache: osv_cache(),
            detail_cache: osv_detail_cache(),
            include_ghsa,
        }
    }

    /// A client against a custom batch URL (used in tests).
    ///
    /// The detail endpoint is derived from `batch_url`, so pointing the client at
    /// a mock or a mirror configures both queries at once. Override it with
    /// [`OsvClient::with_query_url`] if the two do not sit side by side.
    #[must_use]
    pub fn with_url(
        client: reqwest::Client,
        batch_url: impl Into<String>,
        include_ghsa: bool,
    ) -> Self {
        let batch_url = batch_url.into();
        let query_url = derive_query_url(&batch_url);
        Self {
            client,
            batch_url,
            query_url,
            cache: osv_cache(),
            detail_cache: osv_detail_cache(),
            include_ghsa,
        }
    }

    /// Override the detail endpoint, replacing the one derived from the batch URL.
    #[must_use]
    pub fn with_query_url(mut self, url: impl Into<String>) -> Self {
        self.query_url = url.into();
        self
    }

    /// Query OSV for each input, returning vulnerability IDs index-aligned to
    /// `queries`. Cache hits are served first; misses are chunked (≤500) and
    /// POSTed, then cached.
    ///
    /// # Errors
    /// Returns [`FetchError::Osv`] / [`FetchError::Http`] on request failure.
    pub async fn query_batch(&self, queries: &[OsvQuery]) -> Result<Vec<Vec<String>>, FetchError> {
        let mut results = vec![Vec::new(); queries.len()];
        let mut pending: Vec<usize> = Vec::new();

        for (i, q) in queries.iter().enumerate() {
            let key = (q.ecosystem.clone(), q.name.clone(), q.version.clone());
            if let Some(hit) = self.cache.get(&key).await {
                results[i] = hit;
            } else {
                pending.push(i);
            }
        }

        for chunk in pending.chunks(MAX_BATCH) {
            let body = BatchRequest {
                queries: chunk
                    .iter()
                    .map(|&i| {
                        let q = &queries[i];
                        Query {
                            version: q.version.clone(),
                            package: Package {
                                name: q.name.clone(),
                                ecosystem: q.ecosystem.clone(),
                            },
                        }
                    })
                    .collect(),
            };

            let parsed: BatchResponse = crate::retry::with_retry(|| async {
                let resp = self.client.post(&self.batch_url).json(&body).send().await?;
                if !resp.status().is_success() {
                    return Err(FetchError::OsvStatus {
                        code: resp.status().as_u16(),
                    });
                }
                resp.json::<BatchResponse>()
                    .await
                    .map_err(|e| FetchError::Osv(e.to_string()))
            })
            .await?;

            // One result per query, in order, is the API's contract. A short body used
            // to leave the unanswered slots empty — recorded as "no vulnerabilities" and
            // written into the cache for ten minutes, so even a retry in the same process
            // could not recover. A truncated answer is an error, not a clean bill.
            if parsed.results.len() < chunk.len() {
                return Err(FetchError::Osv(format!(
                    "querybatch answered {} of {} queries",
                    parsed.results.len(),
                    chunk.len()
                )));
            }

            for (slot, &i) in chunk.iter().enumerate() {
                let ids: Vec<String> = parsed
                    .results
                    .get(slot)
                    .map(|r| {
                        r.vulns
                            .iter()
                            .map(|v| v.id.clone())
                            .filter(|id| self.include_ghsa || !id.starts_with("GHSA-"))
                            .collect()
                    })
                    .unwrap_or_default();
                let q = &queries[i];
                let key = (q.ecosystem.clone(), q.name.clone(), q.version.clone());
                self.cache.insert(key, ids.clone()).await;
                results[i] = ids;
            }
        }

        Ok(results)
    }

    /// Fetch the full advisory records for one exact package version.
    ///
    /// One HTTP request per uncached `(ecosystem, name, version)` — OSV returns
    /// every advisory affecting that version in a single response, so this does
    /// not scale with the advisory count. Two cheaper paths come first: an entry
    /// in the detail cache, and an *empty* entry in the ID cache, which already
    /// proves the version is clean under the identical GHSA filter and so needs
    /// no request at all.
    ///
    /// The same GHSA filter as [`OsvClient::query_batch`] applies, so an enriched
    /// result never disagrees with the check that produced it.
    ///
    /// # Errors
    /// Returns [`FetchError::Osv`] / [`FetchError::Http`] on request failure.
    pub async fn query_detail(&self, query: &OsvQuery) -> Result<Vec<Advisory>, FetchError> {
        let key = (
            query.ecosystem.clone(),
            query.name.clone(),
            query.version.clone(),
        );
        if let Some(hit) = self.detail_cache.get(&key).await {
            return Ok(hit.as_ref().clone());
        }
        if let Some(ids) = self.cache.get(&key).await
            && ids.is_empty()
        {
            return Ok(Vec::new());
        }

        let mut advisories: Vec<Advisory> = Vec::new();
        let mut page_token: Option<String> = None;
        let mut pages = 0usize;
        let mut complete = true;
        loop {
            let body = DetailRequest {
                version: query.version.clone(),
                package: Package {
                    name: query.name.clone(),
                    ecosystem: query.ecosystem.clone(),
                },
                page_token: page_token.clone(),
            };
            let resp = self.client.post(&self.query_url).json(&body).send().await?;
            if !resp.status().is_success() {
                return Err(FetchError::OsvStatus {
                    code: resp.status().as_u16(),
                });
            }
            let parsed: DetailResponse = resp
                .json()
                .await
                .map_err(|e| FetchError::Osv(e.to_string()))?;

            for vuln in parsed.vulns {
                if !self.include_ghsa && vuln.id.starts_with("GHSA-") {
                    continue;
                }
                advisories.push(advisory_from_wire(vuln, &query.ecosystem, &query.name));
            }

            pages += 1;
            page_token = parsed.next_page_token.filter(|token| !token.is_empty());
            if page_token.is_none() {
                break;
            }
            if pages >= MAX_DETAIL_PAGES {
                tracing::debug!(
                    package = %query.name,
                    version = %query.version,
                    "OSV advisory detail pagination bound reached; returning a partial list"
                );
                complete = false;
                break;
            }
        }

        let cached = Arc::new(advisories);
        self.detail_cache.insert(key.clone(), cached.clone()).await;
        // Back-fill the ID cache so a later batch query costs nothing — but only
        // from a complete list, since a truncated one would cache away advisories.
        if complete {
            let ids: Vec<String> = cached.iter().map(|a| a.id.clone()).collect();
            self.cache.insert(key, ids).await;
        }
        Ok(cached.as_ref().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_detail_url_from_a_batch_url() {
        assert_eq!(
            derive_query_url("https://api.osv.dev/v1/querybatch"),
            "https://api.osv.dev/v1/query"
        );
        assert_eq!(
            derive_query_url("http://127.0.0.1:8080/v1/querybatch"),
            "http://127.0.0.1:8080/v1/query"
        );
    }

    #[test]
    fn replaces_the_final_segment_when_there_is_no_batch_suffix() {
        assert_eq!(
            derive_query_url("https://mirror.test/osv/lookup"),
            "https://mirror.test/osv/query"
        );
    }

    #[test]
    fn an_explicit_detail_url_overrides_the_derived_one() {
        let client = OsvClient::with_url(
            reqwest::Client::new(),
            "https://api.osv.dev/v1/querybatch",
            false,
        );
        assert_eq!(client.query_url, "https://api.osv.dev/v1/query");
        let client = client.with_query_url("https://elsewhere.test/lookup");
        assert_eq!(client.query_url, "https://elsewhere.test/lookup");
        assert_eq!(client.batch_url, "https://api.osv.dev/v1/querybatch");
    }
}
