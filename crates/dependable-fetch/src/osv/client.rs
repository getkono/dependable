//! The OSV batch client with an in-process result cache.

use super::types::{BatchRequest, BatchResponse, Package, Query};
use crate::cache::{OsvCache, osv_cache};
use crate::error::FetchError;

const DEFAULT_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// Maximum version-entries per batch request (PRD §5.6).
const MAX_BATCH: usize = 500;

/// A single OSV query: does `(ecosystem, name, version)` have known vulns?
#[derive(Debug, Clone)]
pub struct OsvQuery {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// Queries the OSV `querybatch` endpoint, caching results in-process.
pub struct OsvClient {
    client: reqwest::Client,
    batch_url: String,
    cache: OsvCache,
    include_ghsa: bool,
}

impl OsvClient {
    /// A client against the public OSV API.
    #[must_use]
    pub fn new(client: reqwest::Client, include_ghsa: bool) -> Self {
        Self {
            client,
            batch_url: DEFAULT_BATCH_URL.to_string(),
            cache: osv_cache(),
            include_ghsa,
        }
    }

    /// A client against a custom batch URL (used in tests).
    #[must_use]
    pub fn with_url(
        client: reqwest::Client,
        batch_url: impl Into<String>,
        include_ghsa: bool,
    ) -> Self {
        Self {
            client,
            batch_url: batch_url.into(),
            cache: osv_cache(),
            include_ghsa,
        }
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

            let resp = self.client.post(&self.batch_url).json(&body).send().await?;
            if !resp.status().is_success() {
                return Err(FetchError::Osv(format!("status {}", resp.status())));
            }
            let parsed: BatchResponse = resp
                .json()
                .await
                .map_err(|e| FetchError::Osv(e.to_string()))?;

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
}
