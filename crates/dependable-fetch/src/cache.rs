//! In-process TTL caches (moka). A persistent on-disk cache is deferred (V1.1).

use std::time::Duration;

use moka::future::Cache;

/// Caches OSV results, keyed by `(ecosystem, name, version)` → vulnerability IDs.
pub type OsvCache = Cache<(String, String, String), Vec<String>>;

/// A fresh OSV cache with a 10-minute TTL.
#[must_use]
pub fn osv_cache() -> OsvCache {
    Cache::builder()
        .time_to_live(Duration::from_secs(600))
        .max_capacity(10_000)
        .build()
}

/// Caches available versions, keyed by `(ecosystem, name)` → versions.
pub type VersionsCache = Cache<(String, String), Vec<String>>;

/// A fresh versions cache with a 5-minute TTL.
#[must_use]
pub fn versions_cache() -> VersionsCache {
    Cache::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(10_000)
        .build()
}
