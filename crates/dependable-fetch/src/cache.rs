//! Caching layers. An in-process TTL cache (moka) sits in front of a persistent
//! on-disk cache ([`DiskCache`]): a moka miss consults the disk before the network,
//! so repeat and CI runs avoid re-fetching registry version lists.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moka::future::Cache;
use serde::{Deserialize, Serialize};

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

/// Default TTL for on-disk cache entries: 1 hour. Long enough to make repeat and
/// CI runs cheap, short enough that a freshly published version shows up soon.
pub(crate) const DISK_CACHE_TTL: Duration = Duration::from_secs(3600);

/// One cached registry response: the version list plus the wall-clock time it was
/// fetched (for TTL) and the package name (to detect the rare hash collision).
#[derive(Serialize, Deserialize)]
struct CacheEntry {
    /// Unix seconds at which the entry was written.
    fetched_at: u64,
    /// The package name the entry belongs to.
    name: String,
    /// The registry-native version list, newest-first.
    versions: Vec<String>,
}

/// A persistent, on-disk registry-response cache.
///
/// Entries live at `<root>/<ecosystem>/<hash(name)>.json` and expire after
/// [`DISK_CACHE_TTL`]. It sits below the in-process [`VersionsCache`]: the checker
/// consults it only on a moka miss, and every read/write is best-effort — a cache
/// failure degrades to a network fetch and never fails a check.
pub(crate) struct DiskCache {
    root: PathBuf,
    ttl: Duration,
}

impl DiskCache {
    /// A disk cache rooted at `root` with the given entry TTL.
    pub(crate) fn new(root: PathBuf, ttl: Duration) -> Self {
        Self { root, ttl }
    }

    /// The default cache root: `$XDG_CACHE_HOME/dependable`, else
    /// `$HOME/.cache/dependable`. Returns `None` when neither is set, which
    /// disables the disk cache gracefully. Windows cache-dir resolution
    /// (`%LOCALAPPDATA%`) is handled separately (see the Windows-support work).
    #[must_use]
    pub(crate) fn default_root() -> Option<PathBuf> {
        if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(xdg).join("dependable"));
        }
        let home = std::env::var_os("HOME").filter(|v| !v.is_empty())?;
        Some(PathBuf::from(home).join(".cache").join("dependable"))
    }

    /// The on-disk path for one `(ecosystem, name)` entry. The name is hashed so
    /// the filename is filesystem-safe regardless of scopes/slashes; the stored
    /// name in the entry guards against collisions.
    fn path_for(&self, ecosystem: &str, name: &str) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        self.root
            .join(ecosystem)
            .join(format!("{:016x}.json", hasher.finish()))
    }

    /// Read a fresh, non-expired entry for `(ecosystem, name)`, or `None` on a
    /// miss, an expired entry, a name mismatch, or any IO/parse error.
    #[must_use]
    pub(crate) async fn get(&self, ecosystem: &str, name: &str) -> Option<Vec<String>> {
        let bytes = tokio::fs::read(self.path_for(ecosystem, name)).await.ok()?;
        let entry: CacheEntry = serde_json::from_slice(&bytes).ok()?;
        if entry.name != name || now_secs().saturating_sub(entry.fetched_at) > self.ttl.as_secs() {
            return None;
        }
        Some(entry.versions)
    }

    /// Write (or overwrite) the entry for `(ecosystem, name)`. Best-effort: parent
    /// creation or write failures are swallowed so a check never fails on the cache.
    pub(crate) async fn put(&self, ecosystem: &str, name: &str, versions: &[String]) {
        self.put_at(ecosystem, name, versions, now_secs()).await;
    }

    /// [`DiskCache::put`] with an explicit `fetched_at`, so tests can write an
    /// entry with a past timestamp to exercise expiry.
    async fn put_at(&self, ecosystem: &str, name: &str, versions: &[String], fetched_at: u64) {
        let path = self.path_for(ecosystem, name);
        if let Some(parent) = path.parent()
            && tokio::fs::create_dir_all(parent).await.is_err()
        {
            return;
        }
        let entry = CacheEntry {
            fetched_at,
            name: name.to_string(),
            versions: versions.to_vec(),
        };
        if let Ok(bytes) = serde_json::to_vec(&entry) {
            let _ = tokio::fs::write(&path, bytes).await;
        }
    }
}

/// Wall-clock Unix seconds, saturating to 0 before the epoch (never panics).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrips_a_fresh_entry() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().to_path_buf(), DISK_CACHE_TTL);

        assert_eq!(cache.get("crates.io", "serde").await, None); // cold miss
        cache
            .put("crates.io", "serde", &["1.0.0".into(), "1.2.0".into()])
            .await;
        assert_eq!(
            cache.get("crates.io", "serde").await,
            Some(vec!["1.0.0".into(), "1.2.0".into()])
        );
    }

    #[tokio::test]
    async fn treats_expired_entries_as_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));

        // Written just over an hour ago -> older than the TTL -> a miss.
        cache
            .put_at("npm", "react", &["18.0.0".into()], now_secs() - 3601)
            .await;
        assert_eq!(cache.get("npm", "react").await, None);
    }

    #[tokio::test]
    async fn distinct_names_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().to_path_buf(), DISK_CACHE_TTL);

        cache.put("npm", "left-pad", &["1.3.0".into()]).await;
        cache.put("npm", "right-pad", &["1.0.1".into()]).await;
        assert_eq!(
            cache.get("npm", "left-pad").await,
            Some(vec!["1.3.0".into()])
        );
        assert_eq!(
            cache.get("npm", "right-pad").await,
            Some(vec!["1.0.1".into()])
        );
    }
}
