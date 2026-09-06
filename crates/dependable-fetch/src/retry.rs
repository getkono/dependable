//! Retry with exponential backoff for transient registry and OSV failures.
//!
//! Every fetcher previously treated 403, 429, 500 and a timeout identically: one
//! attempt, then a per-package error. With `concurrency` defaulting to 20 against
//! registries that rate-limit, a large monorepo reliably provoked 429s — and a
//! rate-limited package became `DependencyStatus::Error`, which `--fail-on vulnerable`
//! ignored and the vulnerability scan skipped entirely. A transient failure turned into
//! a silently unaudited dependency.

use std::time::Duration;

use crate::error::FetchError;

/// How many times an operation is attempted in total.
const MAX_ATTEMPTS: u32 = 3;

/// Delay before the second attempt; doubled for each one after.
const BASE_DELAY: Duration = Duration::from_millis(200);

/// Run `operation`, retrying while it fails transiently.
///
/// Only [`FetchError::is_transient`] failures are retried: a 404 is an answer, and
/// repeating it wastes the user's time to reach the same conclusion.
///
/// The backoff is fixed rather than driven by `Retry-After`; the header is not currently
/// carried on the error, so a server asking for a longer pause than this gets the pause
/// this gives it.
pub(crate) async fn with_retry<F, Fut, T>(mut operation: F) -> Result<T, FetchError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, FetchError>>,
{
    let mut delay = BASE_DELAY;
    for attempt in 1..MAX_ATTEMPTS {
        match operation().await {
            Err(error) if error.is_transient() => {
                tracing::debug!(attempt, %error, "transient fetch failure; retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            settled => return settled,
        }
    }
    // The final attempt's result stands, transient or not.
    operation().await
}
