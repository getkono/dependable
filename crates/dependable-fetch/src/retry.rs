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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn status(code: u16) -> FetchError {
        FetchError::Status {
            code,
            package: "pkg".to_owned(),
        }
    }

    /// Rate limits and server faults are retried; every answer a registry means is not.
    #[test]
    fn only_rate_limits_and_server_faults_are_transient() {
        for code in [429, 500, 502, 503, 599] {
            assert!(status(code).is_transient(), "{code}");
            assert!(FetchError::OsvStatus { code }.is_transient(), "osv {code}");
        }
        for code in [400, 401, 403, 404, 410, 451] {
            assert!(!status(code).is_transient(), "{code}");
            assert!(!FetchError::OsvStatus { code }.is_transient(), "osv {code}");
        }
        assert!(!FetchError::NotFound("pkg".to_owned()).is_transient());
        assert!(
            !FetchError::Decode {
                package: "pkg".to_owned(),
                detail: "bad".to_owned(),
            }
            .is_transient()
        );
        assert!(!FetchError::Osv("short body".to_owned()).is_transient());
    }

    /// A transient failure followed by an answer yields the answer, on the second try.
    #[tokio::test]
    async fn a_transient_failure_is_retried_until_it_answers() {
        let calls = AtomicU32::new(0);
        let result = with_retry(|| async {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(status(503))
            } else {
                Ok(7)
            }
        })
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A 404 is an answer, and is returned after one attempt.
    #[tokio::test]
    async fn a_not_found_is_not_retried() {
        let calls = AtomicU32::new(0);
        let result: Result<(), _> = with_retry(|| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(FetchError::NotFound("pkg".to_owned()))
        })
        .await;
        assert!(matches!(result, Err(FetchError::NotFound(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A failure that never clears is attempted exactly `MAX_ATTEMPTS` times, and the
    /// last error is what the caller sees.
    #[tokio::test]
    async fn a_persistent_transient_failure_stops_at_the_attempt_bound() {
        let calls = AtomicU32::new(0);
        let result: Result<(), _> = with_retry(|| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(status(429))
        })
        .await;
        assert!(matches!(result, Err(FetchError::Status { code: 429, .. })));
        assert_eq!(calls.load(Ordering::SeqCst), MAX_ATTEMPTS);
    }
}
