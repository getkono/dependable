//! Error type for the fetch layer.

use thiserror::Error;

/// An error from a registry or OSV request.
///
/// `#[non_exhaustive]`: match with a wildcard arm so new variants are additive.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchError {
    /// A request that failed in transport: a timeout, a refused connection, a TLS or
    /// redirect failure.
    ///
    /// Built through the `From<reqwest::Error>` impl, which drops the request URL.
    /// reqwest's `Display` ends with ` for url (...)`, and a registry root can carry a
    /// credential in its path or query, or in userinfo on any request not built
    /// through a `RequestBuilder`; left in, it would reach the table output and the
    /// GitHub annotations verbatim. The ecosystem and package name are reported beside
    /// the error, so the URL adds nothing the reader lacks.
    #[error("http error: {0}")]
    Http(reqwest::Error),

    #[error("package `{0}` not found")]
    NotFound(String),

    #[error("registry returned status {code} for `{package}`")]
    Status { code: u16, package: String },

    /// A successful response that carried no versions at all.
    ///
    /// Distinct from [`NotFound`](Self::NotFound), which is the registry saying the
    /// package does not exist. A `200` with an empty version list is not that answer: a
    /// Nexus or Artifactory group repository whose upstream proxy is down serves exactly
    /// such a locally-merged document for a package that certainly does exist. Treating
    /// it as a 404 exempted it from a `--fail-on` gate, certifying a build against a
    /// dependency nothing was ever known about.
    #[error("registry listed no versions for `{package}`")]
    EmptyVersionList { package: String },

    /// The registry listed the package, and every release it lists is yanked.
    ///
    /// A permanent answer about this one package, exactly as a 404 is: Cargo will not
    /// resolve a yanked release for a new lockfile, and asking again returns the same
    /// list. Unlike [`EmptyVersionList`](Self::EmptyVersionList) nothing about it
    /// suggests the registry failed to answer.
    #[error("every published version of `{package}` is yanked")]
    AllYanked { package: String },

    #[error("failed to decode response for `{package}`: {detail}")]
    Decode { package: String, detail: String },

    #[error("OSV query failed: {0}")]
    Osv(String),

    #[error("OSV returned status {code}")]
    OsvStatus { code: u16 },
}

impl From<reqwest::Error> for FetchError {
    /// Wraps a transport error with its URL removed, so no credential embedded in a
    /// registry root survives into the message. See [`FetchError::Http`].
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error.without_url())
    }
}

impl FetchError {
    /// Whether the registry answered, permanently, that this package has nothing to
    /// offer: it does not exist, or every release of it is yanked.
    ///
    /// Such an answer is a per-dependency fact rather than a registry that could not be
    /// reached, so it neither marks the registry unreachable nor fails a gate.
    #[must_use]
    pub fn is_permanent_absence(&self) -> bool {
        matches!(self, Self::NotFound(_) | Self::AllYanked { .. })
    }

    /// Whether retrying might succeed.
    ///
    /// Rate limits and server faults are the registry saying "not now"; a timeout or a
    /// refused connection is the network doing the same. A 404 is an answer, and a
    /// decode failure is a response we will parse identically next time — retrying
    /// either only spends the user's time reaching the same conclusion.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Status { code, .. } | Self::OsvStatus { code } => {
                *code == 429 || (500..600).contains(code)
            }
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            // An empty-but-well-formed document parses the same way next time, so a
            // retry only spends the user's time reaching the same conclusion — the same
            // reasoning as a decode failure. It is still not a 404, so the gate refuses
            // to certify through it.
            Self::NotFound(_)
            | Self::AllYanked { .. }
            | Self::EmptyVersionList { .. }
            | Self::Decode { .. }
            | Self::Osv(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FetchError;

    /// A loopback URL on a port nothing listens on, so a request to it fails with a
    /// refused connection and no external network is involved.
    fn closed_loopback_root() -> String {
        // Bind then drop a listener so the port is free and closed.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("bind loopback")
            .port();
        format!("127.0.0.1:{port}")
    }

    /// Converts `raw`, after checking that reqwest's own message carries `secret` (so
    /// the test proves the conversion is what removes it), and checks the result.
    fn assert_redacted(raw: reqwest::Error, secret: &str) {
        assert!(raw.to_string().contains(secret), "{raw}");

        let error = FetchError::from(raw);
        let display = error.to_string();
        assert!(!display.contains(secret), "{display}");
        assert!(!format!("{error:?}").contains(secret), "{error:?}");
        assert!(display.starts_with("http error: "), "{display}");
        // The URL goes; the kind of failure stays, so retry still applies.
        assert!(error.is_transient());
    }

    /// A refused connection to a root carrying `user:secret@` does not print the
    /// credential.
    #[tokio::test]
    async fn http_error_display_omits_url_userinfo() {
        let url = format!(
            "http://user:secret@{}/index/se/rd/serde",
            closed_loopback_root()
        );
        // `Client::execute` keeps the userinfo in the URL it reports; the
        // `RequestBuilder` path moves it into a basic-auth header first, so this is
        // the route on which reqwest itself would print it.
        let request = reqwest::Request::new(reqwest::Method::GET, url.parse().expect("valid url"));
        let raw = reqwest::Client::new()
            .execute(request)
            .await
            .expect_err("nothing listens on a closed port");

        assert_redacted(raw, "secret");
    }

    /// A token carried in the path, which reqwest never strips, is not printed either.
    #[tokio::test]
    async fn http_error_display_omits_path_token() {
        let url = format!(
            "http://{}/tok-s3cr3t/npm/serde?auth=q-s3cr3t",
            closed_loopback_root()
        );
        let raw = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect_err("nothing listens on a closed port");

        assert_redacted(raw, "s3cr3t");
    }
}
