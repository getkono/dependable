//! Hermetic tests for the package-metadata layer (wiremock; no real network).

use dependable_fetch::{
    CratesIoFetcher, HexFetcher, NpmFetcher, OwnerKind, PackagistFetcher, PyPiFetcher,
    RegistryFetcher, build_client,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn mount(server: &MockServer, at: &'static str, body: &'static str) -> impl Future<Output = ()> {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
}

#[tokio::test]
async fn crates_io_reads_metadata_and_owners() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/crates/serde",
        r#"{
  "crate": { "description": "Serialization framework",
             "homepage": "https://serde.rs",
             "documentation": "https://docs.rs/serde",
             "repository": "https://github.com/serde-rs/serde",
             "downloads": 5000000 },
  "versions": [ { "num": "1.0.228", "license": "MIT OR Apache-2.0", "yanked": false,
                  "rust_version": "1.61", "created_at": "2025-01-02T03:04:05Z" } ]
}"#,
    )
    .await;
    mount(
        &server,
        "/crates/serde/owners",
        r#"{ "users": [ { "login": "dtolnay", "name": "David Tolnay",
                         "url": "https://github.com/dtolnay" },
                       { "login": "oli-obk", "name": null } ],
             "teams": [ { "login": "github:rust-lang:libs", "name": "libs" } ] }"#,
    )
    .await;

    let fetcher =
        CratesIoFetcher::new(build_client().unwrap()).with_api_url(format!("{}/", server.uri()));
    let meta = fetcher
        .fetch_metadata("serde")
        .await
        .expect("request")
        .expect("metadata");

    assert_eq!(
        meta.repository.as_deref(),
        Some("https://github.com/serde-rs/serde")
    );
    assert_eq!(meta.license.as_deref(), Some("MIT OR Apache-2.0"));
    assert_eq!(meta.homepage.as_deref(), Some("https://serde.rs"));
    assert_eq!(meta.documentation.as_deref(), Some("https://docs.rs/serde"));
    assert_eq!(meta.downloads, Some(5_000_000));
    assert_eq!(meta.msrv.as_deref(), Some("1.61"));
    assert_eq!(meta.last_published.as_deref(), Some("2025-01-02T03:04:05Z"));
    assert!(!meta.yanked);
    assert_eq!(meta.owners.len(), 3, "two users and one team");

    assert_eq!(meta.owners[0].name.as_deref(), Some("David Tolnay"));
    assert_eq!(
        meta.owners[0].login.as_deref(),
        Some("dtolnay"),
        "the login survives alongside the display name, not instead of it"
    );
    assert_eq!(
        meta.owners[0].url.as_deref(),
        Some("https://github.com/dtolnay")
    );
    assert_eq!(meta.owners[0].kind, OwnerKind::User);
    assert_eq!(
        meta.owners[0].email, None,
        "crates.io does not publish owner emails"
    );

    assert_eq!(meta.owners[1].name, None);
    assert_eq!(
        meta.owners[1].display_name(),
        Some("oli-obk"),
        "an owner without a display name falls back to its login"
    );

    assert_eq!(
        meta.owners[2].kind,
        OwnerKind::Team,
        "a team owner is reported, not dropped"
    );
    assert_eq!(meta.owners[2].name.as_deref(), Some("libs"));
}

#[tokio::test]
async fn crates_io_reports_a_team_only_crate_as_owned() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/crates/tokio",
        r#"{ "crate": {}, "versions": [] }"#,
    )
    .await;
    // Some crates are owned solely by a team; `users` is then empty.
    mount(
        &server,
        "/crates/tokio/owners",
        r#"{ "users": [], "teams": [ { "login": "github:tokio-rs:core", "name": "core" } ] }"#,
    )
    .await;

    let fetcher = CratesIoFetcher::new(build_client().unwrap()).with_api_url(server.uri());
    let meta = fetcher
        .fetch_metadata("tokio")
        .await
        .expect("request")
        .expect("metadata");

    assert_eq!(meta.owners.len(), 1);
    assert_eq!(meta.owners[0].kind, OwnerKind::Team);
}

#[tokio::test]
async fn crates_io_still_returns_metadata_when_owners_fail() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/crates/serde",
        r#"{ "crate": { "repository": "https://github.com/serde-rs/serde" }, "versions": [] }"#,
    )
    .await;
    // No `/owners` mock: wiremock answers 404, which must not sink the whole call.

    let fetcher = CratesIoFetcher::new(build_client().unwrap()).with_api_url(server.uri());
    let meta = fetcher
        .fetch_metadata("serde")
        .await
        .expect("request")
        .expect("metadata");

    assert_eq!(
        meta.repository.as_deref(),
        Some("https://github.com/serde-rs/serde")
    );
    assert!(
        meta.owners.is_empty(),
        "owners are enrichment, not the point"
    );
}

#[tokio::test]
async fn an_alternate_registry_has_no_crates_io_api() {
    // An alternate sparse index is not crates.io; asking crates.io about its
    // crates would return the wrong package, so we must report nothing instead.
    let fetcher = CratesIoFetcher::with_registry(
        build_client().unwrap(),
        "sparse+https://internal.example.com/index/",
        None,
    );
    assert_eq!(
        fetcher.fetch_metadata("internal-crate").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn the_public_index_url_still_reaches_the_crates_io_api() {
    // The CLI always constructs the fetcher with an explicit index URL, which is
    // the public one by default. That is still crates.io, so metadata must work.
    let fetcher =
        CratesIoFetcher::with_registry(build_client().unwrap(), "https://index.crates.io", None);
    // Not a live call: only the decision about whether an API exists is checked,
    // by confirming it does not short-circuit to `Ok(None)` the way an alternate
    // registry does. A real request is covered by the mocked tests above.
    let alternate = CratesIoFetcher::with_registry(
        build_client().unwrap(),
        "sparse+https://internal.example.com/index/",
        None,
    );
    assert!(
        fetcher.has_metadata_api(),
        "the public index must expose the crates.io API"
    );
    assert!(
        !alternate.has_metadata_api(),
        "an alternate index must not be asked about crates.io"
    );
}

#[tokio::test]
async fn crates_io_reports_a_missing_crate_as_not_found() {
    let server = MockServer::start().await;
    let fetcher = CratesIoFetcher::new(build_client().unwrap()).with_api_url(server.uri());
    assert!(fetcher.fetch_metadata("nope").await.is_err());
}

#[tokio::test]
async fn npm_reads_the_full_packument() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/react",
        r#"{
  "description": "React is a JavaScript library",
  "homepage": "https://react.dev/",
  "license": "MIT",
  "repository": { "type": "git", "url": "git+https://github.com/facebook/react.git" },
  "maintainers": [ { "name": "fb", "email": "opensource@fb.com" } ],
  "dist-tags": { "latest": "18.2.0" },
  "time": { "modified": "2024-01-01T00:00:00Z", "18.2.0": "2022-06-14T19:46:38Z" }
}"#,
    )
    .await;

    let fetcher = NpmFetcher::with_registry(build_client().unwrap(), server.uri());
    let meta = fetcher.fetch_metadata("react").await.unwrap().unwrap();

    assert_eq!(
        meta.description.as_deref(),
        Some("React is a JavaScript library")
    );
    assert_eq!(
        meta.repository.as_deref(),
        Some("git+https://github.com/facebook/react.git")
    );
    assert_eq!(meta.license.as_deref(), Some("MIT"));
    assert_eq!(meta.owners.len(), 1);
    assert_eq!(meta.owners[0].name.as_deref(), Some("fb"));
    assert_eq!(
        meta.owners[0].email.as_deref(),
        Some("opensource@fb.com"),
        "npm publishes maintainer emails and we keep them"
    );
    assert_eq!(
        meta.last_published.as_deref(),
        Some("2022-06-14T19:46:38Z"),
        "the publish date is the one for the `latest` version, not `modified`"
    );
}

#[tokio::test]
async fn npm_accepts_the_shorthand_repository_form() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/tiny",
        r#"{ "repository": "github:owner/tiny", "dist-tags": {} }"#,
    )
    .await;

    let fetcher = NpmFetcher::with_registry(build_client().unwrap(), server.uri());
    let meta = fetcher.fetch_metadata("tiny").await.unwrap().unwrap();
    assert_eq!(meta.repository.as_deref(), Some("github:owner/tiny"));
}

#[tokio::test]
async fn pypi_prefers_a_source_project_url() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/requests/json",
        r#"{
  "info": { "summary": "HTTP for Humans", "home_page": "https://requests.readthedocs.io",
            "license": "Apache 2.0", "author": "Kenneth Reitz",
    "author_email": "me@kennethreitz.org", "maintainer": "Nate Prewitt", "yanked": false,
            "project_urls": { "Source": "https://github.com/psf/requests",
                              "Documentation": "https://requests.readthedocs.io" } },
  "urls": [ { "upload_time_iso_8601": "2023-05-22T15:12:42.123456Z" } ]
}"#,
    )
    .await;

    let fetcher = PyPiFetcher::with_registry(build_client().unwrap(), server.uri());
    let meta = fetcher.fetch_metadata("requests").await.unwrap().unwrap();

    assert_eq!(
        meta.repository.as_deref(),
        Some("https://github.com/psf/requests")
    );
    assert_eq!(meta.description.as_deref(), Some("HTTP for Humans"));
    assert_eq!(meta.owners.len(), 2, "author and a distinct maintainer");
    assert_eq!(meta.owners[0].name.as_deref(), Some("Kenneth Reitz"));
    assert_eq!(meta.owners[0].email.as_deref(), Some("me@kennethreitz.org"));
    assert_eq!(meta.owners[1].name.as_deref(), Some("Nate Prewitt"));
    assert_eq!(
        meta.documentation.as_deref(),
        Some("https://requests.readthedocs.io")
    );
}

#[tokio::test]
async fn packagist_joins_multiple_licenses() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/p2/monolog/monolog.json",
        r#"{ "packages": { "monolog/monolog": [
            { "version": "2.1.0", "description": "Logging for PHP",
              "license": ["MIT", "Apache-2.0"],
              "authors": [ { "name": "Jordi Boggiano", "email": "j.boggiano@seld.be",
                             "homepage": "https://seld.be" } ],
              "source": { "url": "https://github.com/Seldaek/monolog.git" },
              "time": "2020-05-22T08:12:19+00:00" } ] } }"#,
    )
    .await;

    let fetcher = PackagistFetcher::with_registry(build_client().unwrap(), server.uri());
    let meta = fetcher
        .fetch_metadata("monolog/monolog")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(meta.license.as_deref(), Some("MIT OR Apache-2.0"));
    assert_eq!(
        meta.repository.as_deref(),
        Some("https://github.com/Seldaek/monolog.git")
    );
    assert_eq!(meta.owners.len(), 1);
    assert_eq!(meta.owners[0].name.as_deref(), Some("Jordi Boggiano"));
    assert_eq!(meta.owners[0].email.as_deref(), Some("j.boggiano@seld.be"));
    assert_eq!(meta.owners[0].url.as_deref(), Some("https://seld.be"));
}

#[tokio::test]
async fn hex_reads_links_and_downloads() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/api/packages/phoenix",
        r#"{ "meta": { "description": "Productive web framework",
                       "licenses": ["MIT"],
                       "maintainers": ["Chris McCord"],
                       "links": { "GitHub": "https://github.com/phoenixframework/phoenix",
                                  "Homepage": "https://www.phoenixframework.org" } },
             "downloads": { "all": 12345 },
             "docs_html_url": "https://hexdocs.pm/phoenix/",
             "releases": [ { "version": "1.7.10", "inserted_at": "2023-11-01T10:00:00Z" } ] }"#,
    )
    .await;

    let fetcher = HexFetcher::with_registry(build_client().unwrap(), server.uri());
    let meta = fetcher.fetch_metadata("phoenix").await.unwrap().unwrap();

    assert_eq!(
        meta.repository.as_deref(),
        Some("https://github.com/phoenixframework/phoenix")
    );
    assert_eq!(
        meta.homepage.as_deref(),
        Some("https://www.phoenixframework.org")
    );
    assert_eq!(
        meta.documentation.as_deref(),
        Some("https://hexdocs.pm/phoenix/")
    );
    assert_eq!(meta.downloads, Some(12345));
    assert_eq!(meta.last_published.as_deref(), Some("2023-11-01T10:00:00Z"));
}

#[tokio::test]
async fn a_registry_without_a_metadata_endpoint_reports_none() {
    // Go, NuGet, JSR and pub.dev keep the trait default until an endpoint is wired.
    let fetcher = dependable_fetch::GoProxyFetcher::new(build_client().unwrap());
    assert_eq!(
        fetcher.fetch_metadata("golang.org/x/text").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn the_checker_caches_metadata_across_calls() {
    use dependable_fetch::{Checker, Ecosystem};

    let server = MockServer::start().await;
    // `expect(1)` fails the test on drop if the endpoint is hit more than once.
    Mock::given(method("GET"))
        .and(path("/crates/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{ "crate": { "repository": "https://github.com/serde-rs/serde" }, "versions": [] }"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    // Register a crates.io fetcher whose API base is the mock server.
    let fetcher = std::sync::Arc::new(
        CratesIoFetcher::new(build_client().unwrap()).with_api_url(server.uri()),
    );
    let checker = Checker::builder()
        .registry(Ecosystem::Rust, fetcher)
        .build()
        .expect("checker");

    let first = checker
        .fetch_metadata(Ecosystem::Rust, "serde")
        .await
        .expect("first");
    let second = checker
        .fetch_metadata(Ecosystem::Rust, "serde")
        .await
        .expect("second");

    assert_eq!(first, second);
    assert!(first.is_some());
}

// --- live smoke tests (`mise run test:live`) ------------------------------

#[tokio::test]
#[ignore = "hits the network; run with `mise run test:live`"]
async fn live_crates_io_metadata() {
    let fetcher = CratesIoFetcher::new(build_client().unwrap());
    let meta = fetcher
        .fetch_metadata("serde")
        .await
        .expect("request")
        .expect("crates.io publishes metadata for serde");

    assert!(
        meta.repository.is_some_and(|r| r.contains("serde")),
        "a repository URL is the headline field"
    );
    assert!(meta.license.is_some(), "license");
    assert!(meta.downloads.is_some_and(|d| d > 0), "downloads");
    assert!(!meta.owners.is_empty(), "owners");
}

#[tokio::test]
#[ignore = "hits the network; run with `mise run test:live`"]
async fn live_npm_metadata() {
    let fetcher = NpmFetcher::new(build_client().unwrap());
    let meta = fetcher.fetch_metadata("react").await.unwrap().unwrap();
    assert!(meta.repository.is_some_and(|r| r.contains("react")));
    assert!(meta.license.is_some());
}

#[tokio::test]
#[ignore = "hits the network; run with `mise run test:live`"]
async fn live_pypi_metadata() {
    let fetcher = PyPiFetcher::new(build_client().unwrap());
    let meta = fetcher.fetch_metadata("requests").await.unwrap().unwrap();
    assert!(meta.description.is_some());
}

#[tokio::test]
#[ignore = "hits the network; run with `mise run test:live`"]
async fn live_hex_metadata() {
    let fetcher = HexFetcher::new(build_client().unwrap());
    let meta = fetcher.fetch_metadata("phoenix").await.unwrap().unwrap();
    assert!(meta.repository.is_some(), "hex links carry the repository");
}

#[tokio::test]
#[ignore = "hits the network; run with `mise run test:live`"]
async fn live_packagist_metadata() {
    let fetcher = PackagistFetcher::new(build_client().unwrap());
    let meta = fetcher
        .fetch_metadata("monolog/monolog")
        .await
        .unwrap()
        .unwrap();
    assert!(meta.license.is_some());
}
