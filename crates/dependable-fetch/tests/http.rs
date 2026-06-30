//! Hermetic HTTP tests against a local wiremock server (run in normal CI), plus
//! `#[ignore]`d live smoke tests (run via `mise run test:live`).

use dependable_fetch::{
    CratesIoFetcher, GoProxyFetcher, OsvClient, OsvQuery, PyPiFetcher, RegistryFetcher,
    build_client,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn crates_io_fetch_parses_and_sorts() {
    let server = MockServer::start().await;
    let body = concat!(
        "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
        "{\"name\":\"serde\",\"vers\":\"1.2.0\",\"yanked\":false}\n",
        "{\"name\":\"serde\",\"vers\":\"1.1.0\",\"yanked\":true}\n",
    );
    Mock::given(method("GET"))
        .and(path("/se/rd/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = CratesIoFetcher::with_registry(build_client().unwrap(), server.uri(), None);
    let fetched = fetcher.fetch_versions("serde").await.unwrap();
    assert_eq!(fetched.versions, vec!["1.2.0", "1.0.0"]);
    assert_eq!(fetched.latest_tag.as_deref(), Some("1.2.0"));
}

#[tokio::test]
async fn osv_querybatch_aligns_and_filters_ghsa() {
    let server = MockServer::start().await;
    let resp =
        r#"{"results":[{"vulns":[{"id":"RUSTSEC-2020-0001"},{"id":"GHSA-aaaa-bbbb-cccc"}]},{}]}"#;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_string(resp))
        .mount(&server)
        .await;

    let osv = OsvClient::with_url(
        build_client().unwrap(),
        format!("{}/v1/querybatch", server.uri()),
        false, // exclude GHSA
    );
    let queries = vec![
        OsvQuery {
            ecosystem: "crates.io".into(),
            name: "openssl".into(),
            version: "0.10.0".into(),
        },
        OsvQuery {
            ecosystem: "crates.io".into(),
            name: "serde".into(),
            version: "1.0.0".into(),
        },
    ];
    let out = osv.query_batch(&queries).await.unwrap();
    assert_eq!(out[0], vec!["RUSTSEC-2020-0001"]); // GHSA filtered out
    assert!(out[1].is_empty());
}

#[tokio::test]
async fn pypi_fetch_filters_yanked_and_sorts() {
    let server = MockServer::start().await;
    let body = r#"{"releases":{
        "1.0.0":[{"yanked":false}],
        "1.1.0":[{"yanked":true}],
        "2.0.0":[{"yanked":false}],
        "2.1.0a1":[{"yanked":false}]}}"#;
    Mock::given(method("GET"))
        .and(path("/flask/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = PyPiFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("flask").await.unwrap();
    // 1.1.0 is fully yanked; raw PEP 440 strings, newest-first by semver order.
    assert_eq!(fetched.versions, vec!["2.1.0a1", "2.0.0", "1.0.0"]);
}

#[tokio::test]
#[ignore = "hits the network (PyPI)"]
async fn live_pypi_flask_has_versions() {
    let fetcher = PyPiFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("flask").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
async fn go_proxy_lists_versions_strips_v_and_sorts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("v1.0.0\nv1.2.0\nv1.1.0\n"))
        .mount(&server)
        .await;

    let fetcher = GoProxyFetcher::with_proxy(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("github.com/foo/bar").await.unwrap();
    assert_eq!(fetched.versions, vec!["1.2.0", "1.1.0", "1.0.0"]);
}

#[tokio::test]
async fn go_proxy_falls_back_to_latest_when_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/example.com/m/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/example.com/m/@latest"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"Version":"v0.5.0"}"#))
        .mount(&server)
        .await;

    let fetcher = GoProxyFetcher::with_proxy(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("example.com/m").await.unwrap();
    assert_eq!(fetched.versions, vec!["0.5.0"]);
}

#[tokio::test]
async fn go_proxy_case_encodes_uppercase_module() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github.com/!azure/foo/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("v1.0.0\n"))
        .mount(&server)
        .await;

    let fetcher = GoProxyFetcher::with_proxy(build_client().unwrap(), server.uri());
    let fetched = fetcher
        .fetch_versions("github.com/Azure/foo")
        .await
        .unwrap();
    assert_eq!(fetched.versions, vec!["1.0.0"]);
}

#[tokio::test]
#[ignore = "hits the network (Go module proxy)"]
async fn live_go_proxy_has_versions() {
    let fetcher = GoProxyFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("golang.org/x/text").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
#[ignore = "hits the network (crates.io sparse index)"]
async fn live_crates_io_serde_has_versions() {
    let fetcher = CratesIoFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("serde").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
#[ignore = "hits the network (OSV API)"]
async fn live_osv_known_vulnerable_crate() {
    let osv = OsvClient::new(build_client().unwrap(), true);
    // `time` 0.2.7 has a well-known advisory (RUSTSEC-2020-0071).
    let queries = vec![OsvQuery {
        ecosystem: "crates.io".into(),
        name: "time".into(),
        version: "0.2.7".into(),
    }];
    let out = osv.query_batch(&queries).await.unwrap();
    assert!(
        !out[0].is_empty(),
        "expected at least one advisory for time 0.2.7"
    );
}
