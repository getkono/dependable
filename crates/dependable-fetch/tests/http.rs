//! Hermetic HTTP tests against a local wiremock server (run in normal CI), plus
//! `#[ignore]`d live smoke tests (run via `mise run test:live`).

use dependable_fetch::{
    CratesIoFetcher, GoProxyFetcher, HexFetcher, JsrFetcher, NpmFetcher, NuGetFetcher, OsvClient,
    OsvQuery, PackagistFetcher, PubDevFetcher, PyPiFetcher, RegistryFetcher, build_client,
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
async fn npm_fetch_parses_versions_and_latest_tag() {
    let server = MockServer::start().await;
    let body = r#"{"name":"react","dist-tags":{"latest":"18.2.0"},
        "versions":{"18.0.0":{},"18.2.0":{},"18.1.0":{}}}"#;
    Mock::given(method("GET"))
        .and(path("/react"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = NpmFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("react").await.unwrap();
    assert_eq!(fetched.versions, vec!["18.2.0", "18.1.0", "18.0.0"]);
    assert_eq!(fetched.latest_tag.as_deref(), Some("18.2.0"));
}

#[tokio::test]
async fn jsr_fetch_parses_versions_filtering_yanked() {
    let server = MockServer::start().await;
    let body = r#"{"scope":"std","name":"path","latest":"1.0.0",
        "versions":{"1.0.0":{},"0.9.0":{"yanked":true},"0.8.0":{}}}"#;
    Mock::given(method("GET"))
        .and(path("/@std/path/meta.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = JsrFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("@std/path").await.unwrap();
    assert_eq!(fetched.versions, vec!["1.0.0", "0.8.0"]); // 0.9.0 yanked
    assert_eq!(fetched.latest_tag.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn packagist_fetch_parses_versions_and_strips_v() {
    let server = MockServer::start().await;
    let body = r#"{"packages":{"monolog/monolog":[
        {"version":"2.1.0"},{"version":"v2.0.0"},{"version":"2.2.0"}]}}"#;
    Mock::given(method("GET"))
        .and(path("/p2/monolog/monolog.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = PackagistFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("monolog/monolog").await.unwrap();
    assert_eq!(fetched.versions, vec!["2.2.0", "2.1.0", "2.0.0"]);
}

#[tokio::test]
#[ignore = "hits the network (Packagist)"]
async fn live_packagist_monolog_has_versions() {
    let fetcher = PackagistFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("monolog/monolog").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
async fn pub_dev_fetch_parses_versions_and_latest() {
    let server = MockServer::start().await;
    let body = r#"{"name":"http","latest":{"version":"1.1.0"},
        "versions":[{"version":"1.0.0"},{"version":"1.1.0"},{"version":"0.13.5"}]}"#;
    Mock::given(method("GET"))
        .and(path("/api/packages/http"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = PubDevFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("http").await.unwrap();
    assert_eq!(fetched.versions, vec!["1.1.0", "1.0.0", "0.13.5"]); // sorted newest-first
    assert_eq!(fetched.latest_tag.as_deref(), Some("1.1.0"));
}

#[tokio::test]
#[ignore = "hits the network (pub.dev)"]
async fn live_pub_dev_http_has_versions() {
    let fetcher = PubDevFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("http").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
async fn nuget_fetch_lowercases_id_inlines_and_follows_pages() {
    let server = MockServer::start().await;
    // The index inlines one page and references a second by `@id`.
    let index = format!(
        r#"{{"items":[
            {{"items":[
                {{"catalogEntry":{{"version":"12.0.3"}}}},
                {{"catalogEntry":{{"version":"13.0.1"}}}}
            ]}},
            {{"@id":"{}/page2.json"}}
        ]}}"#,
        server.uri()
    );
    Mock::given(method("GET"))
        // The package id is lowercased for the registration path.
        .and(path(
            "/v3/registration5-gz-semver2/newtonsoft.json/index.json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/page2.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"items":[{"catalogEntry":{"version":"13.0.3"}}]}"#),
        )
        .mount(&server)
        .await;

    let fetcher = NuGetFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("Newtonsoft.Json").await.unwrap();
    assert_eq!(fetched.versions, vec!["13.0.3", "13.0.1", "12.0.3"]); // sorted newest-first
    assert_eq!(fetched.latest_tag.as_deref(), Some("13.0.3"));
}

#[tokio::test]
#[ignore = "hits the network (NuGet)"]
async fn live_nuget_newtonsoft_has_versions() {
    let fetcher = NuGetFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("Newtonsoft.Json").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
async fn hex_fetch_parses_and_sorts_releases() {
    let server = MockServer::start().await;
    let body = r#"{"name":"phoenix","releases":[
        {"version":"1.7.9"},{"version":"1.7.10"},{"version":"1.6.0"}]}"#;
    Mock::given(method("GET"))
        .and(path("/api/packages/phoenix"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let fetcher = HexFetcher::with_registry(build_client().unwrap(), server.uri());
    let fetched = fetcher.fetch_versions("phoenix").await.unwrap();
    assert_eq!(fetched.versions, vec!["1.7.10", "1.7.9", "1.6.0"]); // sorted newest-first
    assert_eq!(fetched.latest_tag.as_deref(), Some("1.7.10"));
}

#[tokio::test]
#[ignore = "hits the network (Hex)"]
async fn live_hex_phoenix_has_versions() {
    let fetcher = HexFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("phoenix").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
#[ignore = "hits the network (npm registry)"]
async fn live_npm_react_has_versions() {
    let fetcher = NpmFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("react").await.unwrap();
    assert!(!fetched.versions.is_empty());
}

#[tokio::test]
#[ignore = "hits the network (JSR)"]
async fn live_jsr_std_path_has_versions() {
    let fetcher = JsrFetcher::new(build_client().unwrap());
    let fetched = fetcher.fetch_versions("@std/path").await.unwrap();
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
