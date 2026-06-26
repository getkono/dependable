//! Hermetic end-to-end tests for the high-level [`Checker`], driving a full
//! parse → fetch → evaluate → OSV scan over inline manifest content against a
//! local wiremock server that mocks both the crates.io sparse index and OSV.

use std::sync::Arc;

use dependable_fetch::{
    Checker, DependencyStatus, Ecosystem, JsrFetcher, ManifestKind, NpmFetcher, PackageSource,
    build_client,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MANIFEST: &str = r#"
[dependencies]
serde = "1"
time = "=0.2.7"
local-thing = { path = "../local" }
"#;

// serde is locked behind the latest (-> UpdateAvailable); time is pinned at the
// only available version (-> UpToDate, unless OSV flags it).
const LOCK: &str = r#"
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "time"
version = "0.2.7"
"#;

/// Mount the crates.io sparse-index GETs for serde and time.
async fn mount_index(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/se/rd/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"serde\",\"vers\":\"1.2.0\",\"yanked\":false}\n",
        )))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ti/me/time"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"name\":\"time\",\"vers\":\"0.2.7\",\"yanked\":false}\n"),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn check_manifest_classifies_and_scans() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    // Queries are built in declaration order over checkable deps: serde, then time.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"results":[{},{"vulns":[{"id":"RUSTSEC-2020-0071"}]}]}"#),
        )
        .mount(&server)
        .await;

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(format!("{}/v1/querybatch", server.uri()))
        .concurrency(8)
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();

    let by_name = |n: &str| {
        check
            .results
            .iter()
            .find(|r| r.item.name == n)
            .unwrap_or_else(|| panic!("missing result for {n}"))
    };

    assert_eq!(check.ecosystem, Ecosystem::Rust);
    assert!(check.warnings.is_empty());
    // serde is locked at 1.0.0 but 1.2.0 is available.
    assert_eq!(by_name("serde").status, DependencyStatus::UpdateAvailable);
    // time has a known advisory at its locked version.
    assert_eq!(by_name("time").status, DependencyStatus::Vulnerable);
    assert_eq!(
        by_name("time").current_vulnerabilities,
        vec!["RUSTSEC-2020-0071".to_string()]
    );
    // The path dependency is skipped, never fetched or queried.
    assert_eq!(by_name("local-thing").status, DependencyStatus::Local);
}

#[tokio::test]
async fn check_package_json_with_lockfile() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/react"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dist-tags":{"latest":"18.2.0"},"versions":{"18.0.0":{},"18.2.0":{}}}"#,
        ))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Npm,
            Arc::new(NpmFetcher::with_registry(client, server.uri())),
        )
        .vulnerabilities(false)
        .build()
        .unwrap();

    let manifest = r#"{ "dependencies": { "react": "^18.0.0", "local": "file:../x" } }"#;
    let lock = r#"{ "packages": { "node_modules/react": { "version": "18.0.0" } } }"#;
    let check = checker
        .check_manifest(ManifestKind::PackageJson, manifest, Some(lock))
        .await
        .unwrap();

    assert_eq!(check.ecosystem, Ecosystem::Npm);
    let react = check
        .results
        .iter()
        .find(|r| r.item.name == "react")
        .unwrap();
    assert_eq!(react.item.locked_version.as_deref(), Some("18.0.0"));
    assert_eq!(react.status, DependencyStatus::UpdateAvailable);
    let local = check
        .results
        .iter()
        .find(|r| r.item.name == "local")
        .unwrap();
    assert_eq!(local.status, DependencyStatus::Local);
}

#[tokio::test]
async fn check_deno_routes_jsr_and_npm() {
    let server = MockServer::start().await;
    // npm-sourced `chalk`
    Mock::given(method("GET"))
        .and(path("/chalk"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"versions":{"5.0.0":{},"5.3.0":{},"6.0.0":{}}}"#),
        )
        .mount(&server)
        .await;
    // jsr-sourced `@std/path`
    Mock::given(method("GET"))
        .and(path("/@std/path/meta.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"latest":"1.0.0","versions":{"1.0.0":{}}}"#),
        )
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Npm,
            Arc::new(NpmFetcher::with_registry(client.clone(), server.uri())),
        )
        .jsr_registry(Arc::new(JsrFetcher::with_registry(client, server.uri())))
        .vulnerabilities(false)
        .build()
        .unwrap();

    let manifest =
        r#"{ "imports": { "chalk": "npm:chalk@^5.0.0", "@std/path": "jsr:@std/path@^1.0.0" } }"#;
    let check = checker
        .check_manifest(ManifestKind::DenoJson, manifest, None)
        .await
        .unwrap();

    // Each item was fetched from its own registry (routing by source).
    let chalk = check
        .results
        .iter()
        .find(|r| r.item.name == "chalk")
        .unwrap();
    assert_eq!(chalk.item.source, PackageSource::Registry);
    assert_eq!(chalk.latest_available.as_deref(), Some("6.0.0"));
    let path = check
        .results
        .iter()
        .find(|r| r.item.name == "@std/path")
        .unwrap();
    assert_eq!(path.item.source, PackageSource::Jsr);
    assert_eq!(path.latest_available.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn vulnerabilities_disabled_skips_osv() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    // No POST mock mounted: if OSV were queried it would 404 and fail the check.

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();

    let by_name = |n: &str| check.results.iter().find(|r| r.item.name == n).unwrap();
    // Without the OSV scan, time stays at its version-only status.
    assert_eq!(by_name("time").status, DependencyStatus::UpToDate);
    assert_eq!(by_name("serde").status, DependencyStatus::UpdateAvailable);
    assert!(by_name("time").current_vulnerabilities.is_empty());
}

#[tokio::test]
async fn ghsa_filtering_respects_include_flag() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    // OSV reports only a GHSA advisory for time (slot 1; serde slot 0 is empty).
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"results":[{},{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc"}]}]}"#),
        )
        .mount(&server)
        .await;

    let osv_url = format!("{}/v1/querybatch", server.uri());

    // Default: GHSA excluded -> the advisory is filtered out, time is not vulnerable.
    let excluding = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(osv_url.clone())
        .build()
        .unwrap();
    let check = excluding
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let time = check
        .results
        .iter()
        .find(|r| r.item.name == "time")
        .unwrap();
    assert_eq!(time.status, DependencyStatus::UpToDate);

    // include_ghsa(true): the GHSA advisory counts, time is vulnerable.
    let including = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(osv_url)
        .include_ghsa(true)
        .build()
        .unwrap();
    let check = including
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let time = check
        .results
        .iter()
        .find(|r| r.item.name == "time")
        .unwrap();
    assert_eq!(time.status, DependencyStatus::Vulnerable);
    assert_eq!(
        time.current_vulnerabilities,
        vec!["GHSA-aaaa-bbbb-cccc".to_string()]
    );
}
