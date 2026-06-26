//! Hermetic end-to-end tests for the high-level [`Checker`], driving a full
//! parse → fetch → evaluate → OSV scan over inline manifest content against a
//! local wiremock server that mocks both the crates.io sparse index and OSV.

use std::sync::Arc;

use dependable_fetch::{
    Checker, DependencyStatus, Ecosystem, ManifestKind, PyPiFetcher, build_client,
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
async fn check_requirements_txt_pep440() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"releases":{"2.0.0":[{"yanked":false}],"3.1.0":[{"yanked":false}],"3.2.0a1":[{"yanked":false}]}}"#,
        ))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Python,
            Arc::new(PyPiFetcher::with_registry(client, server.uri())),
        )
        .vulnerabilities(false)
        .build()
        .unwrap();

    // `==2.0.0` pins below the latest; the 3.2.0a1 pre-release is excluded by default.
    let check = checker
        .check_manifest(ManifestKind::RequirementsTxt, "flask==2.0.0\n", None)
        .await
        .unwrap();

    assert_eq!(check.ecosystem, Ecosystem::Python);
    let flask = check
        .results
        .iter()
        .find(|r| r.item.name == "flask")
        .unwrap();
    assert_eq!(flask.status, DependencyStatus::UpdateAvailable);
    assert_eq!(flask.latest_available.as_deref(), Some("3.1.0")); // not 3.2.0a1
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
