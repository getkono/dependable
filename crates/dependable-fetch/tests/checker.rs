//! Hermetic end-to-end tests for the high-level [`Checker`], driving a full
//! parse → fetch → evaluate → OSV scan over inline manifest content against a
//! local wiremock server that mocks both the crates.io sparse index and OSV.

use std::sync::Arc;

use dependable_fetch::osv::Severity;
use dependable_fetch::{
    Checker, DependencyStatus, Ecosystem, GoProxyFetcher, JsrFetcher, ManifestKind, NpmFetcher,
    PackageSource, PackagistFetcher, PyPiFetcher, build_client,
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
async fn check_go_mod_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("v1.0.0\nv1.2.0\n"))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Go,
            Arc::new(GoProxyFetcher::with_proxy(client, server.uri())),
        )
        .vulnerabilities(false)
        .build()
        .unwrap();

    let manifest = "require (\n\tgithub.com/foo/bar v1.0.0\n)\n";
    let check = checker
        .check_manifest(ManifestKind::GoMod, manifest, None)
        .await
        .unwrap();

    assert_eq!(check.ecosystem, Ecosystem::Go);
    let r = check
        .results
        .iter()
        .find(|r| r.item.name == "github.com/foo/bar")
        .unwrap();
    // Resolved at v1.0.0, latest within the major is v1.2.0.
    assert_eq!(r.status, DependencyStatus::UpdateAvailable);
    assert_eq!(r.latest_available.as_deref(), Some("1.2.0"));
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
async fn check_composer_json_with_lockfile() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/p2/monolog/monolog.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"packages":{"monolog/monolog":[{"version":"2.0.0"},{"version":"2.3.0"}]}}"#,
        ))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Php,
            Arc::new(PackagistFetcher::with_registry(client, server.uri())),
        )
        .vulnerabilities(false)
        .build()
        .unwrap();

    let manifest = r#"{ "require": { "php": ">=8.0", "monolog/monolog": "^2.0" } }"#;
    let lock = r#"{ "packages": [ { "name": "monolog/monolog", "version": "2.0.0" } ] }"#;
    let check = checker
        .check_manifest(ManifestKind::ComposerJson, manifest, Some(lock))
        .await
        .unwrap();

    assert_eq!(check.ecosystem, Ecosystem::Php);
    // The `php` platform requirement is not a checkable result.
    assert!(check.results.iter().all(|r| r.item.name != "php"));
    let monolog = check
        .results
        .iter()
        .find(|r| r.item.name == "monolog/monolog")
        .unwrap();
    assert_eq!(monolog.item.locked_version.as_deref(), Some("2.0.0"));
    assert_eq!(monolog.status, DependencyStatus::UpdateAvailable);
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

/// Two workspace members declaring the same crate must cost ONE registry request.
///
/// This is the monorepo guarantee: `run_check` builds one [`Checker`] and loops
/// manifests through it, and the checker's in-process versions cache is keyed by
/// `(registry, name)` rather than by manifest. Nothing about that is enforced by
/// a type, so it is asserted here — a future change to the manifest loop (or to
/// the cache's lifetime) fails loudly instead of silently doubling the traffic.
///
/// The disk cache is off so the assertion is about the in-process cache alone.
#[tokio::test]
async fn one_checker_fetches_a_shared_package_once_across_manifests() {
    const MEMBER_A: &str = r#"
[dependencies]
serde = "1"
"#;
    // Declared on a different line, and beside a dependency the first member does
    // not have, so the two manifests are genuinely different documents.
    const MEMBER_B: &str = r#"
[dependencies]
local-thing = { path = "../local" }
serde = "1"
"#;

    let server = MockServer::start().await;
    // `.expect(1)` is the assertion; wiremock verifies it when the server drops.
    Mock::given(method("GET"))
        .and(path("/se/rd/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"serde\",\"vers\":\"1.2.0\",\"yanked\":false}\n",
        )))
        .expect(1)
        .mount(&server)
        .await;

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache(false)
        .build()
        .unwrap();

    let first = checker
        .check_manifest(ManifestKind::CargoToml, MEMBER_A, None)
        .await
        .unwrap();
    let second = checker
        .check_manifest(ManifestKind::CargoToml, MEMBER_B, None)
        .await
        .unwrap();

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the second manifest must be served from the checker's versions cache"
    );

    // What is shared is the version list. Everything a rewrite needs — the line
    // and columns of the constraint — comes from each manifest's own parse, so
    // the two results describe their own files, not each other's.
    let serde = |check: &dependable_fetch::ManifestCheck| {
        check
            .results
            .iter()
            .find(|r| r.item.name == "serde")
            .expect("serde is declared")
            .clone()
    };
    let (a, b) = (serde(&first), serde(&second));
    assert_eq!(a.latest_available, b.latest_available);
    assert_ne!(
        a.item.version_line, b.item.version_line,
        "position data is per-manifest even though the fetch is shared"
    );
}

#[tokio::test]
async fn disk_cache_serves_a_second_checker() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let dir = tempfile::tempdir().unwrap();

    // First checker fetches serde + time and populates the on-disk cache.
    let first = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache_dir(dir.path())
        .build()
        .unwrap();
    first
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let after_first = server.received_requests().await.unwrap().len();
    assert_eq!(
        after_first, 2,
        "serde + time fetched once (local-thing skipped)"
    );

    // A second checker has a fresh in-process cache but shares the disk dir, so it
    // serves both packages from disk and makes no new registry requests.
    let second = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache_dir(dir.path())
        .build()
        .unwrap();
    second
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        after_first,
        "second checker should hit the disk cache, not the registry"
    );
}

#[tokio::test]
async fn no_cache_forces_a_refetch() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let dir = tempfile::tempdir().unwrap();

    // Disk cache disabled: even sharing a dir, a fresh checker re-fetches everything.
    let first = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache(false)
        .disk_cache_dir(dir.path())
        .build()
        .unwrap();
    first
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let after_first = server.received_requests().await.unwrap().len();

    let second = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache(false)
        .disk_cache_dir(dir.path())
        .build()
        .unwrap();
    second
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        after_first * 2,
        "with --no-cache the second checker re-fetches every package"
    );
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

/// The OSV batch response that flags `time` (slot 1) and clears `serde` (slot 0).
const BATCH_FLAGS_TIME: &str = r#"{"results":[{},{"vulns":[{"id":"RUSTSEC-2020-0071"}]}]}"#;

/// A trimmed `/v1/query` response: the full record behind `RUSTSEC-2020-0071`.
const DETAIL_RUSTSEC: &str = r#"{"vulns":[{
  "id": "RUSTSEC-2020-0071",
  "summary": "Potential segfault in the time crate",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
  "affected": [{
    "package": {"name": "time", "ecosystem": "crates.io"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.23"}]}]
  }],
  "references": [{"type": "ADVISORY", "url": "https://rustsec.org/advisories/RUSTSEC-2020-0071.html"}]
}]}"#;

/// The same, plus a GHSA record for the same crate.
const DETAIL_RUSTSEC_AND_GHSA: &str = r#"{"vulns":[
  {
    "id": "RUSTSEC-2020-0071",
    "summary": "Potential segfault in the time crate",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
  },
  {
    "id": "GHSA-3gxf-9r58-2ghg",
    "summary": "Segmentation fault in time",
    "database_specific": {"severity": "MODERATE"}
  }
]}"#;

/// Mount the crates.io index plus the OSV batch response flagging `time`.
async fn mount_index_and_batch(server: &MockServer) {
    mount_index(server).await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_string(BATCH_FLAGS_TIME))
        .mount(server)
        .await;
}

#[tokio::test]
async fn advisory_details_are_off_by_default() {
    let server = MockServer::start().await;
    mount_index_and_batch(&server).await;
    // No /v1/query mock is mounted: a detail request would 404 and surface as a
    // warning, so a clean, empty result proves the default check makes none.

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(format!("{}/v1/querybatch", server.uri()))
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let time = check
        .results
        .iter()
        .find(|r| r.item.name == "time")
        .unwrap();

    assert!(check.warnings.is_empty());
    assert_eq!(time.status, DependencyStatus::Vulnerable);
    assert_eq!(
        time.current_vulnerabilities,
        vec!["RUSTSEC-2020-0071".to_string()]
    );
    assert!(time.advisories.is_empty());
}

#[tokio::test]
async fn advisory_details_enriches_only_vulnerable_results() {
    let server = MockServer::start().await;
    mount_index_and_batch(&server).await;
    // `.expect(1)`: only `time` is vulnerable, so only `time` is looked up.
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DETAIL_RUSTSEC))
        .expect(1)
        .mount(&server)
        .await;

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(format!("{}/v1/querybatch", server.uri()))
        .advisory_details(true)
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let by_name = |n: &str| check.results.iter().find(|r| r.item.name == n).unwrap();
    let time = by_name("time");

    assert!(check.warnings.is_empty());
    assert_eq!(time.advisories.len(), 1);
    assert_eq!(time.max_cvss(), Some(6.2));
    assert_eq!(time.max_severity(), Some(Severity::Medium));
    let advisory = time.advisory("RUSTSEC-2020-0071").expect("the record");
    assert_eq!(advisory.title(), "Potential segfault in the time crate");
    assert_eq!(advisory.fixed_versions, vec!["0.2.23"]);
    assert!(advisory.advisory_url().is_some());
    // The IDs are untouched, and a clean dependency is never queried.
    assert_eq!(
        time.current_vulnerabilities,
        vec!["RUSTSEC-2020-0071".to_string()]
    );
    assert!(by_name("serde").advisories.is_empty());
}

#[tokio::test]
async fn advisory_details_respects_include_ghsa() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"results":[{},{"vulns":[{"id":"RUSTSEC-2020-0071"},{"id":"GHSA-3gxf-9r58-2ghg"}]}]}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DETAIL_RUSTSEC_AND_GHSA))
        .mount(&server)
        .await;

    let osv_url = format!("{}/v1/querybatch", server.uri());
    let build = |include_ghsa: bool| {
        Checker::builder()
            .http_client(build_client().unwrap())
            .rust_registry(server.uri(), None)
            .osv_url(osv_url.clone())
            .advisory_details(true)
            .include_ghsa(include_ghsa)
            .build()
            .unwrap()
    };
    let ids = |check: &dependable_fetch::ManifestCheck| {
        let time = check
            .results
            .iter()
            .find(|r| r.item.name == "time")
            .unwrap();
        (
            time.current_vulnerabilities.clone(),
            time.advisories
                .iter()
                .map(|a| a.id.clone())
                .collect::<Vec<_>>(),
        )
    };

    // Default: the GHSA record is filtered out of the details exactly as it is
    // out of the IDs, so the two never disagree.
    let check = build(false)
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let (vulnerabilities, advisories) = ids(&check);
    assert_eq!(vulnerabilities, vec!["RUSTSEC-2020-0071".to_string()]);
    assert_eq!(advisories, vec!["RUSTSEC-2020-0071".to_string()]);

    let check = build(true)
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    let (vulnerabilities, advisories) = ids(&check);
    assert_eq!(
        vulnerabilities,
        vec![
            "RUSTSEC-2020-0071".to_string(),
            "GHSA-3gxf-9r58-2ghg".to_string()
        ]
    );
    assert_eq!(advisories, vulnerabilities);
}

#[tokio::test]
async fn advisory_details_degrade_to_a_warning() {
    let server = MockServer::start().await;
    mount_index_and_batch(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(format!("{}/v1/querybatch", server.uri()))
        .advisory_details(true)
        .build()
        .unwrap();

    // The check still succeeds: the version and vulnerability data are correct
    // and useful without the enrichment.
    let check = checker
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
        vec!["RUSTSEC-2020-0071".to_string()]
    );
    assert!(time.advisories.is_empty());
    assert!(
        check
            .warnings
            .iter()
            .any(|w| w.contains("advisory enrichment skipped")),
        "expected an enrichment warning, got {:?}",
        check.warnings
    );
}

#[tokio::test]
async fn advisory_details_are_a_no_op_without_vulnerability_scanning() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    // No OSV mocks at all: any OSV request would 404.

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .advisory_details(true)
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    assert!(check.warnings.is_empty());
    assert!(check.results.iter().all(|r| r.advisories.is_empty()));
}

#[tokio::test]
async fn enrich_advisories_can_be_called_explicitly() {
    let server = MockServer::start().await;
    mount_index_and_batch(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DETAIL_RUSTSEC))
        .expect(1)
        .mount(&server)
        .await;

    // Built *without* the flag: nothing is enriched until the caller asks.
    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(format!("{}/v1/querybatch", server.uri()))
        .build()
        .unwrap();

    let mut check = checker
        .check_manifest(ManifestKind::CargoToml, MANIFEST, Some(LOCK))
        .await
        .unwrap();
    assert!(check.results.iter().all(|r| r.advisories.is_empty()));

    checker.enrich_advisories(&mut check).await.unwrap();
    let time = check
        .results
        .iter()
        .find(|r| r.item.name == "time")
        .unwrap();
    assert_eq!(time.advisories.len(), 1);
    assert_eq!(time.max_cvss(), Some(6.2));
    assert_eq!(time.max_severity(), Some(Severity::Medium));
    assert!(time.advisory("RUSTSEC-2020-0071").is_some());
}

#[tokio::test]
async fn fetch_advisories_returns_records_for_one_package() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DETAIL_RUSTSEC))
        .expect(1)
        .mount(&server)
        .await;

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .osv_url(format!("{}/v1/querybatch", server.uri()))
        .build()
        .unwrap();

    let advisories = checker
        .fetch_advisories(Ecosystem::Rust, "time", "0.2.7")
        .await
        .unwrap();
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories[0].id, "RUSTSEC-2020-0071");
    assert_eq!(advisories[0].severity.score, Some(6.2));

    // The second call is served from the checker's shared detail cache.
    let again = checker
        .fetch_advisories(Ecosystem::Rust, "time", "0.2.7")
        .await
        .unwrap();
    assert_eq!(again, advisories);
}

/// PyPI's single JSON endpoint serves both the version list and the metadata, so
/// the number of requests to it *is* the number of extra lookups a license
/// collection costs.
async fn pypi_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"info":{"license_expression":"BSD-3-Clause"},
                "releases":{"2.0.0":[{"yanked":false}]}}"#,
        ))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_check_collects_licenses_when_they_are_asked_for() {
    let server = pypi_server().await;
    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Python,
            Arc::new(PyPiFetcher::with_registry(client, server.uri())),
        )
        .vulnerabilities(false)
        .disk_cache(false)
        .licenses(true)
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::RequirementsTxt, "flask==2.0.0\n", None)
        .await
        .unwrap();

    assert!(check.warnings.is_empty());
    assert_eq!(check.results[0].license.as_deref(), Some("BSD-3-Clause"));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "one version lookup plus one metadata lookup"
    );
}

#[tokio::test]
async fn a_plain_check_makes_no_metadata_request_at_all() {
    let server = pypi_server().await;
    let client = build_client().unwrap();
    let checker = Checker::builder()
        .http_client(client.clone())
        .registry(
            Ecosystem::Python,
            Arc::new(PyPiFetcher::with_registry(client, server.uri())),
        )
        .vulnerabilities(false)
        .disk_cache(false)
        .build()
        .unwrap();

    let check = checker
        .check_manifest(ManifestKind::RequirementsTxt, "flask==2.0.0\n", None)
        .await
        .unwrap();

    assert_eq!(
        check.results[0].license, None,
        "collection is opt-in; `None` is not `unlicensed`"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the default check must not pay for data nothing asked for"
    );
}

/// A workspace member's `dep.workspace = true` is checked against the version the root
/// declares — the whole point of the feature. Before this, the member's entry parsed as a
/// constraint-less local dep and was skipped, so the crate was only ever checked at the
/// root, and not at all when the root fell outside the scan.
#[tokio::test]
async fn a_member_is_checked_against_the_workspace_roots_constraint() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let dir = tempfile::tempdir().unwrap();
    // Canonical, because the reported `workspace_root` is: on macOS the system temp
    // directory is reached through a `/var` -> `/private/var` symlink, so the two
    // spellings of the same file differ as strings.
    let root = &dir.path().canonicalize().unwrap();

    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/app\"]\n\n[workspace.dependencies]\nserde = \"1.0.0\"\n",
    )
    .unwrap();
    // The lockfile sits at the root too, so this also proves the member picks up both
    // of the things that live above it — the locked version and the constraint.
    std::fs::write(root.join("Cargo.lock"), LOCK).unwrap();
    let member = root.join("crates/app/Cargo.toml");
    std::fs::create_dir_all(member.parent().unwrap()).unwrap();
    let content = "[package]\nname = \"app\"\n\n[dependencies]\nserde.workspace = true\n";
    std::fs::write(&member, content).unwrap();

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache(false)
        .build()
        .unwrap();

    let check = checker.check_path(&member).await.unwrap();

    let serde = check
        .results
        .iter()
        .find(|r| r.item.name == "serde")
        .expect("serde is declared");
    assert_eq!(serde.item.version_constraint, "1.0.0", "from the root");
    assert_eq!(serde.item.locked_version.as_deref(), Some("1.0.0"));
    assert_eq!(serde.status, DependencyStatus::UpdateAvailable);
    assert_eq!(serde.latest_available.as_deref(), Some("1.2.0"));
    assert_eq!(serde.item.source, PackageSource::Inherited);
    // The version string is in the root, so nothing here may be rewritten.
    assert!(!serde.item.is_rewritable());
    assert_eq!(
        (
            serde.item.version_line,
            serde.item.version_col_start,
            serde.item.version_col_end
        ),
        (0, 0, 0),
        "no position in this file is truthful"
    );
    assert_eq!(
        check.workspace_root.as_deref(),
        Some(root.join("Cargo.toml").as_path())
    );

    // Same content with no file behind it: there is no tree to look up, so the entry
    // stays unresolved and reports exactly as it did before.
    let detached = checker
        .check_manifest(ManifestKind::CargoToml, content, None)
        .await
        .unwrap();
    let serde = detached
        .results
        .iter()
        .find(|r| r.item.name == "serde")
        .expect("serde is declared");
    assert_eq!(serde.status, DependencyStatus::Local);
    assert!(serde.item.version_constraint.is_empty());
    assert!(detached.workspace_root.is_none());
}

/// A root declaring a crate by `path` lends the member a path dependency, not a registry
/// version — which is what Cargo itself resolves.
#[tokio::test]
async fn a_path_declaration_is_inherited_as_a_path_dependency() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/app\"]\n\n[workspace.dependencies]\nhelper = { path = \"crates/helper\" }\n",
    )
    .unwrap();
    let member = root.join("crates/app/Cargo.toml");
    std::fs::create_dir_all(member.parent().unwrap()).unwrap();
    std::fs::write(
        &member,
        "[package]\nname = \"app\"\n\n[dependencies]\nhelper.workspace = true\n",
    )
    .unwrap();

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry(server.uri(), None)
        .vulnerabilities(false)
        .disk_cache(false)
        .build()
        .unwrap();

    let check = checker.check_path(&member).await.unwrap();
    let helper = &check.results[0];

    assert_eq!(helper.item.name, "helper");
    assert_eq!(helper.item.source, PackageSource::Local);
    assert_eq!(helper.status, DependencyStatus::Local);
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "a path dependency has no registry to ask"
    );
}

/// Cargo refuses to build a member inheriting a crate the root never declared. Reporting
/// it as an ordinary unchecked dependency, which is what it looks like once resolution
/// finds nothing, would hide a broken manifest behind a shrug.
#[tokio::test]
async fn an_inherited_name_the_root_never_declared_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/app\"]\n\n[workspace.dependencies]\nserde = \"1.0.0\"\n",
    )
    .unwrap();
    let member = root.join("crates/app/Cargo.toml");
    std::fs::create_dir_all(member.parent().unwrap()).unwrap();
    // Inherited in two sections: Cargo allows it, and it is one mistake to fix, not two
    // to report.
    std::fs::write(
        &member,
        "[package]\nname = \"app\"\n\n[dependencies]\ntokio.workspace = true\n\n[dev-dependencies]\ntokio.workspace = true\n",
    )
    .unwrap();

    let checker = Checker::builder()
        .http_client(build_client().unwrap())
        .rust_registry("http://127.0.0.1:1".to_string(), None)
        .vulnerabilities(false)
        .disk_cache(false)
        .build()
        .unwrap();

    let check = checker.check_path(&member).await.unwrap();

    assert_eq!(
        check.warnings.len(),
        1,
        "once per name: {:?}",
        check.warnings
    );
    assert!(
        check.warnings[0].contains("`tokio`"),
        "{:?}",
        check.warnings
    );
    assert!(
        check.warnings[0].contains("declares no such dependency"),
        "{:?}",
        check.warnings
    );
    // The dependency itself still reports as it always did — unchecked, not an error.
    assert_eq!(
        check.results.len(),
        2,
        "both declarations are still reported"
    );
    for result in &check.results {
        assert_eq!(result.status, DependencyStatus::Local);
    }
}
