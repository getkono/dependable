//! Hermetic tests for the OSV detail query: wire parsing, severity derivation,
//! version filtering, caching, pagination, and error surfacing, all against a
//! local wiremock server. The record bodies are trimmed copies of real OSV
//! responses.

use dependable_fetch::osv::{Advisory, CvssVersion, ReferenceKind, Severity};
use dependable_fetch::{OsvClient, OsvQuery, build_client};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A RUSTSEC-shaped record: a CVSS vector, no severity word.
const RUSTSEC: &str = r#"{
  "id": "RUSTSEC-2020-0071",
  "summary": "Potential segfault in the time crate",
  "details": "Unix-like operating systems may segfault due to dereferencing a dangling pointer.",
  "aliases": ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
  "published": "2020-11-18T12:00:00Z",
  "modified": "2023-07-08T12:00:00Z",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
  "affected": [{
    "package": {"name": "time", "ecosystem": "crates.io"},
    "ranges": [{"type": "SEMVER", "events": [
      {"introduced": "0.0.0-0"}, {"fixed": "0.2.23"}
    ]}]
  }],
  "references": [
    {"type": "ADVISORY", "url": "https://rustsec.org/advisories/RUSTSEC-2020-0071.html"},
    {"type": "PACKAGE", "url": "https://crates.io/crates/time"}
  ],
  "database_specific": {"cwe_ids": ["CWE-476"]}
}"#;

/// A GHSA-shaped record as it appears on crates.io: no `severity` array at all,
/// only a severity word under `database_specific`.
const GHSA: &str = r#"{
  "id": "GHSA-3gxf-9r58-2ghg",
  "summary": "Segmentation fault in time",
  "aliases": ["CVE-2020-26235"],
  "affected": [{
    "package": {"name": "time", "ecosystem": "crates.io"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.23"}]}]
  }],
  "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-3gxf-9r58-2ghg"}],
  "database_specific": {"severity": "MODERATE"}
}"#;

fn query() -> OsvQuery {
    OsvQuery {
        ecosystem: "crates.io".to_string(),
        name: "time".to_string(),
        version: "0.2.7".to_string(),
    }
}

/// A client whose batch URL points at `server`; the detail URL is derived from
/// it, so every test also exercises that derivation end to end.
fn client(server: &MockServer, include_ghsa: bool) -> OsvClient {
    OsvClient::with_url(
        build_client().unwrap(),
        format!("{}/v1/querybatch", server.uri()),
        include_ghsa,
    )
}

async fn mount_query(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn query_detail_parses_a_cvss_record_and_a_labelled_record() {
    let server = MockServer::start().await;
    mount_query(&server, format!(r#"{{"vulns":[{RUSTSEC},{GHSA}]}}"#)).await;

    let advisories = client(&server, true).query_detail(&query()).await.unwrap();
    assert_eq!(advisories.len(), 2);

    // A vector but no severity word: the score is computed, the band follows it.
    let rustsec = &advisories[0];
    assert_eq!(rustsec.id, "RUSTSEC-2020-0071");
    assert_eq!(rustsec.severity.score, Some(6.2));
    assert_eq!(rustsec.severity.band, Some(Severity::Medium));
    assert_eq!(rustsec.severity.cvss_version, Some(CvssVersion::V3));
    assert_eq!(
        rustsec.severity.vector.as_deref(),
        Some("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    );
    assert_eq!(rustsec.severity.label, None);
    assert_eq!(rustsec.title(), "Potential segfault in the time crate");
    assert!(rustsec.details.is_some());
    assert_eq!(
        rustsec.aliases,
        vec!["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"]
    );
    assert_eq!(rustsec.fixed_versions, vec!["0.2.23"]);
    assert_eq!(rustsec.cwe_ids, vec!["CWE-476"]);
    assert_eq!(
        rustsec.advisory_url(),
        Some("https://rustsec.org/advisories/RUSTSEC-2020-0071.html")
    );
    assert_eq!(rustsec.references[1].kind, ReferenceKind::Package);
    assert!(!rustsec.is_withdrawn());
    assert_eq!(rustsec.published.as_deref(), Some("2020-11-18T12:00:00Z"));

    // A severity word but no vector: no score is invented, the band comes from
    // the word, and the word itself is kept verbatim for display.
    let ghsa = &advisories[1];
    assert_eq!(ghsa.id, "GHSA-3gxf-9r58-2ghg");
    assert_eq!(ghsa.severity.score, None);
    assert_eq!(ghsa.severity.band, Some(Severity::Medium));
    assert_eq!(ghsa.severity.label.as_deref(), Some("MODERATE"));
    assert!(!ghsa.severity.is_unrated());

    assert_eq!(Advisory::max_cvss(&advisories), Some(6.2));
    assert_eq!(Advisory::max_severity(&advisories), Some(Severity::Medium));
    assert_eq!(Advisory::unrated_count(&advisories), 0);
}

#[tokio::test]
async fn query_detail_filters_ghsa_when_disabled() {
    let server = MockServer::start().await;
    mount_query(&server, format!(r#"{{"vulns":[{RUSTSEC},{GHSA}]}}"#)).await;

    let excluded = client(&server, false).query_detail(&query()).await.unwrap();
    assert_eq!(
        excluded.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
        vec!["RUSTSEC-2020-0071"]
    );

    let included = client(&server, true).query_detail(&query()).await.unwrap();
    assert_eq!(included.len(), 2);
}

#[tokio::test]
async fn query_detail_reports_an_unrated_advisory() {
    let server = MockServer::start().await;
    mount_query(
        &server,
        r#"{"vulns":[{"id":"RUSTSEC-9999-0001","summary":"Unrated"}]}"#.to_string(),
    )
    .await;

    let advisories = client(&server, false).query_detail(&query()).await.unwrap();
    assert_eq!(advisories.len(), 1);
    assert!(advisories[0].severity.is_unrated());
    assert_eq!(advisories[0].severity.score, None);
    assert_eq!(advisories[0].severity.band, None);
    // An unrated advisory is not a 0.0-scored one: the rollups report nothing.
    assert_eq!(Advisory::max_cvss(&advisories), None);
    assert_eq!(Advisory::max_severity(&advisories), None);
    assert_eq!(Advisory::unrated_count(&advisories), 1);
}

#[tokio::test]
async fn query_detail_serves_the_second_call_from_cache() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!(r#"{{"vulns":[{RUSTSEC}]}}"#)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server, false);
    let first = client.query_detail(&query()).await.unwrap();
    let second = client.query_detail(&query()).await.unwrap();
    assert_eq!(first, second);
    // The mock's `.expect(1)` is verified when the server drops.
}

#[tokio::test]
async fn query_detail_skips_the_request_when_the_batch_found_nothing() {
    let server = MockServer::start().await;
    // Only the batch endpoint is mounted. A detail request would 404 and surface
    // as an error, so reaching `Ok(vec![])` proves no request was made.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"results":[{}]}"#))
        .mount(&server)
        .await;

    let client = client(&server, false);
    let ids = client
        .query_batch(std::slice::from_ref(&query()))
        .await
        .unwrap();
    assert_eq!(ids, vec![Vec::<String>::new()]);

    let advisories = client.query_detail(&query()).await.unwrap();
    assert!(advisories.is_empty());
}

#[tokio::test]
async fn query_detail_follows_pagination() {
    let server = MockServer::start().await;
    // Higher precedence (a lower priority number): the continuation request.
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .and(body_string_contains("page_token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!(r#"{{"vulns":[{GHSA}]}}"#)),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    // The first page, which asks for a second.
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"vulns":[{RUSTSEC}],"next_page_token":"more"}}"#
        )))
        .mount(&server)
        .await;

    let advisories = client(&server, true).query_detail(&query()).await.unwrap();
    assert_eq!(
        advisories.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
        vec!["RUSTSEC-2020-0071", "GHSA-3gxf-9r58-2ghg"]
    );
}

#[tokio::test]
async fn query_detail_keeps_only_the_queried_packages_ranges() {
    let server = MockServer::start().await;
    mount_query(
        &server,
        r#"{"vulns":[{
          "id": "RUSTSEC-9999-0002",
          "affected": [
            {"package": {"name": "time", "ecosystem": "npm"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
            {"package": {"name": "time", "ecosystem": "crates.io"},
             "ranges": [
               {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.23"}]},
               {"type": "GIT", "events": [{"introduced": "aaaaaa"}, {"fixed": "bbbbbb"}]}
             ]}
          ]
        }]}"#
            .to_string(),
    )
    .await;

    let advisories = client(&server, false).query_detail(&query()).await.unwrap();
    let advisory = &advisories[0];
    // The npm entry and the commit-hash range are both gone.
    assert_eq!(advisory.ranges.len(), 1);
    assert_eq!(advisory.ranges[0].fixed.as_deref(), Some("0.2.23"));
    assert_eq!(advisory.fixed_versions, vec!["0.2.23"]);
}

#[tokio::test]
async fn query_detail_surfaces_a_status_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let err = client(&server, false)
        .query_detail(&query())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("status 500"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
#[ignore = "hits the network (OSV)"]
async fn live_query_detail_enriches_a_known_advisory() {
    let client = OsvClient::new(build_client().unwrap(), true);
    let advisories = client.query_detail(&query()).await.unwrap();

    assert!(
        !advisories.is_empty(),
        "time 0.2.7 should have known advisories"
    );
    for advisory in &advisories {
        assert!(!advisory.id.is_empty());
        assert!(!advisory.title().is_empty());
        if let Some(score) = advisory.severity.score {
            assert!(
                (0.0..=10.0).contains(&score),
                "{}: score {score} out of range",
                advisory.id
            );
        }
    }
}
