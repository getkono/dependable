//! Serde types for the OSV `querybatch` and `query` APIs.
//!
//! `querybatch` answers "is this version affected?" with bare IDs; `query`
//! returns the full advisory records for one exact package version. Every field
//! of a record is `#[serde(default)]` and unknown fields are ignored, so one
//! malformed record can never fail a whole response.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct BatchRequest {
    pub queries: Vec<Query>,
}

#[derive(Debug, Serialize)]
pub struct Query {
    pub version: String,
    pub package: Package,
}

#[derive(Debug, Serialize)]
pub struct Package {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct BatchResponse {
    #[serde(default)]
    pub results: Vec<QueryResult>,
}

#[derive(Debug, Default, Deserialize)]
pub struct QueryResult {
    #[serde(default)]
    pub vulns: Vec<VulnRef>,
}

#[derive(Debug, Deserialize)]
pub struct VulnRef {
    pub id: String,
}

/// A `POST /v1/query` body: the full advisory records for one exact version.
///
/// Deliberately a separate struct from [`Query`] so the `querybatch` body is
/// provably unchanged by the paging field.
#[derive(Debug, Serialize)]
pub struct DetailRequest {
    /// The exact version to look up.
    pub version: String,
    /// The package to look it up for.
    pub package: Package,
    /// The continuation token from a previous page, omitted on the first page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

/// One page of a `query` response.
#[derive(Debug, Default, Deserialize)]
pub struct DetailResponse {
    /// The advisory records on this page.
    #[serde(default)]
    pub vulns: Vec<Vuln>,
    /// A token for the next page, if the result set was truncated.
    #[serde(default)]
    pub next_page_token: Option<String>,
}

/// One full OSV advisory record.
#[derive(Debug, Default, Deserialize)]
pub struct Vuln {
    /// The advisory's own ID.
    #[serde(default)]
    pub id: String,
    /// Other IDs naming the same vulnerability.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One-line summary.
    #[serde(default)]
    pub summary: Option<String>,
    /// Long-form description (Markdown).
    #[serde(default)]
    pub details: Option<String>,
    /// Publication timestamp, RFC 3339.
    #[serde(default)]
    pub published: Option<String>,
    /// Last-modified timestamp, RFC 3339.
    #[serde(default)]
    pub modified: Option<String>,
    /// Withdrawal timestamp, RFC 3339; present only if withdrawn.
    #[serde(default)]
    pub withdrawn: Option<String>,
    /// Severity vectors, if the publisher scored the advisory.
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
    /// The packages and version ranges this advisory affects.
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// Published links.
    #[serde(default)]
    pub references: Vec<Reference>,
    /// Publisher-defined extras. The OSV schema declares this arbitrary JSON, so
    /// it is read by key (`severity`, `cwe_ids`) rather than typed.
    #[serde(default)]
    pub database_specific: serde_json::Value,
}

/// One severity rating. `score` is always a CVSS **vector string**, never a
/// number — the name is OSV's, not a description of the contents.
///
/// The `type` field is read as `kind` so it does not collide with the public
/// severity *band* type.
#[derive(Debug, Default, Deserialize)]
pub struct SeverityEntry {
    /// The rating system: `CVSS_V2`, `CVSS_V3`, `CVSS_V4`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// The CVSS vector string.
    #[serde(default)]
    pub score: String,
}

/// One affected package and the version ranges of it that are affected.
#[derive(Debug, Default, Deserialize)]
pub struct Affected {
    /// Which package this entry is about.
    #[serde(default)]
    pub package: AffectedPackage,
    /// The affected version ranges.
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// Publisher-defined extras, read by key.
    #[serde(default)]
    pub database_specific: serde_json::Value,
}

/// The package an [`Affected`] entry names.
#[derive(Debug, Default, Deserialize)]
pub struct AffectedPackage {
    /// The package name as the ecosystem spells it.
    #[serde(default)]
    pub name: String,
    /// The ecosystem, possibly with a distribution suffix (`Debian:11`).
    #[serde(default)]
    pub ecosystem: String,
}

/// One affected version range, expressed as an ordered event list.
#[derive(Debug, Default, Deserialize)]
pub struct Range {
    /// The range's version ordering: `SEMVER`, `ECOSYSTEM`, or `GIT`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// The events that open and close the range.
    #[serde(default)]
    pub events: Vec<Event>,
}

/// One boundary in a [`Range`]. Exactly one field is set per event.
#[derive(Debug, Default, Deserialize)]
pub struct Event {
    /// Affected from this version onward.
    #[serde(default)]
    pub introduced: Option<String>,
    /// Fixed in this version (no longer affected).
    #[serde(default)]
    pub fixed: Option<String>,
    /// Affected up to and including this version.
    #[serde(default)]
    pub last_affected: Option<String>,
}

/// One published link.
#[derive(Debug, Default, Deserialize)]
pub struct Reference {
    /// What the link points at (`ADVISORY`, `FIX`, `WEB`, …).
    #[serde(rename = "type", default)]
    pub kind: String,
    /// The link itself.
    #[serde(default)]
    pub url: String,
}
