//! SARIF v2.1.0 output for code-scanning tooling.
//!
//! Renders a [`Report`] as a SARIF v2.1.0 log — the format GitHub's Security tab
//! and most IDE problem panes ingest — from hand-rolled `serde` structs rather
//! than a SARIF crate, so the schema stays visible and pinned.
//!
//! # Public surface
//!
//! [`render`], [`DEP001`] and [`DEP002`]. Everything else in this module is
//! private on purpose: the SARIF document shape is an output artifact, not an
//! API, and publishing the structs would freeze the JSON layout as semver
//! surface.
//!
//! # Rules
//!
//! | Rule | Meaning | Default level |
//! | --- | --- | --- |
//! | [`DEP001`] | a newer version of the dependency is available | `warning` |
//! | [`DEP002`] | the version in use is affected by a known advisory | `error` |
//!
//! One result is emitted **per advisory ID**, so each CVE becomes its own alert
//! carrying its own `properties.cvssScore`, and one result per dependency for
//! [`DEP001`]. `DEP003` onwards are unused and free for later rules.
//!
//! # Purity and determinism
//!
//! Rendering touches no filesystem, no clock and no network: it is a pure
//! function of the [`Report`] handed in. [`Report::generated_at`] is
//! deliberately *not* serialized (see the omissions below), and advisory IDs are
//! sorted lexicographically, so `check --format sarif` is **byte-deterministic**
//! for a given tree — golden tests need no injected clock.
//!
//! # Deliberate omissions
//!
//! - **No `startColumn` / `endColumn`.** [`Item::version_col_start`] and
//!   [`Item::version_col_end`](dependable_core::Item::version_col_end) are *byte*
//!   offsets, while SARIF columns are unicode code points (or UTF-16 units, per
//!   `run.columnKind`). Byte offsets would be silently wrong on any line holding
//!   non-ASCII, so only the line is reported — always correct, and enough to
//!   point at "this manifest, this line".
//! - **No `uriBaseId` / `originalUriBaseIds`.** Defining `%SRCROOT%` properly
//!   writes the developer's absolute repository path into the artifact, and
//!   GitHub code scanning wants plain repository-relative URIs anyway.
//! - **No `invocations[]`.** This is *why* [`Report::generated_at`] is not
//!   serialized, and the payoff is byte-determinism.
//! - **No `toolExecutionNotifications`.** Skipped and unparseable manifests are
//!   already reported on stderr by the CLI.
//! - **No `region` at all** for a dependency whose version lives in another file — a
//!   Cargo `dep.workspace = true`, resolved against the workspace root. The result still
//!   carries its `artifactLocation`, which SARIF permits; see [`start_line`].
//! - **No `cvssVersion` property.**
//!   [`AdvisorySeverity::cvss_version`](dependable_core::result::AdvisorySeverity::cvss_version)
//!   is an enum with no stable display form; the vector string is emitted
//!   instead, and it carries the revision in its own prefix.
//!
//! # Off-by-one — read before touching `region`
//!
//! [`Item::version_line`] is **zero-indexed**, while SARIF's `region.startLine`
//! is **one-based**. One is added on the way in, or every reported location
//! lands a line short of the version it points at.

use std::collections::BTreeMap;
use std::path::{Component, Path, Prefix};

use dependable_core::result::{Advisory, Severity};
use dependable_core::{CheckResult, DependencyStatus, Item};
use serde::Serialize;

use crate::error::ReportError;
use crate::model::Report;

/// The rule ID for a dependency with a newer published version.
pub const DEP001: &str = "DEP001";

/// The rule ID for a dependency affected by a known advisory.
pub const DEP002: &str = "DEP002";

/// The SARIF schema this renderer targets.
const SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// The SARIF specification version. Required by the schema.
const SARIF_VERSION: &str = "2.1.0";

/// `tool.driver.name`. Required by the schema.
const TOOL_NAME: &str = "dependable";

/// `tool.driver.informationUri`, and the `helpUri` of every rule.
const INFORMATION_URI: &str = "https://github.com/getkono/dependable";

/// `run.automationDetails.id`, so consecutive runs of this tool are recognized
/// as the same logical analysis.
const AUTOMATION_ID: &str = "dependable/check";

/// The `partialFingerprints` key. Versioned so the fingerprint recipe can change
/// without silently re-keying existing alerts.
const FINGERPRINT_KEY: &str = "dependable/v1";

/// The `security-severity` GitHub reads off the [`DEP002`] rule. GitHub takes
/// this from the `reportingDescriptor`, not the result, so with a fixed rule
/// catalogue it cannot vary per finding; the accurate per-finding number is
/// `properties.cvssScore`.
const DEP002_SECURITY_SEVERITY: &str = "7.0";

/// Shown for a dependency whose version is neither locked nor constrained.
const UNKNOWN_VERSION: &str = "unknown";

/// Render `report` as a SARIF v2.1.0 log.
///
/// Exactly one `run` is produced regardless of how many manifests the report
/// covers, and `results` is always present — an *absent* `results` means "the
/// tool produced no results", which is a failed run, not "found nothing".
///
/// # Errors
///
/// Returns [`ReportError::Serialize`] if the log cannot be serialized, which in
/// practice means a non-finite CVSS score reached `properties.cvssScore`.
#[must_use = "the rendered SARIF document is the only output of this call"]
pub fn render(report: &Report) -> Result<String, ReportError> {
    Ok(serde_json::to_string_pretty(&build(&findings(report)))?)
}

// ---------------------------------------------------------------------------
// Mapping: Report -> findings
// ---------------------------------------------------------------------------

/// One thing worth telling a code-scanning tool about. A private intermediate:
/// it keeps the mapping table (status → rule → level → message) unit-testable
/// without publishing a second input model alongside [`Report`].
struct Finding {
    rule_id: &'static str,
    rule_index: usize,
    level: Level,
    message: String,
    uri: String,
    /// One-based, as SARIF requires.
    start_line: Option<usize>,
    fingerprint: String,
    properties: ResultProperties,
}

/// Every finding in `report`, in manifest order, then result order, then by
/// lexicographically sorted advisory ID within a dependency.
///
/// The advisory sort is load-bearing:
/// [`CheckResult::current_vulnerabilities`] arrives from an OSV response through
/// a cache, so its order is not stable across runs.
fn findings(report: &Report) -> Vec<Finding> {
    let mut findings = Vec::new();
    for manifest in &report.manifests {
        let uri = uri_for(&report.root, &manifest.path);
        let ecosystem = manifest.ecosystem;
        for result in &manifest.results {
            let line = start_line(&result.item);
            match result.status {
                DependencyStatus::Vulnerable => {
                    for id in advisory_ids(result) {
                        findings.push(vulnerable_finding(
                            result,
                            id,
                            ecosystem.osv_name(),
                            &uri,
                            line,
                        ));
                    }
                }
                DependencyStatus::Outdated => findings.push(outdated_finding(
                    result,
                    Level::Warning,
                    ecosystem.osv_name(),
                    ecosystem.display_name(),
                    &uri,
                    line,
                )),
                DependencyStatus::UpdateAvailable => findings.push(outdated_finding(
                    result,
                    Level::Note,
                    ecosystem.osv_name(),
                    ecosystem.display_name(),
                    &uri,
                    line,
                )),
                // `PatchAvailable` is deliberately silent: it keeps SARIF aligned
                // with `FailOn::Outdated`, which excludes patches, and stops the
                // Security tab drowning in notes.
                // `UpToDate`, `Local` and `Git` have nothing to report, and
                // `Error` is a tool failure rather than a finding about the code
                // — the CLI already puts it on stderr.
                _ => {}
            }
        }
    }
    findings
}

/// SARIF's one-based `region.startLine` from [`Item::version_line`], which is
/// zero-indexed — or `None` for an item whose recorded span means nothing in this file.
///
/// [`Item::has_position`] is the discriminator rather than the position itself, because
/// `0` is a legal line: a `requirements.txt` can declare on its first line. A workspace
/// member inheriting `dep.workspace = true` is checkable, and so does reach here, but its
/// version string lives in the root manifest. Emitting `startLine: 1` for it would point
/// code scanning at the wrong line of the right file, so the finding is reported against
/// the file with no region at all.
fn start_line(item: &Item) -> Option<usize> {
    item.has_position().then(|| item.version_line + 1)
}

/// The advisory IDs affecting the version in use, sorted and deduplicated.
///
/// [`CheckResult::current_vulnerabilities`] is authoritative for *which*
/// advisories apply; [`CheckResult::advisories`] is the enrichment payload and is
/// empty unless enrichment ran. Driving off the ID list and looking detail up
/// with [`CheckResult::advisory`] means the renderer behaves identically either
/// way — only the set of `properties` keys differs.
fn advisory_ids(result: &CheckResult) -> Vec<&str> {
    let mut ids: Vec<&str> = if result.current_vulnerabilities.is_empty() {
        result.advisories.iter().map(|a| a.id.as_str()).collect()
    } else {
        result
            .current_vulnerabilities
            .iter()
            .map(String::as_str)
            .collect()
    };
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// A [`DEP002`] finding for one `(dependency, advisory ID)` pair.
fn vulnerable_finding(
    result: &CheckResult,
    id: &str,
    ecosystem: &'static str,
    uri: &str,
    start_line: Option<usize>,
) -> Finding {
    let advisory = result.advisory(id);
    let current = current_version(result);
    Finding {
        rule_id: DEP002,
        rule_index: 1,
        level: level_for(advisory),
        message: vulnerable_message(&result.item.name, &current, id, advisory, result),
        uri: uri.to_string(),
        start_line,
        fingerprint: fingerprint(DEP002, ecosystem, &result.item.name, id, uri),
        properties: ResultProperties {
            package: result.item.name.clone(),
            ecosystem,
            current_version: current,
            latest_version: latest_version(result),
            status: result.status.token(),
            advisory_id: Some(id.to_string()),
            cvss_score: advisory.and_then(|a| a.severity.score),
            severity: advisory.and_then(|a| a.severity.band).map(|b| b.token()),
            severity_label: advisory.and_then(|a| a.severity.label.clone()),
            cvss_vector: advisory.and_then(|a| a.severity.vector.clone()),
            fixed_versions: advisory
                .map(|a| a.fixed_versions.clone())
                .unwrap_or_default(),
            aliases: advisory.map(|a| a.aliases.clone()).unwrap_or_default(),
            cwe_ids: advisory.map(|a| a.cwe_ids.clone()).unwrap_or_default(),
            advisory_url: advisory
                .and_then(Advisory::advisory_url)
                .map(str::to_string),
        },
    }
}

/// A [`DEP001`] finding for one dependency.
fn outdated_finding(
    result: &CheckResult,
    level: Level,
    ecosystem: &'static str,
    ecosystem_display: &'static str,
    uri: &str,
    start_line: Option<usize>,
) -> Finding {
    let current = current_version(result);
    let latest = latest_version(result);
    Finding {
        rule_id: DEP001,
        rule_index: 0,
        level,
        message: outdated_message(
            &result.item.name,
            &current,
            latest.as_deref(),
            ecosystem_display,
        ),
        uri: uri.to_string(),
        start_line,
        fingerprint: fingerprint(
            DEP001,
            ecosystem,
            &result.item.name,
            result.status.token(),
            uri,
        ),
        properties: ResultProperties {
            package: result.item.name.clone(),
            ecosystem,
            current_version: current,
            latest_version: latest,
            status: result.status.token(),
            advisory_id: None,
            cvss_score: None,
            severity: None,
            severity_label: None,
            cvss_vector: None,
            fixed_versions: Vec::new(),
            aliases: Vec::new(),
            cwe_ids: Vec::new(),
            advisory_url: None,
        },
    }
}

/// The severity band the level follows: a computed CVSS score wins over the
/// publisher's band, which wins over nothing.
///
/// [`Severity`] is deliberately *not* `#[non_exhaustive]`, so this match carries
/// no wildcard — a future band becomes a compile error here rather than a silent
/// mis-level.
fn level_for(advisory: Option<&Advisory>) -> Level {
    let severity = advisory.map(|a| &a.severity);
    let band = severity
        .and_then(|s| s.score)
        .map(Severity::from_score)
        .or_else(|| severity.and_then(|s| s.band));
    match band {
        Some(Severity::Critical | Severity::High) => Level::Error,
        Some(Severity::Medium) => Level::Warning,
        Some(Severity::Low | Severity::None) => Level::Note,
        // An unrated vulnerability is still a vulnerability.
        None => Level::Error,
    }
}

/// The version in use: the locked version, else the declared constraint, else
/// [`UNKNOWN_VERSION`].
fn current_version(result: &CheckResult) -> String {
    result
        .item
        .locked_version
        .clone()
        .or_else(|| {
            (!result.item.version_constraint.is_empty())
                .then(|| result.item.version_constraint.clone())
        })
        .unwrap_or_else(|| UNKNOWN_VERSION.to_string())
}

/// The version to upgrade to: the absolute latest, else the latest compatible.
fn latest_version(result: &CheckResult) -> Option<String> {
    result
        .latest_available
        .clone()
        .or_else(|| result.latest_compatible.clone())
}

/// The [`DEP001`] message. `message.text` is required and must be non-empty, so
/// the "latest" clause is dropped rather than rendered as `None`.
fn outdated_message(package: &str, current: &str, latest: Option<&str>, ecosystem: &str) -> String {
    match latest {
        Some(latest) => {
            format!("`{package}` {current} is outdated; {latest} is available ({ecosystem}).")
        }
        None => format!("`{package}` {current} is outdated ({ecosystem})."),
    }
}

/// The [`DEP002`] message. Every clause after the first is conditional, so the
/// text degrades to `` `pkg` 1.0.0 is affected by RUSTSEC-0000-0000. `` when
/// advisory enrichment is off — still a valid, non-empty `message.text`.
fn vulnerable_message(
    package: &str,
    current: &str,
    id: &str,
    advisory: Option<&Advisory>,
    result: &CheckResult,
) -> String {
    let Some(advisory) = advisory else {
        return format!("`{package}` {current} is affected by {id}.");
    };
    let mut message = format!(
        "`{package}` {current} is affected by {id}: {}.",
        advisory.title()
    );
    if !advisory.fixed_versions.is_empty() {
        message.push_str(&format!(
            " Fixed in {}.",
            advisory.fixed_versions.join(", ")
        ));
    }
    if let Some(latest) = latest_version(result) {
        message.push_str(&format!(" Upgrade to {latest}."));
    }
    if let Some(score) = advisory.severity.score {
        message.push_str(&format!(" CVSS {score}."));
    }
    message
}

/// The stable identity of a finding across runs.
///
/// The **line number is deliberately excluded**: reformatting a manifest would
/// otherwise close and re-open every alert in it. A plain string, not a hash —
/// nothing here needs to be opaque, and a readable fingerprint is a readable
/// diff.
fn fingerprint(
    rule_id: &str,
    ecosystem: &str,
    package: &str,
    discriminator: &str,
    uri: &str,
) -> String {
    format!("{rule_id}:{ecosystem}:{package}:{discriminator}:{uri}")
}

// ---------------------------------------------------------------------------
// URIs
// ---------------------------------------------------------------------------

/// A manifest path as a SARIF `artifactLocation.uri`.
///
/// A path under `root` becomes a relative URI, `/`-joined on every platform and
/// percent-encoded — the form GitHub code scanning wants, since the log carries no
/// `uriBaseId`. [`Path::components`] normalizes `.` away, so `./crates/app/Cargo.toml`
/// yields `crates/app/Cargo.toml` whether or not the prefix stripped.
///
/// A path *outside* `root` cannot be expressed relatively, and emitting it as a bare
/// path-absolute string produced a URI nothing resolves: consumers reject an absolute
/// path with no base, and a Windows path additionally had its drive letter
/// percent-encoded into `C%3A/Users/...`. Such a path becomes an absolute `file:` URI
/// instead, where a drive prefix is legal and keeps its colon. A *relative* path outside
/// the root stays relative — it is already the form a consumer can resolve.
///
/// "Outside the root" is decided by [`Path::has_root`] and not [`Path::is_absolute`],
/// which on Windows are not the same question: `/elsewhere/Cargo.toml` is rooted but
/// carries no drive, so `is_absolute` is false there and the same input produced a
/// `file:` URI on Unix and a bare path-absolute string on Windows. A rooted path is
/// exactly as unresolvable without a base on one platform as on the other, and a SARIF
/// log should not describe the same manifest differently for the machine that rendered
/// it. A drive-relative path (`C:foo`) is rooted by neither test and stays relative.
///
/// No filesystem access: nothing here canonicalizes or probes.
fn uri_for(root: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(root) {
        return encode_uri(&join_components(relative));
    }
    if path.has_root() {
        return absolute_file_uri(path);
    }
    encode_uri(&join_components(path))
}

/// `/`-join a path's components, dropping `.` and any root — but **keeping** a prefix.
///
/// A drive-relative path (`C:foo`) is rooted by neither [`Path::has_root`] nor
/// [`Path::is_absolute`], so it arrives here, and dropping its prefix turned
/// `C:crates\app` into `crates/app` — the same URI a path on any other drive produces.
/// The prefix is emitted as an ordinary segment and percent-encoded with the rest
/// (`C%3A/crates/app`), because outside a `file:` URI's leading position a bare colon
/// is not the drive separator it is there.
fn join_components(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Prefix(p) => Some(p.as_os_str().to_string_lossy().into_owned()),
            Component::ParentDir => Some("..".to_string()),
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
        })
        .collect();
    parts.join("/")
}

/// How one Windows path prefix is spelled in a `file:` URI: an authority, and a leading
/// path segment.
///
/// Split out from [`absolute_file_uri`] because the four prefix forms are the whole
/// difficulty and this is the only way to test them off Windows — [`Path`] parses a
/// prefix only there, while [`Prefix`] itself is spellable everywhere.
///
/// - A drive (`C:`, and the verbatim `\\?\C:` that [`std::fs::canonicalize`] hands
///   back) is a path segment. The colon is legal in a `file:` URI path and encoding it
///   yields `C%3A`, which resolves to nothing.
/// - A UNC share (`\\server\share`, and its verbatim spelling) has a real authority:
///   `file://server/share/...`. Emitting it as a path produced `file://///server/...`,
///   which names a different thing.
/// - The verbatim and device namespaces (`\\?\Volume{…}`, `\\.\COM1`) name no
///   authority, so they stay path segments — encoded, because `?` unencoded opens a URI
///   query and truncated the path at `file:////`.
fn prefix_uri_parts(prefix: Prefix<'_>) -> (Option<String>, Option<String>) {
    let drive = |letter: u8| Some(format!("{}:", letter.to_ascii_uppercase() as char));
    match prefix {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => (None, drive(letter)),
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => (
            Some(encode_uri(&server.to_string_lossy())),
            Some(encode_uri(&share.to_string_lossy())),
        ),
        Prefix::Verbatim(name) | Prefix::DeviceNS(name) => {
            (None, Some(encode_uri(&name.to_string_lossy())))
        }
    }
}

/// An absolute path as a `file:` URI, with each segment percent-encoded.
fn absolute_file_uri(path: &Path) -> String {
    let mut authority = String::new();
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => {
                let (server, segment) = prefix_uri_parts(p.kind());
                if let Some(server) = server {
                    authority = server;
                }
                if let Some(segment) = segment {
                    parts.push(segment);
                }
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_string()),
            Component::Normal(part) => parts.push(encode_uri(&part.to_string_lossy())),
        }
    }
    format!("file://{authority}/{}", parts.join("/"))
}

/// Percent-encode every byte outside the URI-safe set, leaving `/` as the path
/// separator. `crates/my app/Cargo.toml` becomes `crates/my%20app/Cargo.toml`.
fn encode_uri(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(byte as char);
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// The SARIF document
// ---------------------------------------------------------------------------

/// Assemble the log envelope around `findings`.
fn build(findings: &[Finding]) -> SarifLog {
    SarifLog {
        schema: SCHEMA,
        version: SARIF_VERSION,
        runs: [Run {
            tool: Tool {
                driver: ToolComponent {
                    name: TOOL_NAME,
                    version: crate::VERSION,
                    semantic_version: crate::VERSION,
                    information_uri: INFORMATION_URI,
                    rules: rules(),
                },
            },
            automation_details: AutomationDetails { id: AUTOMATION_ID },
            results: findings.iter().map(SarifResult::from_finding).collect(),
        }],
    }
}

/// The full rule catalogue, always emitted whether or not a rule fired — a
/// consumer reading `tool.driver.rules` learns what this tool can report.
fn rules() -> [ReportingDescriptor; 2] {
    [
        ReportingDescriptor {
            id: DEP001,
            name: "OutdatedDependency",
            short_description: Text::new("A newer version of the dependency is available."),
            full_description: Text::new(
                "The manifest declares a dependency whose newest published version is greater \
                 than the version in use. Falling behind accumulates upgrade risk and delays \
                 the delivery of security fixes.",
            ),
            help: Text::new(
                "Raise the version constraint in the manifest, or run `dependable check --fix`.",
            ),
            help_uri: INFORMATION_URI,
            default_configuration: RuleConfig {
                level: Level::Warning,
            },
            properties: RuleProperties {
                tags: &["dependencies", "maintenance"],
                security_severity: None,
            },
        },
        ReportingDescriptor {
            id: DEP002,
            name: "VulnerableDependency",
            short_description: Text::new(
                "The dependency version in use is affected by a known advisory.",
            ),
            full_description: Text::new(
                "An OSV advisory affects the resolved version of this dependency. Upgrade to a \
                 fixed version, or remove the dependency.",
            ),
            help: Text::new(
                "Upgrade to a version outside the advisory's affected range, or drop the \
                 dependency.",
            ),
            help_uri: INFORMATION_URI,
            default_configuration: RuleConfig {
                level: Level::Error,
            },
            properties: RuleProperties {
                tags: &["security", "dependencies", "vulnerability"],
                security_severity: Some(DEP002_SECURITY_SEVERITY),
            },
        },
    ]
}

/// The root of a SARIF log.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    /// Exactly one run per invocation, however many manifests were checked.
    runs: [Run; 1],
}

/// One analysis run.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    tool: Tool,
    automation_details: AutomationDetails,
    /// **Never** skipped when empty: an absent `results` means the run produced
    /// nothing because it failed, not because it found nothing.
    results: Vec<SarifResult>,
}

/// Identifies this run as one instance of a recurring analysis.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AutomationDetails {
    id: &'static str,
}

/// The analysis tool.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Tool {
    driver: ToolComponent,
}

/// The tool's primary component and its rule catalogue.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolComponent {
    name: &'static str,
    version: &'static str,
    semantic_version: &'static str,
    information_uri: &'static str,
    rules: [ReportingDescriptor; 2],
}

/// One rule in the catalogue.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportingDescriptor {
    id: &'static str,
    name: &'static str,
    short_description: Text,
    full_description: Text,
    help: Text,
    help_uri: &'static str,
    default_configuration: RuleConfig,
    properties: RuleProperties,
}

/// A rule's default configuration.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleConfig {
    level: Level,
}

/// A rule's property bag.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleProperties {
    tags: &'static [&'static str],
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    security_severity: Option<&'static str>,
}

/// One reported finding.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: &'static str,
    rule_index: usize,
    /// Always explicit, never inherited from the rule's default configuration —
    /// a per-finding severity is the whole point of the band mapping.
    level: Level,
    message: Text,
    locations: [Location; 1],
    partial_fingerprints: BTreeMap<String, String>,
    properties: ResultProperties,
}

impl SarifResult {
    fn from_finding(finding: &Finding) -> Self {
        let mut partial_fingerprints = BTreeMap::new();
        partial_fingerprints.insert(FINGERPRINT_KEY.to_string(), finding.fingerprint.clone());
        Self {
            rule_id: finding.rule_id,
            rule_index: finding.rule_index,
            level: finding.level,
            message: Text::new(&finding.message),
            locations: [Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: finding.uri.clone(),
                    },
                    region: finding.start_line.map(|start_line| Region { start_line }),
                },
            }],
            partial_fingerprints,
            properties: finding.properties.clone(),
        }
    }
}

/// Where a finding is.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

/// A location in a file.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    /// Absent when the finding has no truthful line in this file — see [`start_line`].
    /// SARIF permits a bare `artifactLocation`, and consumers fall back to the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

/// The file itself. No `uriBaseId` — see the module docs.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
}

/// The span within the file. Line only, and always one-based.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
}

/// SARIF's `multiformatMessageString`, in its plain-text form.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Text {
    text: String,
}

impl Text {
    fn new(text: &str) -> Self {
        Self {
            text: text.to_string(),
        }
    }
}

/// A result's severity.
///
/// SARIF also defines `"none"`, which this renderer never emits: every finding
/// it produces is worth at least a note.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum Level {
    Note,
    Warning,
    Error,
}

/// A result's property bag: everything a consumer might want that SARIF has no
/// first-class slot for.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ResultProperties {
    package: String,
    /// The OSV ecosystem name (`crates.io`, `npm`, …), the machine-readable form.
    ecosystem: &'static str,
    current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_version: Option<String>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_vector: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixed_versions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cwe_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use dependable_core::result::{AdvisorySeverity, CvssVersion};
    use dependable_core::{Ecosystem, ManifestKind, PackageSource, parse};
    use serde_json::Value;
    use time::OffsetDateTime;

    use super::*;
    use crate::model::ManifestResults;

    /// A Cargo manifest whose line numbers are the point of the fixture:
    ///
    /// ```text
    /// 1  [package]
    /// 2  name = "sample"
    /// 3
    /// 4  [dependencies]
    /// 5  serde = "1.0.100"
    /// ```
    ///
    /// `serde` declares its version on **source line 5**, so `version_line` (which
    /// is zero-indexed) is 4 and SARIF's `startLine` must be 5.
    /// [`start_line_is_one_based`] pins both the derived and the literal end.
    const FIXTURE: &str = "[package]\nname = \"sample\"\n\n[dependencies]\nserde = \"1.0.100\"\n";

    /// `Item` is `#[non_exhaustive]` with no constructor, so every fixture here
    /// is minted the only way an external crate can: by parsing a manifest with
    /// `dependable_core`'s Cargo parser. A failure in these tests that mentions
    /// a missing or misplaced item means **the core parser changed**, not that
    /// the SARIF renderer broke.
    fn result(status: DependencyStatus) -> CheckResult {
        let parsed = parse(ManifestKind::CargoToml, FIXTURE).expect("parse the fixture manifest");
        let item = parsed
            .items
            .into_iter()
            .find(|i| i.name == "serde")
            .expect("the fixture declares serde");
        CheckResult::new(item, status)
    }

    /// A result with a version the checker would have resolved.
    fn outdated() -> CheckResult {
        let mut result = result(DependencyStatus::Outdated);
        result.latest_available = Some("1.0.200".to_string());
        result
    }

    fn report_of(results: Vec<CheckResult>) -> Report {
        report_at(
            PathBuf::from("/repo"),
            PathBuf::from("/repo/Cargo.toml"),
            results,
        )
    }

    fn report_at(root: PathBuf, path: PathBuf, results: Vec<CheckResult>) -> Report {
        let mut report = Report::new(root);
        report.push(ManifestResults::new(path, Ecosystem::Rust, results));
        report
    }

    fn rendered(report: &Report) -> Value {
        serde_json::from_str(&render(report).expect("render the report")).expect("valid JSON")
    }

    fn run(value: &Value) -> &Value {
        &value["runs"][0]
    }

    fn results_of(value: &Value) -> &Vec<Value> {
        run(value)["results"]
            .as_array()
            .expect("results is an array")
    }

    // -- A.1 ----------------------------------------------------------------

    #[test]
    fn empty_report_has_the_required_envelope() {
        let log = rendered(&Report::new(PathBuf::from("/repo")));

        assert_eq!(log["$schema"], SCHEMA);
        assert_eq!(log["version"], "2.1.0");
        assert_eq!(log["runs"].as_array().expect("runs").len(), 1);

        let driver = &run(&log)["tool"]["driver"];
        assert_eq!(driver["name"], "dependable");
        assert_eq!(driver["version"], crate::VERSION);
        assert_eq!(driver["semanticVersion"], crate::VERSION);
        assert_eq!(driver["informationUri"], INFORMATION_URI);

        let rules = driver["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], DEP001);
        assert_eq!(rules[1]["id"], DEP002);
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "warning");
        assert_eq!(rules[1]["defaultConfiguration"]["level"], "error");
        assert_eq!(rules[1]["properties"]["security-severity"], "7.0");

        // Present and empty: an *absent* `results` would mean the run failed.
        assert!(
            run(&log).get("results").is_some(),
            "`results` must always be emitted"
        );
        assert!(results_of(&log).is_empty());
    }

    // -- A.2 ----------------------------------------------------------------

    #[test]
    fn outdated_result_carries_the_required_fields() {
        let log = rendered(&report_of(vec![outdated()]));
        let results = results_of(&log);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], DEP001);
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[0]["level"], "warning");
        assert!(
            !results[0]["message"]["text"]
                .as_str()
                .expect("a message")
                .is_empty()
        );
        assert_eq!(
            results[0]["locations"].as_array().expect("locations").len(),
            1
        );
        assert_eq!(results[0]["properties"]["package"], "serde");
        assert_eq!(results[0]["properties"]["ecosystem"], "crates.io");
        assert_eq!(results[0]["properties"]["latestVersion"], "1.0.200");
    }

    // -- A.3 ----------------------------------------------------------------

    #[test]
    fn start_line_is_one_based() {
        let result = outdated();
        // Derived: the invariant, whatever the fixture says.
        let expected = result.item.version_line + 1;
        // Literal: a human counting lines in FIXTURE lands on 5.
        assert_eq!(result.item.version_line, 4, "the fixture moved");
        assert_eq!(expected, 5);

        let log = rendered(&report_of(vec![result]));
        let region = &results_of(&log)[0]["locations"][0]["physicalLocation"]["region"];

        assert_eq!(region["startLine"], expected);
        assert_eq!(region["startLine"], 5);
        // Byte offsets are not code points, so no columns are emitted at all.
        assert!(region.get("startColumn").is_none());
        assert!(region.get("endColumn").is_none());
    }

    /// A workspace member inheriting `dep.workspace = true` is checkable, so it reaches
    /// the renderer — but its version string is in the root manifest, and its recorded
    /// span is a zero that would render as `startLine: 1`. Code scanning gets the file
    /// and no line, rather than a confident pointer at the wrong one.
    #[test]
    fn an_inherited_dependency_gets_a_location_with_no_region() {
        let mut result = outdated();
        result.item.source = PackageSource::Inherited;
        result.item.version_constraint = "1.0.100".to_string();
        assert!(
            result.item.is_checkable(),
            "it must still produce a finding"
        );
        assert!(!result.item.is_rewritable());

        let log = rendered(&report_of(vec![result]));
        let location = &results_of(&log)[0]["locations"][0]["physicalLocation"];

        assert_eq!(location["artifactLocation"]["uri"], "Cargo.toml");
        assert!(
            location.get("region").is_none(),
            "no region at all: {location}"
        );
    }

    // -- A.4 ----------------------------------------------------------------

    /// A path that is absolute on the platform the test is running on.
    ///
    /// `/elsewhere/Cargo.toml` is absolute on Unix and *not* on Windows, where
    /// [`Path::is_absolute`] wants a drive prefix. A fixture written that way
    /// takes `uri_for`'s relative branch on Windows while asserting the absolute
    /// branch's answer, so the assertion tests nothing there and fails.
    fn outside_root(rest: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{}", rest.replace('/', "\\")))
        } else {
            PathBuf::from(format!("/{rest}"))
        }
    }

    /// The `file:` URI [`outside_root`] renders to, whose drive prefix Windows
    /// keeps and Unix has none of.
    fn outside_root_uri(rest: &str) -> String {
        if cfg!(windows) {
            format!("file:///C:/{rest}")
        } else {
            format!("file:///{rest}")
        }
    }

    #[test]
    fn uri_is_relative_to_report_root_and_slash_joined() {
        let log = rendered(&report_at(
            PathBuf::from("/repo"),
            PathBuf::from("/repo/crates/app/Cargo.toml"),
            vec![outdated()],
        ));
        let location = &results_of(&log)[0]["locations"][0]["physicalLocation"];

        assert_eq!(location["artifactLocation"]["uri"], "crates/app/Cargo.toml");
        // No uriBaseId: it would carry the developer's absolute path.
        assert!(location["artifactLocation"].get("uriBaseId").is_none());

        // An absolute path outside the root becomes a `file:` URI. A bare
        // path-absolute string is not resolvable by a consumer that was given no
        // `uriBaseId`, which this log deliberately omits.
        let outside = rendered(&report_at(
            PathBuf::from("/repo"),
            outside_root("elsewhere/Cargo.toml"),
            vec![outdated()],
        ));
        assert_eq!(
            results_of(&outside)[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            outside_root_uri("elsewhere/Cargo.toml").as_str()
        );

        // `.` components are normalized away even when the prefix does not strip.
        assert_eq!(
            uri_for(Path::new("."), Path::new("./crates/app/Cargo.toml")),
            "crates/app/Cargo.toml"
        );
        assert_eq!(
            uri_for(Path::new("/nope"), Path::new("./crates/app/Cargo.toml")),
            "crates/app/Cargo.toml"
        );
    }

    // -- A.5 ----------------------------------------------------------------

    #[test]
    fn uri_components_are_percent_encoded() {
        assert_eq!(
            uri_for(
                Path::new("/repo"),
                Path::new("/repo/crates/my app/Cargo.toml")
            ),
            "crates/my%20app/Cargo.toml"
        );
        // The separator itself survives; so do the unreserved characters.
        assert_eq!(
            uri_for(Path::new("/repo"), Path::new("/repo/a-b_c.d~e/Cargo.toml")),
            "a-b_c.d~e/Cargo.toml"
        );
    }

    // -- A.6 ----------------------------------------------------------------

    /// A vulnerable result with one fully enriched advisory.
    fn vulnerable(ids: &[&str], advisories: Vec<Advisory>) -> CheckResult {
        let mut result = result(DependencyStatus::Vulnerable);
        result.latest_available = Some("1.0.200".to_string());
        result.current_vulnerabilities = ids.iter().map(|id| (*id).to_string()).collect();
        result.advisories = advisories;
        result
    }

    #[test]
    fn vulnerable_result_carries_cvss_score() {
        let advisory = Advisory::new("RUSTSEC-2020-0071")
            .with_summary("Use-after-free")
            .with_severity(
                AdvisorySeverity::from_score(9.8)
                    .with_vector("CVSS:3.1/AV:N", CvssVersion::V3)
                    .with_label("CRITICAL"),
            )
            .with_fixed_versions(vec!["1.0.150".to_string()])
            .with_aliases(vec!["CVE-2020-0000".to_string()]);
        let log = rendered(&report_of(vec![vulnerable(
            &["RUSTSEC-2020-0071"],
            vec![advisory],
        )]));
        let results = results_of(&log);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], DEP002);
        assert_eq!(results[0]["ruleIndex"], 1);
        assert_eq!(results[0]["level"], "error");

        let properties = &results[0]["properties"];
        assert_eq!(properties["cvssScore"], 9.8);
        assert_eq!(properties["severity"], "CRITICAL");
        assert_eq!(properties["severityLabel"], "CRITICAL");
        assert_eq!(properties["cvssVector"], "CVSS:3.1/AV:N");
        assert_eq!(properties["advisoryId"], "RUSTSEC-2020-0071");
        assert_eq!(properties["fixedVersions"][0], "1.0.150");
        assert_eq!(properties["aliases"][0], "CVE-2020-0000");
        // The enum is not serialized, so no cvssVersion key exists.
        assert!(properties.get("cvssVersion").is_none());

        let message = results[0]["message"]["text"].as_str().expect("a message");
        assert!(message.contains("RUSTSEC-2020-0071"), "{message}");
        assert!(message.contains("Use-after-free"), "{message}");
        assert!(message.contains("Fixed in 1.0.150."), "{message}");
        assert!(message.contains("Upgrade to 1.0.200."), "{message}");
        assert!(message.contains("CVSS 9.8."), "{message}");
    }

    // -- A.7 ----------------------------------------------------------------

    #[test]
    fn level_follows_the_severity_band_numeric_first() {
        let cases: [(AdvisorySeverity, Level); 7] = [
            (AdvisorySeverity::from_score(9.8), Level::Error),
            (AdvisorySeverity::from_score(7.0), Level::Error),
            (AdvisorySeverity::from_score(5.0), Level::Warning),
            (AdvisorySeverity::from_score(1.0), Level::Note),
            (AdvisorySeverity::from_score(0.0), Level::Note),
            // A score present but a label contradicting it: the number wins.
            (
                AdvisorySeverity::from_score(9.8).with_label("LOW"),
                Level::Error,
            ),
            // Rated by label only.
            (AdvisorySeverity::from_label("MODERATE"), Level::Warning),
        ];
        for (severity, expected) in cases {
            let advisory = Advisory::new("X").with_severity(severity.clone());
            assert_eq!(
                level_for(Some(&advisory)),
                expected,
                "band {:?} score {:?}",
                severity.band,
                severity.score
            );
        }

        // Unrated, and not enriched at all: still an error, because an unrated
        // vulnerability is still a vulnerability.
        assert_eq!(
            level_for(Some(
                &Advisory::new("X").with_severity(AdvisorySeverity::unrated())
            )),
            Level::Error
        );
        assert_eq!(level_for(None), Level::Error);
    }

    // -- A.8 ----------------------------------------------------------------

    #[test]
    fn one_result_per_advisory() {
        // Deliberately supplied out of order: the renderer sorts.
        let log = rendered(&report_of(vec![vulnerable(
            &["RUSTSEC-2021-0002", "GHSA-aaaa-bbbb-cccc"],
            vec![
                Advisory::new("RUSTSEC-2021-0002").with_severity(AdvisorySeverity::from_score(9.1)),
                Advisory::new("GHSA-aaaa-bbbb-cccc")
                    .with_severity(AdvisorySeverity::from_score(4.0)),
            ],
        )]));
        let results = results_of(&log);

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0]["properties"]["advisoryId"],
            "GHSA-aaaa-bbbb-cccc"
        );
        assert_eq!(results[1]["properties"]["advisoryId"], "RUSTSEC-2021-0002");
        // Each carries its own score and its own level.
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(results[1]["level"], "error");
        // ... and its own fingerprint, so they are two distinct alerts.
        assert_ne!(
            results[0]["partialFingerprints"][FINGERPRINT_KEY],
            results[1]["partialFingerprints"][FINGERPRINT_KEY]
        );
    }

    // -- A.9 ----------------------------------------------------------------

    #[test]
    fn status_mapping_table() {
        let cases: [(DependencyStatus, Option<(&str, &str)>); 8] = [
            (DependencyStatus::Outdated, Some((DEP001, "warning"))),
            (DependencyStatus::UpdateAvailable, Some((DEP001, "note"))),
            (DependencyStatus::PatchAvailable, None),
            (DependencyStatus::UpToDate, None),
            (DependencyStatus::Local, None),
            (DependencyStatus::Git, None),
            (DependencyStatus::Error("boom".to_string()), None),
            (DependencyStatus::Vulnerable, Some((DEP002, "error"))),
        ];
        for (status, expected) in cases {
            let mut check = result(status.clone());
            check.latest_available = Some("1.0.200".to_string());
            if status == DependencyStatus::Vulnerable {
                check.current_vulnerabilities = vec!["RUSTSEC-2020-0071".to_string()];
            }
            let log = rendered(&report_of(vec![check]));
            let results = results_of(&log);
            match expected {
                Some((rule, level)) => {
                    assert_eq!(results.len(), 1, "{status:?} should emit one result");
                    assert_eq!(results[0]["ruleId"], rule, "{status:?}");
                    assert_eq!(results[0]["level"], level, "{status:?}");
                }
                None => assert!(results.is_empty(), "{status:?} should emit nothing"),
            }
        }
    }

    // -- A.10 ---------------------------------------------------------------

    #[test]
    fn unenriched_vulnerable_still_renders() {
        // Enrichment off: IDs but no advisory records.
        let log = rendered(&report_of(vec![vulnerable(
            &["RUSTSEC-2020-0071"],
            Vec::new(),
        )]));
        let results = results_of(&log);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], DEP002);
        // No band to read, so the rule's own default applies.
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["message"]["text"],
            "`serde` 1.0.100 is affected by RUSTSEC-2020-0071."
        );
        let properties = &results[0]["properties"];
        assert!(properties.get("cvssScore").is_none());
        assert!(properties.get("severity").is_none());
        assert!(properties.get("fixedVersions").is_none());
        assert_eq!(properties["advisoryId"], "RUSTSEC-2020-0071");
    }

    // -- A.11 ---------------------------------------------------------------

    #[test]
    fn optional_fields_are_omitted_not_null() {
        fn assert_no_nulls(value: &Value, path: &str) {
            match value {
                Value::Null => panic!("null at {path}; omit the key instead"),
                Value::Object(map) => {
                    for (key, child) in map {
                        assert_no_nulls(child, &format!("{path}.{key}"));
                    }
                }
                Value::Array(items) => {
                    for (index, child) in items.iter().enumerate() {
                        assert_no_nulls(child, &format!("{path}[{index}]"));
                    }
                }
                _ => {}
            }
        }

        let mut report = Report::new(PathBuf::from("/repo"));
        report.push(ManifestResults::new(
            PathBuf::from("/repo/Cargo.toml"),
            Ecosystem::Rust,
            vec![
                outdated(),
                result(DependencyStatus::UpdateAvailable),
                vulnerable(&["RUSTSEC-2020-0071"], Vec::new()),
                vulnerable(
                    &["GHSA-aaaa-bbbb-cccc"],
                    vec![
                        Advisory::new("GHSA-aaaa-bbbb-cccc")
                            .with_severity(AdvisorySeverity::from_score(6.1)),
                    ],
                ),
            ],
        ));
        assert_no_nulls(&rendered(&report), "$");
    }

    // -- A.12 ---------------------------------------------------------------

    #[test]
    fn fingerprints_ignore_the_line_number() {
        // Two manifests differing only in where the dependency sits.
        let early = "[dependencies]\nserde = \"1.0.100\"\n";
        let late = "[package]\nname = \"s\"\n\n\n\n\n\n\n[dependencies]\nserde = \"1.0.100\"\n";
        let fingerprint_of = |source: &str| {
            let item = parse(ManifestKind::CargoToml, source)
                .expect("parse")
                .items
                .into_iter()
                .find(|i| i.name == "serde")
                .expect("serde");
            let mut check = CheckResult::new(item, DependencyStatus::Outdated);
            check.latest_available = Some("1.0.200".to_string());
            let log = rendered(&report_of(vec![check]));
            let results = results_of(&log);
            (
                results[0]["partialFingerprints"][FINGERPRINT_KEY]
                    .as_str()
                    .expect("a fingerprint")
                    .to_string(),
                results[0]["locations"][0]["physicalLocation"]["region"]["startLine"].clone(),
            )
        };

        let (early_print, early_line) = fingerprint_of(early);
        let (late_print, late_line) = fingerprint_of(late);

        assert_ne!(early_line, late_line, "the fixture must move the line");
        assert_eq!(
            early_print, late_print,
            "reformatting a manifest must not re-key the alert"
        );
    }

    // -- A.13 ---------------------------------------------------------------

    #[test]
    fn generated_at_is_not_serialized() {
        let build = |stamp: i64| {
            let mut report = Report::at(
                PathBuf::from("/repo"),
                OffsetDateTime::from_unix_timestamp(stamp).expect("a valid timestamp"),
            );
            report.push(ManifestResults::new(
                PathBuf::from("/repo/Cargo.toml"),
                Ecosystem::Rust,
                vec![outdated()],
            ));
            render(&report).expect("render the report")
        };

        assert_eq!(build(1_700_000_000), build(0));
    }

    /// A Windows path had its drive prefix percent-encoded into `C%3A/...`, which names
    /// nothing. In a `file:` URI the colon is legal and must survive; the encoding still
    /// applies to the segments, where a space is real.
    ///
    /// Windows-only: elsewhere a backslash is an ordinary character and `C:\...` is one
    /// relative component, so there is no drive prefix to preserve. The CI matrix runs
    /// the suite on `windows-latest`, which is where this bites.
    #[cfg(windows)]
    #[test]
    fn a_windows_path_keeps_its_drive_and_encodes_its_segments() {
        let uri = uri_for(
            Path::new(r"D:\repo"),
            Path::new(r"C:\Users\dev\my project\Cargo.toml"),
        );
        assert!(!uri.contains("%3A"), "the drive colon was encoded: {uri}");
        assert_eq!(uri, "file:///C:/Users/dev/my%20project/Cargo.toml");

        // A rooted path carrying no drive is `is_absolute() == false` on Windows and
        // true everywhere else. It is unresolvable without a base on both, so it takes
        // the same `file:` form on both — a log must not describe one manifest two ways
        // depending on the machine that rendered it.
        assert_eq!(
            uri_for(Path::new(r"D:\repo"), Path::new("/elsewhere/Cargo.toml")),
            "file:///elsewhere/Cargo.toml"
        );

        // A drive-relative path (`C:foo`) is rooted by neither test: it resolves against
        // that drive's working directory, so it stays relative — but it keeps naming its
        // drive. This assertion used to read `crates/app/Cargo.toml`, which is the URI a
        // path on *any* drive produces: the correction restores information the renderer
        // was dropping, it does not relax the check.
        assert_eq!(
            uri_for(Path::new(r"D:\repo"), Path::new(r"C:crates\app\Cargo.toml")),
            "C%3A/crates/app/Cargo.toml"
        );

        // A UNC share has a real authority. Rendering it as a path produced
        // `file://///server/share/...`, which names a different thing.
        assert_eq!(
            uri_for(
                Path::new(r"D:\repo"),
                Path::new(r"\\server\share\repo\Cargo.toml")
            ),
            "file://server/share/repo/Cargo.toml"
        );

        // The verbatim form `std::fs::canonicalize` returns, and which `discover.rs`
        // deliberately preserves. Emitting the prefix unencoded left `file:////?/C:/...`,
        // where the `?` opens a URI query and truncates the path at `file:////`.
        assert_eq!(
            uri_for(Path::new(r"D:\repo"), Path::new(r"\\?\C:\repo\Cargo.toml")),
            "file:///C:/repo/Cargo.toml"
        );
        assert_eq!(
            uri_for(
                Path::new(r"D:\repo"),
                Path::new(r"\\?\UNC\server\share\repo\Cargo.toml")
            ),
            "file://server/share/repo/Cargo.toml"
        );
    }

    /// The prefix forms, off Windows.
    ///
    /// [`Path`] parses a prefix only on Windows, so the end-to-end assertions above run
    /// on one platform in the CI matrix — which is how the UNC and verbatim spellings
    /// went unnoticed. [`Prefix`] itself is spellable everywhere, so the decision each
    /// form drives is checked on every platform the suite runs on.
    #[test]
    fn every_windows_prefix_form_has_a_uri_spelling() {
        use std::ffi::OsStr;

        // A drive is a path segment, and its colon must survive: `C%3A` in the leading
        // position of a `file:` URI resolves to nothing.
        assert_eq!(
            prefix_uri_parts(Prefix::Disk(b'C')),
            (None, Some("C:".to_owned()))
        );
        // `\?\C:\...` is what `std::fs::canonicalize` returns and what `simplified()`
        // preserves; it names the same drive.
        assert_eq!(
            prefix_uri_parts(Prefix::VerbatimDisk(b'C')),
            (None, Some("C:".to_owned()))
        );

        // A UNC share is an authority plus a first segment, not four extra slashes.
        assert_eq!(
            prefix_uri_parts(Prefix::UNC(OsStr::new("server"), OsStr::new("share"))),
            (Some("server".to_owned()), Some("share".to_owned()))
        );
        assert_eq!(
            prefix_uri_parts(Prefix::VerbatimUNC(
                OsStr::new("server"),
                OsStr::new("share")
            )),
            (Some("server".to_owned()), Some("share".to_owned()))
        );

        // The verbatim and device namespaces name no authority, and every byte of them
        // is encoded — an unencoded `?` opens a URI query and truncates the path.
        let (authority, segment) = prefix_uri_parts(Prefix::Verbatim(OsStr::new("Volume{1}")));
        assert_eq!(authority, None);
        let segment = segment.expect("a verbatim namespace names a segment");
        assert!(!segment.contains('{'), "{segment}");
        assert!(!segment.contains('}'), "{segment}");

        assert_eq!(
            prefix_uri_parts(Prefix::DeviceNS(OsStr::new("COM1"))),
            (None, Some("COM1".to_owned()))
        );
    }

    /// A space in a directory name still has to be encoded, in both forms.
    #[test]
    fn spaces_are_encoded_in_relative_and_absolute_uris() {
        assert_eq!(
            uri_for(Path::new("/repo"), Path::new("/repo/my app/Cargo.toml")),
            "my%20app/Cargo.toml"
        );
        assert_eq!(
            uri_for(Path::new("/repo"), &outside_root("other dir/Cargo.toml")),
            outside_root_uri("other%20dir/Cargo.toml")
        );
    }

    /// A relative path that does not sit under the root is already resolvable; turning it
    /// into a `file:` URI would invent a base it never had.
    #[test]
    fn a_relative_path_outside_the_root_stays_relative() {
        assert_eq!(
            uri_for(Path::new("/repo"), Path::new("crates/app/Cargo.toml")),
            "crates/app/Cargo.toml"
        );
    }
}
