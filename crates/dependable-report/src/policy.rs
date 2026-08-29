//! Policy evaluation for CI gating.
//!
//! A [`Policy`] is the `[policy]` block of `.dependable.toml`: a set of rules a
//! project's dependencies must satisfy for CI to stay green. [`evaluate`] applies
//! it to a [`Report`] and returns a [`PolicyOutcome`] — the findings, in a stable
//! order, with a message for each.
//!
//! # Design
//!
//! - **The schema lives here**, in the crate that enforces it, and the CLI embeds
//!   it as a field on its config. The config file and the evaluator therefore
//!   cannot drift apart.
//! - **`deny_unknown_fields`**: a typo'd `max_cvvs` is an *error*, not a silently
//!   disabled security gate. A policy that exists is either enforced or it is an
//!   error.
//! - **Pure**: no IO, no exit codes, no knowledge of the terminal. The caller maps
//!   [`PolicyOutcome::has_violations`] onto its own exit status.

use std::path::PathBuf;

use dependable_core::result::{Advisory, Severity};
use dependable_core::semver::normalize::normalize_version;
use dependable_core::semver::{nuget, python};
use dependable_core::{CheckResult, Ecosystem};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model::Report;

/// The severity words [`Policy::fail_on_severity`] accepts, for error messages.
const SEVERITY_TOKENS: &str = "none, low, medium (moderate), high, critical";

/// The ecosystem words a `ecosystem = "..."` key accepts, for error messages.
const ECOSYSTEM_TOKENS: &str = "rust (cargo, crates.io), go (golang), \
npm (node, js, javascript), python (pypi, pip), php (composer, packagist), \
dart (pub, flutter), csharp (c#, dotnet, nuget), elixir (hex, mix)";

/// The CI gating rules read from the `[policy]` block of `.dependable.toml`.
///
/// Every field is optional and the default gates nothing, so adding the block is
/// always opt-in. `#[non_exhaustive]`: build with [`Policy::default`] and assign
/// fields, so later rules (license allowlists) are additive.
///
/// ```toml
/// [policy]
/// max_cvss = 7.0
/// max_major_behind = 2
/// unrated_advisories = "warn"
/// denied_packages = [{ ecosystem = "npm", name = "left-pad" }]
///
/// [[policy.minimum_versions]]
/// name = "openssl"
/// min_version = "0.10.64"
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Policy {
    /// Fail when a dependency carries an advisory whose CVSS base score is at or
    /// above this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cvss: Option<f64>,
    /// Fail at or above this named severity band. Ignored when [`Self::max_cvss`]
    /// is also set — a number is more precise than a word.
    #[serde(
        deserialize_with = "de_severity",
        serialize_with = "ser_severity",
        skip_serializing_if = "Option::is_none"
    )]
    pub fail_on_severity: Option<Severity>,
    /// Fail when a dependency is more than this many major versions behind the
    /// latest available release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_major_behind: Option<u64>,
    /// What to do about advisories that carry no CVSS score at all while a CVSS
    /// rule is in force. Defaults to [`UnratedPolicy::Warn`].
    #[serde(skip_serializing_if = "UnratedPolicy::is_default")]
    pub unrated_advisories: UnratedPolicy,
    /// Packages that must not appear at all, whatever their version or source.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub denied_packages: Vec<PackageRef>,
    /// Floors a named package's version must meet.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub minimum_versions: Vec<MinimumVersion>,
}

impl Policy {
    /// Whether any rule is configured. A policy that gates nothing need not be
    /// evaluated at all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.max_cvss.is_some()
            || self.fail_on_severity.is_some()
            || self.max_major_behind.is_some()
            || !self.denied_packages.is_empty()
            || !self.minimum_versions.is_empty()
    }

    /// Whether a rule here can only be enforced with vulnerability scanning on.
    ///
    /// The caller checks this **before** running: with scanning off every score
    /// is `None`, and [`evaluate`] cannot tell "no advisories were fetched" from
    /// "no advisories exist", so the gate would pass vacuously.
    #[must_use]
    pub fn requires_cvss(&self) -> bool {
        self.max_cvss.is_some() || self.fail_on_severity.is_some()
    }
}

/// A package named by a rule: a name, optionally scoped to one ecosystem.
///
/// Omitting `ecosystem` matches the name in every ecosystem, which is what a
/// polyglot repository usually wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PackageRef {
    /// The ecosystem to scope the match to; `None` matches every ecosystem.
    #[serde(default, with = "eco_opt", skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<Ecosystem>,
    /// The package name, matched ASCII case-insensitively.
    pub name: String,
}

impl PackageRef {
    /// A reference to `name` in every ecosystem.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            ecosystem: None,
            name: name.into(),
        }
    }

    /// Scope this reference to a single ecosystem.
    #[must_use]
    pub fn in_ecosystem(mut self, ecosystem: Ecosystem) -> Self {
        self.ecosystem = Some(ecosystem);
        self
    }
}

/// A floor one package's version must meet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct MinimumVersion {
    /// The ecosystem to scope the match to; `None` matches every ecosystem.
    #[serde(default, with = "eco_opt", skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<Ecosystem>,
    /// The package name, matched ASCII case-insensitively.
    pub name: String,
    /// The lowest acceptable version.
    pub min_version: String,
    /// Why the floor exists. Echoed in the failure message, so a person reading
    /// a red build learns the reason without opening the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MinimumVersion {
    /// A floor of `min_version` for `name`, in every ecosystem.
    #[must_use]
    pub fn new(name: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            ecosystem: None,
            name: name.into(),
            min_version: min_version.into(),
            reason: None,
        }
    }

    /// Scope this floor to a single ecosystem.
    #[must_use]
    pub fn in_ecosystem(mut self, ecosystem: Ecosystem) -> Self {
        self.ecosystem = Some(ecosystem);
        self
    }

    /// Record why the floor exists.
    #[must_use]
    pub fn because(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// What to do with an advisory that carries no CVSS score while a CVSS rule is
/// in force.
///
/// The default is [`UnratedPolicy::Warn`], not `Fail`: RUSTSEC advisories
/// frequently ship without a CVSS vector, and failing every build on them makes
/// `max_cvss` unusable — an unusable gate gets deleted from CI, which is strictly
/// worse than a loud warning. What it must never do is *silently pass*.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnratedPolicy {
    /// Say nothing about unrated advisories.
    Ignore,
    /// Report them as warnings; the build still passes on them alone.
    #[default]
    Warn,
    /// Treat an unrated advisory as a violation.
    Fail,
}

impl UnratedPolicy {
    /// Whether this is the default, so serialization can omit it.
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, UnratedPolicy::Warn)
    }
}

/// Everything [`evaluate`] found, in a deterministic order.
///
/// Order is manifest order, then dependency order within a manifest, then rule
/// order — so two runs over the same report produce byte-identical output.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PolicyOutcome {
    /// Warnings and violations, in evaluation order.
    pub findings: Vec<Finding>,
    /// How many dependencies were examined.
    pub evaluated: usize,
    /// Remarks about the policy itself (an overridden key, say) rather than
    /// about any one dependency.
    pub notes: Vec<String>,
}

impl PolicyOutcome {
    /// Whether anything at [`Level::Violation`] was found — the caller's cue to
    /// fail the build.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        self.violations().next().is_some()
    }

    /// Only the findings that fail the build.
    pub fn violations(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| matches!(f.level, Level::Violation))
    }

    /// Only the findings that are advisory.
    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| matches!(f.level, Level::Warning))
    }

    /// How many findings fail the build.
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations().count()
    }
}

/// How seriously to take a [`Finding`].
///
/// `#[non_exhaustive]`: match with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    /// Reported, but does not fail the build.
    Warning,
    /// Fails the build.
    Violation,
}

/// Which rule produced a [`Finding`].
///
/// `#[non_exhaustive]`: match with a wildcard arm, so a later rule (a license
/// allowlist) is additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rule {
    /// [`Policy::max_cvss`].
    MaxCvss,
    /// [`Policy::fail_on_severity`].
    FailOnSeverity,
    /// [`Policy::max_major_behind`].
    MaxMajorBehind,
    /// [`Policy::denied_packages`].
    DeniedPackage,
    /// [`Policy::minimum_versions`].
    MinimumVersion,
}

impl Rule {
    /// The configuration key this rule is spelled with.
    ///
    /// Returning the *key* rather than a prose name is what makes a red build
    /// actionable: the token in the message is the line to edit.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Rule::MaxCvss => "max_cvss",
            Rule::FailOnSeverity => "fail_on_severity",
            Rule::MaxMajorBehind => "max_major_behind",
            Rule::DeniedPackage => "denied_packages",
            Rule::MinimumVersion => "minimum_versions",
        }
    }
}

/// The rule-specific evidence behind a [`Finding`].
///
/// `#[non_exhaustive]`: match with a wildcard arm.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Detail {
    /// A CVSS base score at or above the threshold.
    Cvss {
        /// The highest score found on the dependency.
        score: f64,
        /// The configured threshold.
        threshold: f64,
        /// The advisories at or above it.
        advisories: Vec<String>,
    },
    /// A severity band at or above the threshold, with no scorable vector.
    Severity {
        /// The highest band found on the dependency.
        band: Severity,
        /// The configured threshold band.
        threshold: Severity,
        /// The advisories at or above it.
        advisories: Vec<String>,
    },
    /// A dependency too many major versions behind.
    MajorBehind {
        /// How many majors behind it is.
        behind: u64,
        /// How many the policy allows.
        allowed: u64,
        /// The latest available version.
        latest: String,
    },
    /// The package is denied outright.
    Denied,
    /// The version is below a configured floor, or the floor itself is unparseable.
    MinimumVersion {
        /// The configured floor, verbatim.
        required: String,
    },
    /// Advisories carrying no rating at all, while a CVSS rule is in force.
    Unrated {
        /// How many are unrated.
        count: usize,
        /// Their IDs.
        advisories: Vec<String>,
        /// The highest score among the *rated* advisories on the same
        /// dependency, if any — context for how far off the gate might be.
        best_known: Option<f64>,
    },
}

/// One thing the policy has to say about one dependency.
///
/// `#[non_exhaustive]`: read the fields, don't construct it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Finding {
    /// Whether this fails the build.
    pub level: Level,
    /// The rule that produced it.
    pub rule: Rule,
    /// The manifest the dependency was declared in.
    pub manifest: PathBuf,
    /// The manifest's ecosystem.
    pub ecosystem: Ecosystem,
    /// The dependency's name.
    pub package: String,
    /// The version in force, where one is known.
    pub current: Option<String>,
    /// The rule-specific evidence.
    pub detail: Detail,
    /// The configured explanation, where the rule carries one.
    pub reason: Option<String>,
}

impl Finding {
    /// A single line naming the rule, the dependency, and what tripped it.
    ///
    /// The line begins with [`Rule::token`], so grepping a CI log for a config
    /// key finds every failure that key caused.
    #[must_use]
    pub fn message(&self) -> String {
        let package = match &self.current {
            Some(version) => format!("{} {version}", self.package),
            None => self.package.clone(),
        };
        let mut line = format!(
            "{:<18}{package} ({}): {}",
            self.rule.token(),
            self.manifest.display(),
            self.detail_text()
        );
        if let Some(reason) = &self.reason {
            line.push_str(" — ");
            line.push_str(reason);
        }
        line
    }

    fn detail_text(&self) -> String {
        match &self.detail {
            Detail::Cvss {
                score,
                threshold,
                advisories,
            } => format!(
                "CVSS {score:.1} >= {threshold:.1}{}",
                render_ids(advisories)
            ),
            Detail::Severity {
                band,
                threshold,
                advisories,
            } => format!(
                "severity {} >= {}, no CVSS score{}",
                band.token(),
                threshold.token(),
                render_ids(advisories)
            ),
            Detail::MajorBehind {
                behind,
                allowed,
                latest,
            } => {
                let plural = if *behind == 1 { "" } else { "s" };
                format!("{behind} major version{plural} behind {latest} (allowed {allowed})")
            }
            Detail::Denied => "denied by policy".to_string(),
            Detail::MinimumVersion { required } => match self.level {
                Level::Violation => format!("below required {required}"),
                _ => format!("`min_version = \"{required}\"` is not a valid version; rule skipped"),
            },
            Detail::Unrated {
                count, advisories, ..
            } => {
                let (noun, verb) = if *count == 1 {
                    ("advisory", "carries")
                } else {
                    ("advisories", "carry")
                };
                format!(
                    "{count} {noun} {verb} no CVSS score; `{}` is a lower bound{}",
                    self.rule.token(),
                    render_ids(advisories)
                )
            }
        }
    }
}

/// Apply `policy` to `report`.
///
/// Pure: no IO, no exit codes. Findings come back in manifest order, then
/// dependency order, then rule order, so the output is reproducible.
///
/// Rules that need data the report does not carry — a major-version distance for
/// a path dependency, say — are *skipped*, never failed: a policy must not turn a
/// missing measurement into a violation.
#[must_use]
pub fn evaluate(report: &Report, policy: &Policy) -> PolicyOutcome {
    let mut outcome = PolicyOutcome::default();

    // SCOPE §A4 D5: a number beats a word, and the override is recorded rather
    // than applied in silence.
    if let (Some(score), Some(band)) = (policy.max_cvss, policy.fail_on_severity) {
        outcome.notes.push(format!(
            "both `max_cvss` and `fail_on_severity` are set; \
             using `max_cvss = {score:.1}` and ignoring `fail_on_severity = \"{}\"`",
            band.label()
        ));
    }
    // One gate, two spellings. `Severity::min_score` is what keeps the band table
    // defined in exactly one place.
    let threshold_score = policy
        .max_cvss
        .or_else(|| policy.fail_on_severity.map(|band| band.min_score()));
    let threshold_band = policy
        .fail_on_severity
        .or_else(|| policy.max_cvss.map(Severity::from_score));
    let cvss_rule = if policy.max_cvss.is_some() {
        Rule::MaxCvss
    } else {
        Rule::FailOnSeverity
    };

    for manifest in &report.manifests {
        let ecosystem = manifest.ecosystem;
        for result in &manifest.results {
            outcome.evaluated += 1;
            let name = result.item.name.as_str();
            let current = current_version(result);
            let mut push = |level: Level, rule: Rule, detail: Detail, reason: Option<String>| {
                outcome.findings.push(Finding {
                    level,
                    rule,
                    manifest: manifest.path.clone(),
                    ecosystem,
                    package: name.to_string(),
                    current: current.clone(),
                    detail,
                    reason,
                });
            };

            // 1. Denied packages — regardless of source, version, or status.
            if policy
                .denied_packages
                .iter()
                .any(|entry| matches(entry.ecosystem, &entry.name, ecosystem, name))
            {
                push(Level::Violation, Rule::DeniedPackage, Detail::Denied, None);
            }

            // 2. Minimum versions — evaluated wherever a version is known, which
            //    includes a locked version under `DependencyStatus::Error`.
            for entry in &policy.minimum_versions {
                if !matches(entry.ecosystem, &entry.name, ecosystem, name) {
                    continue;
                }
                let Some(floor) = parse_version(&entry.min_version, ecosystem) else {
                    push(
                        Level::Warning,
                        Rule::MinimumVersion,
                        Detail::MinimumVersion {
                            required: entry.min_version.clone(),
                        },
                        None,
                    );
                    continue;
                };
                let Some(version) = current
                    .as_deref()
                    .and_then(|raw| parse_version(raw, ecosystem))
                else {
                    continue;
                };
                if version < floor {
                    push(
                        Level::Violation,
                        Rule::MinimumVersion,
                        Detail::MinimumVersion {
                            required: entry.min_version.clone(),
                        },
                        entry.reason.clone(),
                    );
                }
            }

            // 3. Major versions behind — needs both ends measurable.
            if let Some(allowed) = policy.max_major_behind
                && let Some(latest_raw) = result.latest_available.as_deref()
                && let Some(latest) = parse_version(latest_raw, ecosystem)
                && let Some(version) = current
                    .as_deref()
                    .and_then(|raw| parse_version(raw, ecosystem))
            {
                let behind = major_distance(&version, &latest);
                if behind > allowed {
                    push(
                        Level::Violation,
                        Rule::MaxMajorBehind,
                        Detail::MajorBehind {
                            behind,
                            allowed,
                            latest: latest_raw.to_string(),
                        },
                        None,
                    );
                }
            }

            // 4/5. CVSS gate, then the unrated advisories it could not see.
            if result.advisories.is_empty() {
                continue;
            }
            let Some(threshold_score) = threshold_score else {
                continue;
            };
            let mut violated = false;
            if let Some(score) = result.max_cvss()
                && score >= threshold_score
            {
                violated = true;
                push(
                    Level::Violation,
                    cvss_rule,
                    Detail::Cvss {
                        score,
                        threshold: threshold_score,
                        advisories: over_score(&result.advisories, threshold_score),
                    },
                    None,
                );
            } else if let (Some(band), Some(threshold_band)) =
                (result.max_severity(), threshold_band)
                && band >= threshold_band
            {
                // A published band with no scorable vector. Reported as a band
                // comparison so a conservative result is never read as a score.
                violated = true;
                push(
                    Level::Violation,
                    cvss_rule,
                    Detail::Severity {
                        band,
                        threshold: threshold_band,
                        advisories: over_band(&result.advisories, threshold_band),
                    },
                    None,
                );
            }

            let unrated = unrated_ids(&result.advisories);
            if violated || unrated.is_empty() {
                continue;
            }
            let level = match policy.unrated_advisories {
                UnratedPolicy::Ignore => continue,
                UnratedPolicy::Warn => Level::Warning,
                UnratedPolicy::Fail => Level::Violation,
            };
            push(
                level,
                cvss_rule,
                Detail::Unrated {
                    count: unrated.len(),
                    advisories: unrated,
                    best_known: result.max_cvss(),
                },
                None,
            );
        }
    }

    outcome
}

/// The version actually in force: the locked version, else the best version the
/// declared constraint allows.
///
/// Copied verbatim from the checker's own notion of "current", so a policy gate
/// can never disagree with the status column printed beside it.
fn current_version(result: &CheckResult) -> Option<String> {
    result
        .item
        .locked_version
        .clone()
        .or_else(|| result.latest_compatible.clone())
}

/// Parse a version string in `ecosystem`'s own spelling into a semver version.
fn parse_version(raw: &str, ecosystem: Ecosystem) -> Option<semver::Version> {
    let normalized = match ecosystem {
        Ecosystem::Python => python::pep440_to_semver(raw)?,
        Ecosystem::CSharp => nuget::nuget_to_semver(raw)?,
        _ => normalize_version(raw),
    };
    semver::Version::parse(&normalized).ok()
}

/// How many breaking releases separate `current` from `latest`.
///
/// Under `0.x` the **minor** is the breaking axis — which is how the version
/// checker already classifies compatibility — so `0.1 → 0.9` is eight breaking
/// releases behind, not zero. Counting it as zero would make the gate blind to
/// exactly the churn it exists to catch.
fn major_distance(current: &semver::Version, latest: &semver::Version) -> u64 {
    if current.major != latest.major {
        latest.major.saturating_sub(current.major)
    } else if current.major == 0 {
        latest.minor.saturating_sub(current.minor)
    } else {
        0
    }
}

/// Whether a rule entry names this package: the name ASCII case-insensitively,
/// and the ecosystem only when the entry scopes itself to one.
fn matches(
    entry_eco: Option<Ecosystem>,
    entry_name: &str,
    ecosystem: Ecosystem,
    name: &str,
) -> bool {
    entry_eco.is_none_or(|eco| eco == ecosystem) && entry_name.eq_ignore_ascii_case(name)
}

/// IDs of the advisories scoring at or above `threshold`.
fn over_score(advisories: &[Advisory], threshold: f64) -> Vec<String> {
    advisories
        .iter()
        .filter(|a| a.severity.score.is_some_and(|s| s >= threshold))
        .map(|a| a.id.clone())
        .collect()
}

/// IDs of the advisories banded at or above `threshold`.
fn over_band(advisories: &[Advisory], threshold: Severity) -> Vec<String> {
    advisories
        .iter()
        .filter(|a| a.severity.band.is_some_and(|b| b >= threshold))
        .map(|a| a.id.clone())
        .collect()
}

/// IDs of the advisories carrying no usable rating at all.
fn unrated_ids(advisories: &[Advisory]) -> Vec<String> {
    advisories
        .iter()
        .filter(|a| a.severity.is_unrated())
        .map(|a| a.id.clone())
        .collect()
}

/// ` [A, B]`, or nothing when there is nothing to name.
fn render_ids(ids: &[String]) -> String {
    if ids.is_empty() {
        String::new()
    } else {
        format!(" [{}]", ids.join(", "))
    }
}

/// Map a configured ecosystem word onto an [`Ecosystem`], case-insensitively.
///
/// The core enum spells its variants `Rust`/`CSharp`; configuration is written
/// the way the ecosystems name themselves, and each accepts the aliases people
/// actually type. An unknown word is an error rather than a guess.
fn parse_ecosystem(raw: &str) -> Option<Ecosystem> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "rust" | "cargo" | "crates.io" | "crates" => Some(Ecosystem::Rust),
        "go" | "golang" => Some(Ecosystem::Go),
        "npm" | "node" | "js" | "javascript" => Some(Ecosystem::Npm),
        "python" | "pypi" | "pip" => Some(Ecosystem::Python),
        "php" | "composer" | "packagist" => Some(Ecosystem::Php),
        "dart" | "pub" | "flutter" => Some(Ecosystem::Dart),
        "csharp" | "c#" | "dotnet" | "nuget" => Some(Ecosystem::CSharp),
        "elixir" | "hex" | "mix" => Some(Ecosystem::Elixir),
        _ => None,
    }
}

/// Deserialize [`Policy::fail_on_severity`] from a band name.
fn de_severity<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Severity>, D::Error> {
    let Some(raw) = Option::<String>::deserialize(de)? else {
        return Ok(None);
    };
    Severity::parse(&raw).map(Some).ok_or_else(|| {
        D::Error::custom(format!(
            "unknown severity `{raw}`; expected one of: {SEVERITY_TOKENS}"
        ))
    })
}

/// Serialize [`Policy::fail_on_severity`] back to its band name.
fn ser_severity<S: Serializer>(value: &Option<Severity>, ser: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(band) => ser.serialize_some(band.label()),
        None => ser.serialize_none(),
    }
}

/// `serde` glue for an optional ecosystem written the way people spell it.
mod eco_opt {
    use dependable_core::Ecosystem;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{ECOSYSTEM_TOKENS, parse_ecosystem};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Ecosystem>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            // `display_name` lower-cased, so `C#` round-trips through the alias
            // table without matching on a `#[non_exhaustive]` enum here.
            Some(eco) => ser.serialize_some(&eco.display_name().to_ascii_lowercase()),
            None => ser.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<Ecosystem>, D::Error> {
        let Some(raw) = Option::<String>::deserialize(de)? else {
            return Ok(None);
        };
        parse_ecosystem(&raw).map(Some).ok_or_else(|| {
            D::Error::custom(format!(
                "unknown ecosystem `{raw}`; expected one of: {ECOSYSTEM_TOKENS}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use dependable_core::result::{Advisory, AdvisorySeverity};
    use dependable_core::{DependencyStatus, Item, ManifestKind, parse};

    use super::*;
    use crate::model::ManifestResults;

    /// The full `[policy]` block from the product spec, without the table header
    /// so it deserializes straight into [`Policy`].
    const FULL: &str = r#"
max_cvss = 7.0
fail_on_severity = "high"
max_major_behind = 2
unrated_advisories = "warn"
denied_packages = [
  { ecosystem = "npm", name = "left-pad" },
  { name = "openssl-src" },
]

[[minimum_versions]]
ecosystem = "rust"
name = "openssl"
min_version = "0.10.64"
reason = "CVE-2023-xxxx fix"
"#;

    fn policy(toml: &str) -> Policy {
        toml_edit::de::from_str(toml).expect("a valid policy block")
    }

    fn policy_error(toml: &str) -> String {
        toml_edit::de::from_str::<Policy>(toml)
            .expect_err("an invalid policy block")
            .to_string()
    }

    /// `Item` is `#[non_exhaustive]` with no constructor, so a real one is
    /// obtained the only way another crate can: by parsing a manifest. That keeps
    /// the fixture honest — it is the same `Item` the checker emits.
    fn item(spec: &str) -> Item {
        let manifest = format!("[dependencies]\n{spec}\n");
        parse(ManifestKind::CargoToml, &manifest)
            .expect("parse the fixture manifest")
            .items
            .into_iter()
            .next()
            .expect("one dependency")
    }

    fn checked(spec: &str) -> CheckResult {
        CheckResult::new(item(spec), DependencyStatus::UpToDate)
    }

    fn locked(spec: &str, version: &str) -> CheckResult {
        let mut result = checked(spec);
        result.item.locked_version = Some(version.to_string());
        result
    }

    fn scored(id: &str, score: f64) -> Advisory {
        Advisory::new(id).with_severity(AdvisorySeverity::from_score(score))
    }

    fn banded(id: &str, label: &str) -> Advisory {
        Advisory::new(id).with_severity(AdvisorySeverity::from_label(label))
    }

    fn rust(results: Vec<CheckResult>) -> Report {
        manifest(Ecosystem::Rust, "Cargo.toml", results)
    }

    fn manifest(ecosystem: Ecosystem, path: &str, results: Vec<CheckResult>) -> Report {
        let mut report = Report::new(PathBuf::from("/proj"));
        report.push(ManifestResults::new(
            PathBuf::from(path),
            ecosystem,
            results,
        ));
        report
    }

    fn messages(outcome: &PolicyOutcome) -> Vec<String> {
        outcome.findings.iter().map(Finding::message).collect()
    }

    // --- schema -----------------------------------------------------------

    #[test]
    fn a_full_policy_block_round_trips() {
        let parsed = policy(FULL);

        assert_eq!(parsed.max_cvss, Some(7.0));
        assert_eq!(parsed.fail_on_severity, Some(Severity::High));
        assert_eq!(parsed.max_major_behind, Some(2));
        assert_eq!(parsed.unrated_advisories, UnratedPolicy::Warn);
        assert_eq!(
            parsed.denied_packages,
            vec![
                PackageRef::new("left-pad").in_ecosystem(Ecosystem::Npm),
                PackageRef::new("openssl-src"),
            ]
        );
        assert_eq!(
            parsed.minimum_versions,
            vec![
                MinimumVersion::new("openssl", "0.10.64")
                    .in_ecosystem(Ecosystem::Rust)
                    .because("CVE-2023-xxxx fix"),
            ]
        );

        // Serializing and re-reading must land on the same policy, or a config
        // written back out would quietly mean something else.
        let rendered = toml_edit::ser::to_string(&parsed).expect("serialize the policy");
        assert_eq!(policy(&rendered), parsed);
    }

    #[test]
    fn a_mistyped_key_is_an_error_not_a_disabled_gate() {
        // The whole point: `max_cvvs` must never be read as "no CVSS rule".
        let error = policy_error("max_cvvs = 7.0\n");
        assert!(error.contains("max_cvvs"), "{error}");
    }

    #[test]
    fn an_unknown_nested_key_is_also_an_error() {
        let error = policy_error("denied_packages = [{ name = \"x\", nope = 1 }]\n");
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    fn the_github_moderate_alias_is_medium() {
        assert_eq!(
            policy("fail_on_severity = \"MODERATE\"\n").fail_on_severity,
            Some(Severity::Medium)
        );
    }

    #[test]
    fn an_unknown_severity_names_the_accepted_values() {
        let error = policy_error("fail_on_severity = \"nope\"\n");
        assert!(error.contains("nope"), "{error}");
        for band in ["none", "low", "medium", "high", "critical"] {
            assert!(error.contains(band), "expected `{band}` in: {error}");
        }
    }

    #[test]
    fn ecosystem_words_resolve_the_way_people_spell_them() {
        let cases = [
            ("npm", Ecosystem::Npm),
            ("CRATES.IO", Ecosystem::Rust),
            ("c#", Ecosystem::CSharp),
            ("golang", Ecosystem::Go),
            ("pypi", Ecosystem::Python),
            ("packagist", Ecosystem::Php),
            ("flutter", Ecosystem::Dart),
            ("mix", Ecosystem::Elixir),
        ];
        for (word, expected) in cases {
            let parsed = policy(&format!(
                "denied_packages = [{{ ecosystem = \"{word}\", name = \"x\" }}]\n"
            ));
            assert_eq!(
                parsed.denied_packages[0].ecosystem,
                Some(expected),
                "{word}"
            );
        }
    }

    #[test]
    fn csharp_round_trips_through_the_alias_table() {
        // `display_name()` is "C#", which is only a valid config word because the
        // alias table accepts it back.
        let parsed = policy("denied_packages = [{ ecosystem = \"csharp\", name = \"x\" }]\n");
        let rendered = toml_edit::ser::to_string(&parsed).expect("serialize");
        assert!(rendered.contains("c#"), "{rendered}");
        assert_eq!(policy(&rendered), parsed);
    }

    #[test]
    fn an_unknown_ecosystem_names_the_accepted_values() {
        let error = policy_error("denied_packages = [{ ecosystem = \"cobol\", name = \"x\" }]\n");
        assert!(error.contains("cobol"), "{error}");
        assert!(error.contains("crates.io"), "{error}");
    }

    #[test]
    fn the_default_policy_is_empty_and_gates_nothing() {
        let default = Policy::default();
        assert!(!default.is_active());
        assert!(!default.requires_cvss());
        // An all-skipped policy must serialize to nothing, so embedding it in the
        // CLI's serialized defaults contributes no keys for `deny_unknown_fields`
        // to trip over.
        let rendered = toml_edit::ser::to_string(&default).expect("serialize");
        assert!(rendered.trim().is_empty(), "{rendered:?}");

        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![scored("RUSTSEC-2020-0071", 9.8)];
        let outcome = evaluate(&rust(vec![result]), &default);
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.evaluated, 1);
    }

    #[test]
    fn a_cvss_rule_is_what_requires_scanning() {
        assert!(policy("max_cvss = 7.0\n").requires_cvss());
        assert!(policy("fail_on_severity = \"high\"\n").requires_cvss());
        assert!(!policy("max_major_behind = 1\n").requires_cvss());
        assert!(policy("max_major_behind = 1\n").is_active());
    }

    // --- D5: a number beats a word ---------------------------------------

    #[test]
    fn a_numeric_threshold_beats_a_named_band_and_the_override_is_recorded() {
        let mut result = locked("serde = \"1\"", "1.0.0");
        result.advisories = vec![scored("RUSTSEC-2024-0001", 8.0)];
        let policy = policy("max_cvss = 7.0\nfail_on_severity = \"critical\"\n");

        let outcome = evaluate(&rust(vec![result]), &policy);

        // `critical` alone would have let 8.0 through; the number won.
        assert_eq!(outcome.violation_count(), 1);
        assert_eq!(outcome.findings[0].rule, Rule::MaxCvss);
        assert_eq!(outcome.notes.len(), 1);
        assert!(
            outcome.notes[0].contains("max_cvss = 7.0"),
            "{:?}",
            outcome.notes
        );
        assert!(
            outcome.notes[0].contains("fail_on_severity"),
            "{:?}",
            outcome.notes
        );
    }

    #[test]
    fn a_named_band_reuses_the_shared_band_table() {
        // `high` must mean exactly `Severity::High.min_score()` — 7.0 — with no
        // second copy of the band boundaries living here.
        let policy = policy("fail_on_severity = \"high\"\n");
        let at = {
            let mut r = locked("a = \"1\"", "1.0.0");
            r.advisories = vec![scored("A", 7.0)];
            r
        };
        let below = {
            let mut r = locked("b = \"1\"", "1.0.0");
            r.advisories = vec![scored("B", 6.9)];
            r
        };

        let outcome = evaluate(&rust(vec![at, below]), &policy);

        assert_eq!(outcome.violation_count(), 1);
        assert_eq!(outcome.findings[0].package, "a");
        assert_eq!(outcome.findings[0].rule, Rule::FailOnSeverity);
        assert!(outcome.notes.is_empty());
    }

    // --- CVSS ------------------------------------------------------------

    #[test]
    fn the_highest_score_across_advisories_is_the_one_compared() {
        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![scored("LOW", 3.1), scored("HIGH", 9.8), scored("MID", 5.0)];

        let outcome = evaluate(&rust(vec![result]), &policy("max_cvss = 7.0\n"));

        assert_eq!(outcome.violation_count(), 1);
        let Detail::Cvss {
            score, advisories, ..
        } = &outcome.findings[0].detail
        else {
            panic!(
                "expected a CVSS detail, got {:?}",
                outcome.findings[0].detail
            );
        };
        assert_eq!(*score, 9.8);
        assert_eq!(advisories, &["HIGH".to_string()]);
        assert_eq!(
            messages(&outcome)[0],
            "max_cvss          time 0.2.7 (Cargo.toml): CVSS 9.8 >= 7.0 [HIGH]"
        );
    }

    #[test]
    fn a_score_below_the_threshold_passes() {
        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![scored("A", 6.9)];

        let outcome = evaluate(&rust(vec![result]), &policy("max_cvss = 7.0\n"));

        assert!(!outcome.has_violations(), "{:?}", messages(&outcome));
    }

    #[test]
    fn a_band_only_advisory_trips_the_band_comparison_and_says_so() {
        // A published band with no scorable vector must not slip past a numeric
        // gate — and the message must not read as though a score was compared.
        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![banded("RUSTSEC-2020-0071", "high")];

        let outcome = evaluate(&rust(vec![result]), &policy("max_cvss = 7.0\n"));

        assert_eq!(outcome.violation_count(), 1);
        assert!(matches!(
            outcome.findings[0].detail,
            Detail::Severity {
                band: Severity::High,
                threshold: Severity::High,
                ..
            }
        ));
        assert_eq!(
            messages(&outcome)[0],
            "max_cvss          time 0.2.7 (Cargo.toml): severity HIGH >= HIGH, \
             no CVSS score [RUSTSEC-2020-0071]"
        );
    }

    // --- unrated advisories ----------------------------------------------

    #[test]
    fn unrated_advisories_warn_by_default_rather_than_passing_silently() {
        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![Advisory::new("RUSTSEC-2020-0071")];

        let outcome = evaluate(&rust(vec![result]), &policy("max_cvss = 7.0\n"));

        assert!(!outcome.has_violations());
        assert_eq!(outcome.warnings().count(), 1);
        assert_eq!(outcome.findings[0].level, Level::Warning);
        assert!(
            messages(&outcome)[0].contains("no CVSS score"),
            "{:?}",
            messages(&outcome)
        );
    }

    #[test]
    fn unrated_advisories_can_be_ignored_or_failed() {
        let build = || {
            let mut result = locked("time = \"0.2\"", "0.2.7");
            result.advisories = vec![Advisory::new("X")];
            rust(vec![result])
        };

        let ignored = evaluate(
            &build(),
            &policy("max_cvss = 7.0\nunrated_advisories = \"ignore\"\n"),
        );
        assert!(ignored.findings.is_empty());

        let failed = evaluate(
            &build(),
            &policy("max_cvss = 7.0\nunrated_advisories = \"fail\"\n"),
        );
        assert_eq!(failed.violation_count(), 1);
    }

    #[test]
    fn a_package_that_already_violates_is_not_also_reported_as_unrated() {
        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![scored("SCORED", 9.8), Advisory::new("UNRATED")];

        let outcome = evaluate(&rust(vec![result]), &policy("max_cvss = 7.0\n"));

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].level, Level::Violation);
    }

    #[test]
    fn unrated_advisories_are_silent_when_no_cvss_rule_is_set() {
        let mut result = locked("time = \"0.2\"", "0.2.7");
        result.advisories = vec![Advisory::new("X")];

        let outcome = evaluate(&rust(vec![result]), &policy("max_major_behind = 5\n"));

        assert!(outcome.findings.is_empty());
    }

    // --- max_major_behind -------------------------------------------------

    #[test]
    fn major_distance_counts_breaking_releases_including_under_zero_dot_x() {
        let cases = [
            ("1.0.0", "3.0.0", 2),
            // Under 0.x the minor is the breaking axis: eight breaking releases,
            // not zero.
            ("0.1.0", "0.9.0", 8),
            ("0.9.0", "1.0.0", 1),
            ("2.0.0", "2.9.9", 0),
            ("4.0.0", "1.0.0", 0),
        ];
        for (current, latest, expected) in cases {
            let mut result = locked("clap = \"*\"", current);
            result.latest_available = Some(latest.to_string());
            let outcome = evaluate(&rust(vec![result]), &policy("max_major_behind = 0\n"));
            let behind = match outcome.findings.first().map(|f| &f.detail) {
                Some(Detail::MajorBehind { behind, .. }) => *behind,
                _ => 0,
            };
            assert_eq!(behind, expected, "{current} -> {latest}");
        }
    }

    #[test]
    fn the_allowance_is_inclusive() {
        let build = |allowed: u64| {
            let mut result = locked("clap = \"*\"", "2.34.0");
            result.latest_available = Some("4.5.4".to_string());
            let policy = policy(&format!("max_major_behind = {allowed}\n"));
            evaluate(&rust(vec![result]), &policy)
        };

        assert!(!build(2).has_violations(), "distance == allowed passes");
        let failed = build(1);
        assert_eq!(failed.violation_count(), 1);
        assert_eq!(
            messages(&failed)[0],
            "max_major_behind  clap 2.34.0 (Cargo.toml): 2 major versions behind 4.5.4 (allowed 1)"
        );
    }

    #[test]
    fn an_unmeasurable_dependency_is_skipped_not_failed() {
        // No `latest_available` (a path or git dependency, or a failed fetch) and
        // an unparseable version must both be silent: a missing measurement is
        // not a violation.
        let local = CheckResult::new(item("lp = { path = \"../lp\" }"), DependencyStatus::Local);
        let mut errored = CheckResult::new(
            item("broken = \"1\""),
            DependencyStatus::Error("boom".to_string()),
        );
        errored.latest_available = Some("4.0.0".to_string());
        let mut nonsense = locked("weird = \"*\"", "not-a-version");
        nonsense.latest_available = Some("4.0.0".to_string());

        let outcome = evaluate(
            &rust(vec![local, errored, nonsense]),
            &policy("max_major_behind = 0\n"),
        );

        assert!(outcome.findings.is_empty(), "{:?}", messages(&outcome));
        assert_eq!(outcome.evaluated, 3);
    }

    // --- denied_packages --------------------------------------------------

    #[test]
    fn denied_packages_match_by_name_case_insensitively() {
        let outcome = evaluate(
            &rust(vec![locked("Left-Pad = \"1\"", "1.0.0")]),
            &policy("denied_packages = [{ name = \"left-pad\" }]\n"),
        );

        assert_eq!(outcome.violation_count(), 1);
        assert_eq!(outcome.findings[0].rule, Rule::DeniedPackage);
        assert_eq!(
            messages(&outcome)[0],
            "denied_packages   Left-Pad 1.0.0 (Cargo.toml): denied by policy"
        );
    }

    #[test]
    fn an_ecosystem_scoped_deny_only_matches_that_ecosystem() {
        let entry = "denied_packages = [{ ecosystem = \"npm\", name = \"left-pad\" }]\n";

        let rust_run = evaluate(&rust(vec![checked("left-pad = \"1\"")]), &policy(entry));
        assert!(!rust_run.has_violations());

        let npm_run = evaluate(
            &manifest(
                Ecosystem::Npm,
                "package.json",
                vec![checked("left-pad = \"1\"")],
            ),
            &policy(entry),
        );
        assert_eq!(npm_run.violation_count(), 1);
        assert_eq!(
            messages(&npm_run)[0],
            "denied_packages   left-pad (package.json): denied by policy"
        );
    }

    #[test]
    fn a_path_dependency_is_still_denied() {
        // "Denied" means denied whatever the source — a vendored copy is exactly
        // how a banned package sneaks back in.
        let local = CheckResult::new(
            item("left-pad = { path = \"../left-pad\" }"),
            DependencyStatus::Local,
        );

        let outcome = evaluate(
            &rust(vec![local]),
            &policy("denied_packages = [{ name = \"left-pad\" }]\n"),
        );

        assert_eq!(outcome.violation_count(), 1);
    }

    // --- minimum_versions -------------------------------------------------

    #[test]
    fn a_version_below_the_floor_violates_and_the_reason_is_echoed() {
        let outcome = evaluate(
            &rust(vec![locked("openssl = \"0.10\"", "0.10.60")]),
            &policy(
                "[[minimum_versions]]\nname = \"openssl\"\nmin_version = \"0.10.64\"\n\
                 reason = \"CVE-2023-xxxx fix\"\n",
            ),
        );

        assert_eq!(outcome.violation_count(), 1);
        assert_eq!(
            messages(&outcome)[0],
            "minimum_versions  openssl 0.10.60 (Cargo.toml): below required 0.10.64 \
             — CVE-2023-xxxx fix"
        );
    }

    #[test]
    fn a_version_at_or_above_the_floor_passes() {
        let floor = "[[minimum_versions]]\nname = \"openssl\"\nmin_version = \"0.10.64\"\n";
        for version in ["0.10.64", "0.10.65", "0.11.0"] {
            let outcome = evaluate(
                &rust(vec![locked("openssl = \"0.10\"", version)]),
                &policy(floor),
            );
            assert!(!outcome.has_violations(), "{version}");
        }
    }

    #[test]
    fn the_locked_version_is_what_the_floor_is_measured_against() {
        // The locked version is what is actually built, so it — not the best the
        // constraint would allow — is what the gate must judge.
        let mut result = locked("openssl = \"0.10\"", "0.10.60");
        result.latest_compatible = Some("0.10.70".to_string());

        let outcome = evaluate(
            &rust(vec![result]),
            &policy("[[minimum_versions]]\nname = \"openssl\"\nmin_version = \"0.10.64\"\n"),
        );

        assert_eq!(outcome.violation_count(), 1);
    }

    #[test]
    fn a_floor_still_applies_when_the_registry_lookup_failed() {
        // A lockfile version is known even when the fetch errored, so the gate is
        // still enforceable — and a network blip must not disable it.
        let mut result = CheckResult::new(
            item("openssl = \"0.10\""),
            DependencyStatus::Error("offline".to_string()),
        );
        result.item.locked_version = Some("0.10.60".to_string());

        let outcome = evaluate(
            &rust(vec![result]),
            &policy("[[minimum_versions]]\nname = \"openssl\"\nmin_version = \"0.10.64\"\n"),
        );

        assert_eq!(outcome.violation_count(), 1);
    }

    #[test]
    fn an_unparseable_floor_warns_rather_than_failing_or_panicking() {
        let outcome = evaluate(
            &rust(vec![locked("openssl = \"0.10\"", "0.10.60")]),
            &policy("[[minimum_versions]]\nname = \"openssl\"\nmin_version = \"latest\"\n"),
        );

        assert!(!outcome.has_violations());
        assert_eq!(outcome.warnings().count(), 1);
        assert!(
            messages(&outcome)[0].contains("is not a valid version"),
            "{:?}",
            messages(&outcome)
        );
    }

    // --- shape ------------------------------------------------------------

    #[test]
    fn findings_follow_manifest_then_dependency_then_rule_order() {
        let mut report = Report::new(PathBuf::from("/proj"));
        report.push(ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            vec![
                locked("aaa = \"1\"", "1.0.0"),
                locked("bbb = \"1\"", "1.0.0"),
            ],
        ));
        report.push(ManifestResults::new(
            PathBuf::from("api/Cargo.toml"),
            Ecosystem::Rust,
            vec![locked("ccc = \"1\"", "1.0.0")],
        ));
        let policy = policy(
            "denied_packages = [{ name = \"aaa\" }, { name = \"bbb\" }, { name = \"ccc\" }]\n\
             [[minimum_versions]]\nname = \"aaa\"\nmin_version = \"2.0.0\"\n",
        );

        let outcome = evaluate(&report, &policy);

        let ordered: Vec<_> = outcome
            .findings
            .iter()
            .map(|f| (f.package.as_str(), f.rule))
            .collect();
        assert_eq!(
            ordered,
            [
                ("aaa", Rule::DeniedPackage),
                ("aaa", Rule::MinimumVersion),
                ("bbb", Rule::DeniedPackage),
                ("ccc", Rule::DeniedPackage),
            ]
        );
        assert_eq!(outcome.evaluated, 3);
        assert_eq!(outcome.violation_count(), 4);
        assert_eq!(outcome.warnings().count(), 0);
    }

    #[test]
    fn every_rule_token_is_the_config_key_that_spells_it() {
        // A new rule cannot ship without a token that names a real config key —
        // the token is what makes a red build actionable.
        let keys = [
            (Rule::MaxCvss, "max_cvss"),
            (Rule::FailOnSeverity, "fail_on_severity"),
            (Rule::MaxMajorBehind, "max_major_behind"),
            (Rule::DeniedPackage, "denied_packages"),
            (Rule::MinimumVersion, "minimum_versions"),
        ];
        for (rule, key) in keys {
            assert_eq!(rule.token(), key);
            assert!(
                FULL.contains(&format!("{key} =")) || FULL.contains(&format!("[[{key}]]")),
                "`{key}` is not a key of the documented policy block"
            );
        }
    }
}
