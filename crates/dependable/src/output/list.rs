//! Output for `dependable list`: the repository's projects and what each declares.
//!
//! `check` reports one flat stream of dependency *results*; `list` reports the
//! *inventory* — every manifest that was discovered, what it calls itself, and what it
//! declares — which is why the two do not share a renderer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dependable_fetch::core::ProjectRole;
use dependable_fetch::{DependencyKind, Ecosystem, Item, PackageSource};
use serde::Serialize;

use crate::cli::Format;
use crate::output::posix;

/// The identifier of the JSON document's shape. Consumers can pin on it; any
/// incompatible change to the shape takes a new version.
///
/// The *shape*, and specifically what a consumer may rely on remaining true:
/// removing a field, renaming one, or changing one's type takes a new version.
/// *Adding* a field does not — a consumer that reads the fields it knows is
/// unaffected by a key it never looks at, and a version bump would break every
/// consumer pinning `v1` in order to protect none of them. The token sets inside
/// those fields are likewise open and always have been: `source` already falls back
/// to `"unknown"` for a variant this function does not name, so a consumer that
/// matched exhaustively on them was never safe. Adding a token (`"locked"`) or a
/// field (`dependencies_unread`) therefore stays within `v1`.
/// The README states the same policy for readers who never open this file.
const SCHEMA: &str = "dependable.list/v1";

/// One discovered manifest: its identity and the dependencies it declares.
pub struct ProjectReport {
    /// The manifest path relative to the scanned root, for display and output.
    pub relative: PathBuf,
    /// The ecosystem the manifest belongs to.
    pub ecosystem: Ecosystem,
    /// The declared package name, or `None` for a manifest that declares none.
    pub name: Option<String>,
    /// The declared version, with any workspace inheritance already resolved.
    pub version: Option<String>,
    /// Whether [`version`](Self::version) came from a workspace root rather than the
    /// manifest itself.
    pub version_inherited: bool,
    /// Whether this is a package, a central-version manifest, or an unnamed list.
    pub role: ProjectRole,
    /// The lockfile that supplied locked versions, relative to the scanned root.
    pub lockfile: Option<PathBuf>,
    /// Whether the file that *is* this project's dependency list went unread, so
    /// [`Self::items`] being empty says nothing about the project.
    ///
    /// The same fact [`crate::output::ManifestReport::dependencies_unread`] carries
    /// for `check`, and set from the same notices: only a SwiftPM project can set
    /// it, because a `Package.swift` is a program this tool declines to read, so
    /// with no readable `Package.resolved` beside it there is no dependency list at
    /// all. A `Package.resolved` that parses to zero pins leaves this `false` — that
    /// project really does declare nothing.
    pub dependencies_unread: bool,
    /// Dependencies whose constraint was inherited from a workspace root.
    pub inherited: Vec<String>,
    /// The declared dependencies, in manifest order.
    pub items: Vec<Item>,
    /// Available feature flags per dependency, when `--features` was passed.
    pub features: BTreeMap<String, Vec<String>>,
    /// The registry-declared license per dependency, when `--licenses` was
    /// passed. An absent key is "not published to us", never "unlicensed".
    pub licenses: BTreeMap<String, String>,
}

impl ProjectReport {
    /// The manifest's display name: its declared name, else its file name.
    fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.relative.file_name().map_or_else(
                || self.relative.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            )
        })
    }
}

/// Render `reports` in the requested `format`.
///
/// # Errors
/// Propagates serialization / IO errors from the chosen renderer.
pub fn render(format: Format, reports: &[ProjectReport], root: &Path) -> anyhow::Result<()> {
    match format {
        Format::Table => {
            table(reports);
            Ok(())
        }
        Format::Json => json(reports, root),
        Format::Text => {
            text(reports);
            Ok(())
        }
    }
}

/// Human-readable output: a header per project, then one line per dependency.
fn table(reports: &[ProjectReport]) {
    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let identity = match (&report.name, &report.version) {
            (Some(name), Some(version)) => format!("{name} v{version} — "),
            (Some(name), None) => format!("{name} — "),
            (None, _) => String::new(),
        };
        let role = match report.role {
            ProjectRole::Workspace => " [workspace]",
            _ => "",
        };
        // A count is a claim about the project. Where the file that *is* the
        // dependency list went unread there was nothing to count, so the heading
        // says that instead — in the same words `check` and the HTML report use, so
        // a reader comparing the three sees one phrase and not three. The
        // `is_empty` conjunct is load-bearing: a partially-read list still gets
        // counted rather than disclaimed.
        let scope = if report.items.is_empty() && report.dependencies_unread {
            "dependency list unread".to_owned()
        } else {
            format!("{} dependencies", report.items.len())
        };
        println!(
            "{} — {identity}{}{role} ({scope})",
            report.relative.display(),
            report.ecosystem.display_name(),
        );
        for item in &report.items {
            let constraint = if item.version_constraint.is_empty() {
                "—"
            } else {
                &item.version_constraint
            };
            println!(
                "  {} {}{}{}{}",
                item.name,
                constraint,
                locked_note(item),
                annotation(item),
                license_note(report, item)
            );
            if let Some(features) = report.features.get(&item.name)
                && !features.is_empty()
            {
                println!("      features: {}", features.join(", "));
            }
        }
    }
}

/// Machine-readable line output: one tab-separated record per dependency.
fn text(reports: &[ProjectReport]) {
    for report in reports {
        let label = report.label();
        let manifest = posix(&report.relative);
        for item in &report.items {
            // The license is emitted unconditionally, so every record keeps the
            // same arity whether or not `--licenses` was passed.
            println!(
                "{label}\t{}\t{manifest}\t{}\t{}\t{}\t{}\t{}\t{}",
                report.ecosystem.display_name(),
                item.name,
                blank_as_dash(&item.version_constraint),
                item.kind.token(),
                source_token(item.source),
                item.locked_version.as_deref().unwrap_or("—"),
                report.licenses.get(&item.name).map_or("—", String::as_str),
            );
        }
    }
}

/// The inventory as a single JSON document.
fn json(reports: &[ProjectReport], root: &Path) -> anyhow::Result<()> {
    let mut by_ecosystem: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut dependencies = 0;
    for report in reports {
        *by_ecosystem
            .entry(report.ecosystem.display_name())
            .or_default() += 1;
        dependencies += report.items.len();
    }

    let projects = reports
        .iter()
        .map(|report| ProjectDto {
            name: report.name.as_deref(),
            version: report.version.as_deref(),
            version_inherited: report.version_inherited,
            ecosystem: report.ecosystem.display_name(),
            role: role_token(report.role),
            manifest: posix(&report.relative),
            lockfile: report.lockfile.as_deref().map(posix),
            dependencies_unread: report.dependencies_unread,
            dependencies: report
                .items
                .iter()
                .map(|item| DependencyDto {
                    name: &item.name,
                    constraint: (!item.version_constraint.is_empty())
                        .then_some(item.version_constraint.as_str()),
                    kind: item.kind.token(),
                    direct: item.kind.is_direct(),
                    source: source_token(item.source),
                    locked: item.locked_version.as_deref(),
                    registry: item.registry.as_deref(),
                    inherited: item.source == PackageSource::Inherited
                        || report.inherited.contains(&item.name),
                    features: report.features.get(&item.name).map(Vec::as_slice),
                    license: report.licenses.get(&item.name).map(String::as_str),
                })
                .collect(),
        })
        .collect();

    let output = Output {
        schema: SCHEMA,
        root: posix(root),
        summary: SummaryDto {
            projects: reports.len(),
            dependencies,
            by_ecosystem,
        },
        projects,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[derive(Serialize)]
struct Output<'a> {
    schema: &'static str,
    root: String,
    summary: SummaryDto,
    projects: Vec<ProjectDto<'a>>,
}

#[derive(Serialize)]
struct SummaryDto {
    projects: usize,
    dependencies: usize,
    by_ecosystem: BTreeMap<&'static str, usize>,
}

#[derive(Serialize)]
struct ProjectDto<'a> {
    name: Option<&'a str>,
    version: Option<&'a str>,
    version_inherited: bool,
    ecosystem: &'static str,
    role: &'static str,
    manifest: String,
    lockfile: Option<String>,
    /// Whether the file that *is* this project's dependency list went unread, so an
    /// empty `dependencies` says nothing about the project. Always emitted — the
    /// answer is always known — and `false` for every ecosystem but SwiftPM.
    ///
    /// `lockfile: null` is not a substitute: `--no-lock-file` produces that too, and
    /// a `Package.resolved` that parses to zero pins leaves this `false` because the
    /// project really does declare nothing. Additive, so the schema is unchanged.
    dependencies_unread: bool,
    dependencies: Vec<DependencyDto<'a>>,
}

#[derive(Serialize)]
struct DependencyDto<'a> {
    name: &'a str,
    constraint: Option<&'a str>,
    kind: &'static str,
    /// Whether the package itself depends on this — false for a central declaration or
    /// a recorded transitive requirement.
    direct: bool,
    source: &'static str,
    locked: Option<&'a str>,
    registry: Option<&'a str>,
    /// Whether this dependency's version is declared somewhere other than its own
    /// entry *but still in a manifest*: a Cargo `workspace = true` resolved against
    /// the root, a Gradle `[versions]` alias, a shared Maven `<properties>` value.
    ///
    /// True for every entry whose `source` is `inherited`, so the two fields can no
    /// longer contradict each other on the same object. Also true where the root's
    /// declaration supplied a `path` or `git` source, which replaces `source`
    /// outright and would otherwise lose the fact that it was inherited at all.
    ///
    /// False for `"source": "locked"`, and deliberately: a lockfile pin was not
    /// inherited from anything, because nothing declared it. The point of the field
    /// is to send a consumer to the file where the version can be bumped, and for a
    /// locked entry there is no such file.
    inherited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    features: Option<&'a [String]>,
    /// The registry-declared license, when `--licenses` was passed and the
    /// registry published one. Additive and optional, so the schema is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<&'a str>,
}

/// ` [MIT OR Apache-2.0]` in table output, or nothing when no license is known.
fn license_note(report: &ProjectReport, item: &Item) -> String {
    match report.licenses.get(&item.name) {
        Some(license) => format!(" [{license}]"),
        None => String::new(),
    }
}

/// A stable token for a project's role.
fn role_token(role: ProjectRole) -> &'static str {
    match role {
        ProjectRole::Package => "package",
        ProjectRole::Workspace => "workspace",
        _ => "unnamed",
    }
}

/// A stable token for where a dependency comes from.
fn source_token(source: PackageSource) -> &'static str {
    match source {
        PackageSource::Registry => "registry",
        PackageSource::Jsr => "jsr",
        PackageSource::Local => "local",
        PackageSource::Git => "git",
        PackageSource::Inherited => "inherited",
        PackageSource::Locked => "locked",
        _ => "unknown",
    }
}

fn blank_as_dash(value: &str) -> &str {
    if value.is_empty() { "—" } else { value }
}

/// ` (locked 1.2.3)` when a lockfile pinned a different version than the constraint.
fn locked_note(item: &Item) -> String {
    match &item.locked_version {
        Some(locked) if *locked != item.version_constraint => format!(" (locked {locked})"),
        _ => String::new(),
    }
}

/// The trailing annotation in table output: a non-registry source, or a section that
/// means the manifest does not itself depend on the package.
fn annotation(item: &Item) -> &'static str {
    match item.source {
        PackageSource::Local => " (local)",
        PackageSource::Git => " (git)",
        PackageSource::Jsr => " (jsr)",
        // An inherited entry that never found its declaration states no version, and
        // would otherwise render as a bare `—` that reads like a parse failure. A
        // resolved one falls through to its section, so a `dev` dep still says so.
        PackageSource::Inherited if item.version_constraint.is_empty() => " (unresolved)",
        // `Locked` deliberately has no arm. A lockfile pin states a version, so it is
        // not unresolved, and it is not a source a reader of a table needs told about
        // — what a reader wants to know is that it is not a declared direct
        // dependency, which is exactly what its `kind` says below.
        _ => match item.kind {
            DependencyKind::Dev => " (dev)",
            DependencyKind::Build => " (build)",
            DependencyKind::Optional => " (optional)",
            DependencyKind::Peer => " (peer)",
            DependencyKind::Workspace => " (declared)",
            DependencyKind::Indirect => " (indirect)",
            _ => "",
        },
    }
}
