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
        println!(
            "{} — {identity}{}{role} ({} dependencies)",
            report.relative.display(),
            report.ecosystem.display_name(),
            report.items.len()
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
                    inherited: report.inherited.contains(&item.name),
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
    /// Whether the constraint came from the workspace root rather than this manifest.
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
