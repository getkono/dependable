//! JSON output (PRD §5.8 shape).

use dependable_fetch::PackageSource;
use serde::Serialize;

use super::{ManifestReport, Summary, current_display};

#[derive(Serialize)]
struct Output<'a> {
    summary: SummaryDto,
    results: Vec<ResultDto<'a>>,
}

/// The `summary` object of the `check --format json` document.
///
/// `manifests` and `unique_packages` are additive: every other key keeps its
/// name, its type, and its per-declaration meaning, so a consumer pinned to the
/// documented shape is unaffected.
#[derive(Serialize)]
struct SummaryDto {
    manifests: usize,
    unique_packages: usize,
    total: usize,
    up_to_date: usize,
    patch_available: usize,
    update_available: usize,
    outdated: usize,
    vulnerable: usize,
    error: usize,
}

#[derive(Serialize)]
struct ResultDto<'a> {
    name: &'a str,
    ecosystem: &'static str,
    manifest: String,
    current: String,
    latest_compatible: Option<&'a str>,
    latest_available: Option<&'a str>,
    status: &'static str,
    kind: &'static str,
    vulnerabilities: &'a [String],
    locked_at: Option<&'a str>,
    /// The manifest that declared this constraint, when it was not `manifest` itself —
    /// a Cargo `dep.workspace = true` resolved against the workspace root. Absent
    /// otherwise, so a consumer pinned to the documented shape is unaffected, and absent
    /// in particular when the root declared nothing: naming a manifest as the source of a
    /// constraint it never supplied would be worse than saying nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    inherited_from: Option<String>,
}

/// Serialize all reports as a single pretty JSON document to stdout.
///
/// # Errors
/// Returns an error if serialization fails.
pub fn render(reports: &[ManifestReport]) -> anyhow::Result<()> {
    let summary = Summary::of(reports);
    let mut results = Vec::new();
    for report in reports {
        let manifest = report.path.display().to_string();
        let workspace_root = report
            .workspace_root
            .as_ref()
            .map(|root| root.display().to_string());
        for result in &report.results {
            results.push(ResultDto {
                name: &result.item.name,
                ecosystem: report.ecosystem.display_name(),
                manifest: manifest.clone(),
                current: current_display(result),
                latest_compatible: result.latest_compatible.as_deref(),
                latest_available: result.latest_available.as_deref(),
                status: result.status.token(),
                kind: result.item.kind.token(),
                vulnerabilities: &result.current_vulnerabilities,
                locked_at: result.item.locked_version.as_deref(),
                inherited_from: (result.item.source == PackageSource::Inherited
                    && !result.item.version_constraint.is_empty())
                .then(|| workspace_root.clone())
                .flatten(),
            });
        }
    }

    let output = Output {
        summary: SummaryDto {
            manifests: summary.manifests,
            unique_packages: summary.unique_packages,
            total: summary.total,
            up_to_date: summary.up_to_date,
            patch_available: summary.patch_available,
            update_available: summary.update_available,
            outdated: summary.outdated,
            vulnerable: summary.vulnerable,
            error: summary.error,
        },
        results,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
