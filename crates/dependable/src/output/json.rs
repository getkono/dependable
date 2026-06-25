//! JSON output (PRD §5.8 shape).

use serde::Serialize;

use super::{ManifestReport, Summary, current_display};

#[derive(Serialize)]
struct Output<'a> {
    summary: SummaryDto,
    results: Vec<ResultDto<'a>>,
}

#[derive(Serialize)]
struct SummaryDto {
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
    vulnerabilities: &'a [String],
    locked_at: Option<&'a str>,
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
        for result in &report.results {
            results.push(ResultDto {
                name: &result.item.name,
                ecosystem: report.ecosystem.display_name(),
                manifest: manifest.clone(),
                current: current_display(result),
                latest_compatible: result.latest_compatible.as_deref(),
                latest_available: result.latest_available.as_deref(),
                status: result.status.token(),
                vulnerabilities: &result.current_vulnerabilities,
                locked_at: result.item.locked_version.as_deref(),
            });
        }
    }

    let output = Output {
        summary: SummaryDto {
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
