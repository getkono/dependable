//! Machine-readable text output: one line per dependency.

use super::{ManifestReport, current_display, latest_display};

/// Render each dependency as `STATUS name current latest manifest [ids]`.
///
/// # Errors
/// Never fails; returns `Result` to match the renderer signature.
pub fn render(reports: &[ManifestReport]) -> anyhow::Result<()> {
    for report in reports {
        let manifest = report.path.display().to_string();
        for result in &report.results {
            let ids = if result.current_vulnerabilities.is_empty() {
                String::new()
            } else {
                format!("  [{}]", result.current_vulnerabilities.join(","))
            };
            println!(
                "{:<8} {} {} {} {}{}",
                result.status.token(),
                result.item.name,
                current_display(result),
                latest_display(result),
                manifest,
                ids
            );
        }
    }
    Ok(())
}
