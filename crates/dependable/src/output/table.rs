//! Colored, TTY-aware table output (the default).

use dependable_fetch::{CheckResult, DependencyStatus};
use owo_colors::{OwoColorize, Stream, Style};

use super::{ManifestReport, Summary, current_display, latest_display};

/// Render all reports as tables, with a combined totals line for multi-manifest runs.
///
/// # Errors
/// Never fails; returns `Result` to match the renderer signature.
pub fn render(reports: &[ManifestReport], quiet: bool) -> anyhow::Result<()> {
    // `--quiet` means "only the exit code matters" (CI use): print nothing.
    if quiet {
        return Ok(());
    }
    for (i, report) in reports.iter().enumerate() {
        if i > 0 {
            println!();
        }
        render_one(report);
    }
    if reports.len() > 1 {
        println!();
        let summary = Summary::of(reports);
        // The scope of the rollup, said out loud: how many manifests it spans and
        // how many distinct packages they actually depend on. The totals that
        // follow stay per-declaration, because that is what there is to act on.
        print!(
            "Overall ({}, {}) — ",
            counted(summary.manifests, "manifest", "manifests"),
            counted(summary.unique_packages, "unique package", "unique packages")
        );
        print_totals(&summary);
    }
    Ok(())
}

fn render_one(report: &ManifestReport) {
    let count = report.results.len();
    // "0 dependencies" is a count, and a count is a claim about the project. Where
    // the file that *is* the dependency list went unread there was nothing to
    // count, so the heading says that instead: a reader skimming headings must not
    // come away believing a project depends on nothing when nothing was read.
    let scope = if count == 0 && report.dependencies_unread {
        "dependency list unread".to_owned()
    } else {
        format!("{count} dependenc{}", if count == 1 { "y" } else { "ies" })
    };
    println!(
        "{} — {} ({scope})",
        report
            .path
            .display()
            .if_supports_color(Stream::Stdout, OwoColorize::bold),
        report.ecosystem.display_name(),
    );
    println!();

    let rows: Vec<(String, String, String, &CheckResult)> = report
        .results
        .iter()
        .map(|r| {
            (
                r.item.name.clone(),
                current_display(r),
                latest_display(r),
                r,
            )
        })
        .collect();

    let wp = width(rows.iter().map(|(n, _, _, _)| n.len()), "Package");
    let wc = width(rows.iter().map(|(_, c, _, _)| c.len()), "Current");
    let wl = width(rows.iter().map(|(_, _, l, _)| l.len()), "Latest");

    println!(
        "{:<wp$}  {:<wc$}  {:<wl$}  Status",
        "Package", "Current", "Latest"
    );
    for (name, current, latest, result) in &rows {
        println!(
            "{:<wp$}  {:<wc$}  {:<wl$}  {}",
            name,
            current,
            latest,
            status_cell(result)
        );
    }
    println!();
    print_totals(&Summary::of(std::slice::from_ref(report)));
}

fn width(lengths: impl Iterator<Item = usize>, header: &str) -> usize {
    lengths
        .chain(std::iter::once(header.len()))
        .max()
        .unwrap_or(0)
}

/// The status text, colored when stdout supports it.
fn status_cell(result: &CheckResult) -> String {
    let text = match &result.status {
        DependencyStatus::Vulnerable => {
            let n = result.current_vulnerabilities.len();
            format!("{n} vulnerabilit{}", if n == 1 { "y" } else { "ies" })
        }
        DependencyStatus::Error(msg) => format!("error: {msg}"),
        other => other.label().to_string(),
    };
    let style = match &result.status {
        DependencyStatus::UpToDate => Style::new().green(),
        DependencyStatus::PatchAvailable | DependencyStatus::UpdateAvailable => {
            Style::new().yellow()
        }
        DependencyStatus::Outdated | DependencyStatus::Error(_) => Style::new().red(),
        DependencyStatus::Vulnerable => Style::new().red().bold(),
        DependencyStatus::Local | DependencyStatus::Git => Style::new().dimmed(),
        // Not dimmed with the deliberately-skipped rows beside it: this one is a
        // gap in the report rather than a row there was nothing to say about, and
        // `--fail-on any` fails the build over it.
        DependencyStatus::Undetermined => Style::new().yellow(),
        _ => Style::new(),
    };
    format!(
        "{}",
        text.if_supports_color(Stream::Stdout, |t| t.style(style))
    )
}

/// `n singular` / `n plural`, since English will not derive one from the other.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn print_totals(summary: &Summary) {
    let mut parts = Vec::new();
    if summary.up_to_date > 0 {
        parts.push(format!("{} up to date", summary.up_to_date));
    }
    if summary.patch_available > 0 {
        parts.push(format!("{} patch", summary.patch_available));
    }
    let updates = summary.update_available + summary.outdated;
    if updates > 0 {
        parts.push(format!("{updates} update"));
    }
    if summary.vulnerable > 0 {
        parts.push(format!("{} vulnerable", summary.vulnerable));
    }
    if summary.error > 0 {
        parts.push(format!("{} error", summary.error));
    }
    let skipped = summary.local + summary.git;
    if skipped > 0 {
        parts.push(format!("{skipped} skipped"));
    }
    // Counted separately from `skipped`: a path dependency was passed over on
    // purpose, an undetermined one is a version this run failed to read.
    if summary.undetermined > 0 {
        parts.push(format!("{} undetermined", summary.undetermined));
    }
    if parts.is_empty() {
        parts.push("nothing to check".to_string());
    }
    println!("Totals: {}", parts.join(" · "));
}
