//! The detail pane: everything known about the selected package.
//!
//! Absence is rendered honestly. A field the registry did not publish reads
//! "not published", never as a blank line that looks like missing data, and a
//! lookup that failed says so rather than looking like an empty package.

use dependable_fetch::{DependencyStatus, PackageMetadata};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::model::{PackageData, PackageFacts, compact_count, relative_age};
use crate::rows::RowKind;

/// Draw the pane for the current selection.
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let lines = match app.selected() {
        None => vec![dim("nothing selected")],
        Some(row) if row.kind == RowKind::Project => project_lines(app, row.project),
        Some(row) => package_lines(app, &row.name, &row.version),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" details "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// What we can say about a whole project.
fn project_lines(app: &App, index: usize) -> Vec<Line<'static>> {
    let project = &app.projects[index];
    let mut lines = vec![
        heading(&project.label),
        field("ecosystem", project.ecosystem.display_name()),
        field("manifest", &project.manifest.display().to_string()),
        field("packages", &project.graph.nodes().len().to_string()),
    ];
    if let Some(caveat) = project.caveat() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            caveat.to_owned(),
            Style::default().fg(Color::Yellow),
        ));
    }
    lines
}

/// What we know about the selected package.
fn package_lines(app: &App, name: &str, version: &str) -> Vec<Line<'static>> {
    let mut lines = vec![heading(name)];
    if version.is_empty() {
        // A shallow graph resolves no versions, so there is nothing to look up.
        lines.push(dim("version not resolved — no lockfile for this project"));
        return lines;
    }
    lines.push(field("resolved", version));
    lines.push(Line::raw(""));

    match app.selected_data() {
        None | Some(PackageData::Unloaded) => lines.push(dim("loading…")),
        Some(PackageData::Loading) => lines.push(dim("loading…")),
        Some(PackageData::Failed(error)) => {
            lines.push(Line::styled(
                format!("could not load: {error}"),
                Style::default().fg(Color::Red),
            ));
            lines.push(dim("press r to try again"));
        }
        Some(PackageData::Ready(facts)) => lines.extend(facts_lines(facts)),
    }
    lines
}

/// Render a completed lookup.
fn facts_lines(facts: &PackageFacts) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Freshness first: it is the question most often being asked.
    if let Some(latest) = &facts.latest {
        lines.push(field("latest", latest));
    }
    if let Some(status) = &facts.status {
        lines.push(Line::from(vec![
            label("status"),
            Span::styled(status.label().to_owned(), status_style(status)),
        ]));
    }

    if facts.vulnerabilities.is_empty() {
        lines.push(field("advisories", "none known"));
    } else {
        lines.push(Line::from(vec![
            label("advisories"),
            Span::styled(
                facts.vulnerabilities.join(", "),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    lines.push(Line::raw(""));
    match &facts.metadata {
        None => lines.push(dim("this registry publishes no package metadata")),
        Some(meta) => lines.extend(metadata_lines(meta)),
    }

    for warning in &facts.warnings {
        lines.push(Line::styled(
            warning.clone(),
            Style::default().fg(Color::Yellow),
        ));
    }
    lines
}

/// The public metadata block.
fn metadata_lines(meta: &PackageMetadata) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(description) = &meta.description {
        // Registry descriptions are often hard-wrapped; the pane does its own
        // wrapping, and the embedded newlines would otherwise run words together.
        lines.push(Line::raw(
            description.split_whitespace().collect::<Vec<_>>().join(" "),
        ));
        lines.push(Line::raw(""));
    }
    lines.push(optional("repository", meta.repository.as_deref()));
    lines.push(optional("homepage", meta.homepage.as_deref()));
    lines.push(optional("docs", meta.documentation.as_deref()));
    lines.push(optional("license", meta.license.as_deref()));
    lines.push(optional("msrv", meta.msrv.as_deref()));

    if meta.authors.is_empty() {
        lines.push(optional("owners", None));
    } else {
        lines.push(field("owners", &meta.authors.join(", ")));
    }

    lines.push(Line::raw(""));
    lines.push(optional(
        "downloads",
        meta.downloads.map(compact_count).as_deref(),
    ));
    lines.push(optional(
        "published",
        meta.last_published.as_deref().map(relative_age).as_deref(),
    ));
    if meta.yanked {
        lines.push(Line::styled(
            "this version has been yanked",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    lines
}

fn status_style(status: &DependencyStatus) -> Style {
    match status {
        DependencyStatus::UpToDate => Style::default().fg(Color::Green),
        DependencyStatus::PatchAvailable | DependencyStatus::UpdateAvailable => {
            Style::default().fg(Color::Yellow)
        }
        DependencyStatus::Outdated => Style::default().fg(Color::Red),
        DependencyStatus::Vulnerable => {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        }
        _ => Style::default().fg(Color::DarkGray),
    }
}

fn heading(text: &str) -> Line<'static> {
    Line::styled(
        text.to_owned(),
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
}

fn label(name: &str) -> Span<'static> {
    Span::styled(
        format!("{name:>11}  "),
        Style::default().fg(Color::DarkGray),
    )
}

fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![label(name), Span::raw(value.to_owned())])
}

/// A field the registry may not have published — said plainly either way.
fn optional(name: &str, value: Option<&str>) -> Line<'static> {
    match value {
        Some(value) => field(name, value),
        None => Line::from(vec![
            label(name),
            Span::styled("not published", Style::default().fg(Color::DarkGray)),
        ]),
    }
}

fn dim(text: &str) -> Line<'static> {
    Line::styled(text.to_owned(), Style::default().fg(Color::DarkGray))
}
