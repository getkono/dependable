//! The dependency tree pane.

use dependable_fetch::NodeKind;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;
use crate::model::PackageData;
use crate::rows::{Row, RowKind};

/// Draw the visible slice of the tree.
pub fn draw(frame: &mut Frame, area: Rect, app: &App, viewport: usize) {
    let rows = app.rows();
    let end = (app.offset + viewport).min(rows.len());
    let lines: Vec<Line> = rows[app.offset.min(rows.len())..end]
        .iter()
        .enumerate()
        .map(|(i, row)| line(app, row, app.offset + i == app.selected_index()))
        .collect();

    let title = if rows.is_empty() {
        " dependencies — nothing to show ".to_owned()
    } else {
        format!(
            " dependencies — {} of {} ",
            app.selected_index() + 1,
            rows.len()
        )
    };

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

/// Render one row: indent, disclosure marker, name, version, and annotations.
fn line<'a>(app: &App, row: &'a Row, selected: bool) -> Line<'a> {
    let mut spans = vec![Span::raw("  ".repeat(row.depth))];

    spans.push(Span::styled(
        marker(row),
        Style::default().fg(Color::DarkGray),
    ));

    spans.push(Span::styled(row.name.clone(), name_style(row, selected)));

    if !row.version.is_empty() {
        spans.push(Span::styled(
            format!(" {}", row.version),
            Style::default().fg(Color::DarkGray),
        ));
    }

    if let Some(tag) = kind_tag(row) {
        spans.push(Span::styled(
            format!(" ({tag})"),
            Style::default().fg(Color::Blue),
        ));
    }

    if row.cyclic {
        spans.push(Span::styled(
            " (cycle)",
            Style::default().fg(Color::DarkGray),
        ));
    }

    if let Some(badge) = status_badge(app, row) {
        spans.push(badge);
    }

    let mut line = Line::from(spans);
    if selected {
        line = line.style(Style::default().bg(Color::Rgb(40, 44, 52)));
    }
    line
}

/// The disclosure marker: open, closed, or a leaf.
fn marker(row: &Row) -> &'static str {
    if !row.has_children {
        "  "
    } else if row.expanded {
        "v "
    } else {
        "> "
    }
}

fn name_style(row: &Row, selected: bool) -> Style {
    let mut style = match row.kind {
        RowKind::Project => Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        RowKind::Package => match row.node_kind {
            Some(NodeKind::Workspace) => Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            Some(NodeKind::Git) => Style::default().fg(Color::Magenta),
            Some(NodeKind::Path) => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        },
    };
    if row.matched {
        style = style.bg(Color::Rgb(70, 60, 0));
    }
    if selected {
        style = style.add_modifier(Modifier::BOLD);
    }
    style
}

/// The `(workspace)` / `(git)` / `(path)` annotation, where it says something.
fn kind_tag(row: &Row) -> Option<&'static str> {
    match row.node_kind? {
        NodeKind::Workspace => Some("workspace"),
        NodeKind::Git => Some("git"),
        NodeKind::Path => Some("path"),
        _ => None,
    }
}

/// A short badge for what is known about the package, so the tree itself carries
/// the headline: vulnerable, outdated, or still loading.
fn status_badge<'a>(app: &App, row: &Row) -> Option<Span<'a>> {
    use dependable_fetch::DependencyStatus;

    // Only registry packages are ever looked up, so only they can carry a badge.
    if row.kind != RowKind::Package
        || row.version.is_empty()
        || row.node_kind != Some(NodeKind::Registry)
    {
        return None;
    }
    let key = crate::model::key(app.ecosystem_of(row), &row.name, &row.version);
    Some(match app.packages.get(&key)? {
        PackageData::Loading => Span::styled(" …", Style::default().fg(Color::DarkGray)),
        PackageData::Failed(_) => Span::styled(" !", Style::default().fg(Color::Red)),
        PackageData::Unloaded => return None,
        PackageData::Ready(facts) => {
            if !facts.vulnerabilities.is_empty() {
                Span::styled(
                    format!(" VULN({})", facts.vulnerabilities.len()),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else {
                match facts.status {
                    Some(DependencyStatus::Outdated) => {
                        Span::styled(" outdated", Style::default().fg(Color::Red))
                    }
                    Some(DependencyStatus::UpdateAvailable) => {
                        Span::styled(" update", Style::default().fg(Color::Yellow))
                    }
                    Some(DependencyStatus::PatchAvailable) => {
                        Span::styled(" patch", Style::default().fg(Color::Yellow))
                    }
                    _ => return None,
                }
            }
        }
    })
}
