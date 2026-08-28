//! The dependency tree pane.

use dependable_fetch::NodeKind;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;
use crate::model::PackageData;
use crate::rows::{Row, RowKind};
use crate::theme::{self, Token};

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
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::fg(Token::Border))
                .title(Span::styled(title, theme::fg(Token::Muted))),
        ),
        area,
    );
}

/// Render one row: indent, disclosure marker, name, version, and annotations.
fn line<'a>(app: &App, row: &'a Row, selected: bool) -> Line<'a> {
    let mut spans = vec![Span::raw("  ".repeat(row.depth))];

    spans.push(Span::styled(marker(row), theme::fg(Token::Muted)));

    spans.push(Span::styled(row.name.clone(), name_style(row, selected)));

    if !row.version.is_empty() {
        spans.push(Span::styled(
            format!(" {}", row.version),
            theme::fg(Token::Muted),
        ));
    }

    if let Some(tag) = kind_tag(row) {
        spans.push(Span::styled(format!(" ({tag})"), theme::fg(Token::Link)));
    }

    if row.cyclic {
        spans.push(Span::styled(" (cycle)", theme::fg(Token::Muted)));
    }

    if let Some(badge) = status_badge(app, row) {
        spans.push(badge);
    }

    let mut line = Line::from(spans);
    if selected {
        line = line.style(theme::selection());
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
        RowKind::Project => theme::bold(Token::Heading),
        RowKind::Package => match row.node_kind {
            Some(NodeKind::Workspace) => theme::bold(Token::KindWorkspace),
            Some(NodeKind::Git) => theme::fg(Token::KindGit),
            Some(NodeKind::Path) => theme::fg(Token::KindPath),
            _ => theme::fg(Token::Text),
        },
    };
    if row.matched {
        style = style.patch(theme::search_match());
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
        PackageData::Loading => Span::styled(" …", theme::fg(Token::Muted)),
        PackageData::Failed(_) => Span::styled(" !", theme::fg(Token::Critical)),
        PackageData::Unloaded => return None,
        PackageData::Ready(facts) => {
            if !facts.vulnerabilities.is_empty() {
                Span::styled(
                    format!(" VULN({})", facts.vulnerabilities.len()),
                    theme::bold(Token::Critical),
                )
            } else {
                match facts.status {
                    Some(DependencyStatus::Outdated) => {
                        Span::styled(" outdated", theme::fg(Token::Critical))
                    }
                    Some(DependencyStatus::UpdateAvailable) => {
                        Span::styled(" update", theme::fg(Token::Warn))
                    }
                    Some(DependencyStatus::PatchAvailable) => {
                        Span::styled(" patch", theme::fg(Token::Warn))
                    }
                    _ => return None,
                }
            }
        }
    })
}
