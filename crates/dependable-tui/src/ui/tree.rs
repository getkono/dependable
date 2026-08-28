//! The dependency tree pane.

use dependable_fetch::NodeKind;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Row as TableRow, Table, TableState};

use crate::app::App;
use crate::model::PackageData;
use crate::rows::{Row, RowKind};
use crate::theme::{self, Token};

/// Draw the tree.
///
/// Rendered as a [`Table`] rather than a `Paragraph` of pre-sliced lines: the
/// widget owns the scroll offset and the highlight, which is what gives the
/// pointer a row to land on and the selection a style ratatui applies for us.
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = app.rows();
    let table_rows: Vec<TableRow> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let hovered = app.hover == Some(i);
            let table_row = TableRow::new(vec![line(app, row, hovered)]);
            // The selection is painted by the table's highlight style and is the
            // stronger signal, so hover never competes with it.
            if hovered && i != app.selected_index() {
                table_row.style(theme::hover())
            } else {
                table_row
            }
        })
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

    // The offset stays owned by `App`, which is free of ratatui so navigation is
    // testable without a terminal; the widget state is rebuilt from it per frame.
    let mut state = TableState::new()
        .with_offset(app.offset)
        .with_selected((!rows.is_empty()).then(|| app.selected_index()));

    frame.render_stateful_widget(
        Table::new(table_rows, [Constraint::Percentage(100)])
            .row_highlight_style(theme::selection())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::fg(Token::Border))
                    .title(Span::styled(title, theme::fg(Token::Muted))),
            ),
        area,
        &mut state,
    );
}

/// Render one row: indent, disclosure marker, name, version, and annotations.
///
/// The selected row's background is applied by the table's highlight style, so
/// nothing here needs to know whether it is selected.
fn line<'a>(app: &App, row: &'a Row, hovered: bool) -> Line<'a> {
    let mut spans = vec![Span::raw("  ".repeat(row.depth))];

    // The marker is the thing a click acts on, so it is the thing that responds
    // to the pointer arriving: it fades from muted to the brand colour. Both
    // ends are ours, so nothing here assumes anything about the terminal.
    let marker_style = if hovered && row.has_children {
        Style::default().fg(theme::blend(
            Token::Muted,
            Token::Brand,
            app.hover_progress(),
        ))
    } else {
        theme::fg(Token::Muted)
    };
    spans.push(Span::styled(marker(row), marker_style));

    spans.push(Span::styled(row.name.clone(), name_style(row)));

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

    Line::from(spans)
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

fn name_style(row: &Row) -> Style {
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
