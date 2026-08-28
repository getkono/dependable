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
            let table_row = TableRow::new(vec![
                name_cell(app, row, hovered),
                Line::styled(row.version.clone(), theme::fg(Token::Muted)),
                Line::styled(age(app, row), theme::fg(Token::Muted)),
                status_cell(app, row),
            ]);
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
        Table::new(
            table_rows,
            [
                Constraint::Min(20), // name, with the tree shape inside it
                Constraint::Length(VERSION_WIDTH),
                Constraint::Length(AGE_WIDTH),
                Constraint::Length(STATUS_WIDTH),
            ],
        )
        .header(header())
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

/// The version column: wide enough for a long semver with a pre-release tag.
const VERSION_WIDTH: u16 = 12;
/// The age column, bounded by [`crate::model::compact_age`].
const AGE_WIDTH: u16 = 6;
/// The status column, wide enough for the longest badge.
const STATUS_WIDTH: u16 = 9;

/// The column headings.
fn header() -> TableRow<'static> {
    TableRow::new(vec![
        Line::styled("  NAME", theme::fg(Token::Muted)),
        Line::styled("VERSION", theme::fg(Token::Muted)),
        Line::styled("AGE", theme::fg(Token::Muted)),
        Line::styled("STATUS", theme::fg(Token::Muted)),
    ])
}

/// How long ago the resolved version was published, in the compact form.
///
/// Empty until the package has been looked up, and for anything that did not
/// come from a registry — a workspace member has no publish date to report.
fn age(app: &App, row: &Row) -> String {
    if row.kind != RowKind::Package || row.node_kind != Some(NodeKind::Registry) {
        return String::new();
    }
    let key = crate::model::key(app.ecosystem_of(row), &row.name, &row.version);
    let Some(PackageData::Ready(facts)) = app.packages.get(&key) else {
        return String::new();
    };
    facts
        .metadata
        .as_ref()
        .and_then(|meta| meta.published_at(&row.version))
        .map(crate::model::compact_age)
        .unwrap_or_default()
}

/// The name column: indent, disclosure marker, name, and its annotations.
///
/// The tree shape lives inside this column so the ones beside it stay aligned;
/// indenting the whole row would step the versions and ages out of line and
/// undo the point of having columns.
///
/// The selected row's background is applied by the table's highlight style, so
/// nothing here needs to know whether it is selected.
fn name_cell<'a>(app: &App, row: &'a Row, hovered: bool) -> Line<'a> {
    let mut spans = vec![Span::raw("  ".repeat(row.depth))];

    // The marker is the thing a click acts on, so it is the thing that responds
    // to the pointer arriving: it fades from muted to the brand colour. Both
    // ends are ours, so nothing here assumes anything about the terminal.
    let marker_style = if hovered && (row.has_children || row.redirect.is_some()) {
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

    if row.cyclic {
        spans.push(Span::styled(" (cycle)", theme::fg(Token::Muted)));
    }
    if row.redirect.is_some() {
        spans.push(Span::styled(" (see root)", theme::fg(Token::Muted)));
    }

    Line::from(spans)
}

/// The disclosure marker: open, closed, a pointer elsewhere, or a leaf.
///
/// Always two columns wide, so the indent arithmetic the click hit-test relies
/// on holds whatever a row turns out to be.
fn marker(row: &Row) -> &'static str {
    if row.redirect.is_some() {
        "\u{2197} "
    } else if !row.has_children {
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

/// The status column.
///
/// A registry package reports its freshness here. Anything else reports where
/// it came from instead — the two never apply to the same row, and a workspace
/// member's origin is the most useful thing to say about it. Keeping the origin
/// out of the name column also stops it crowding out the name itself, which is
/// what the column is for.
fn status_cell<'a>(app: &App, row: &Row) -> Line<'a> {
    if let Some(tag) = kind_tag(row) {
        return Line::styled(tag, theme::fg(Token::Link));
    }
    status_badge(app, row).unwrap_or_else(|| Line::raw(""))
}

/// A short badge for what is known about the package, so the tree itself carries
/// the headline: vulnerable, outdated, or still loading.
fn status_badge<'a>(app: &App, row: &Row) -> Option<Line<'a>> {
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
        PackageData::Loading => Line::styled(app.spinner(), theme::fg(Token::Muted)),
        PackageData::Failed(_) => Line::styled("failed", theme::fg(Token::Critical)),
        PackageData::Unloaded => return None,
        PackageData::Ready(facts) => {
            if !facts.vulnerabilities.is_empty() {
                Line::styled(
                    format!("VULN {}", facts.vulnerabilities.len()),
                    theme::bold(Token::Critical),
                )
            } else {
                match facts.status {
                    Some(DependencyStatus::Outdated) => {
                        Line::styled("outdated", theme::fg(Token::Critical))
                    }
                    Some(DependencyStatus::UpdateAvailable) => {
                        Line::styled("update", theme::fg(Token::Warn))
                    }
                    Some(DependencyStatus::PatchAvailable) => {
                        Line::styled("patch", theme::fg(Token::Warn))
                    }
                    Some(DependencyStatus::UpToDate) => Line::styled("ok", theme::fg(Token::Ok)),
                    _ => return None,
                }
            }
        }
    })
}
