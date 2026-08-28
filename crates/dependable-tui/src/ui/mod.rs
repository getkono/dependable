//! Rendering. Reads [`App`]; never mutates it beyond scrolling to the selection.

mod detail;
mod tree;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::{App, Mode};
use crate::theme::{self, Token};

/// Draw the whole UI for one frame.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // tree + detail
            Constraint::Length(1), // search line
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[0]);

    // The border and title take two rows off the usable height.
    let viewport = panes[0].height.saturating_sub(2) as usize;
    app.scroll_into_view(viewport);

    tree::draw(frame, panes[0], app, viewport);
    detail::draw(frame, panes[1], app);
    draw_search(frame, chunks[1], app);
    draw_status(frame, chunks[2], app);

    if app.mode == Mode::Help {
        draw_help(frame, frame.area());
    }
}

/// The search line, showing a cursor while it is being typed into.
fn draw_search(frame: &mut Frame, area: Rect, app: &App) {
    let (prefix, style) = match app.mode {
        Mode::Search => ("/", theme::fg(Token::Warn)),
        _ if app.query.is_empty() => ("", theme::fg(Token::Muted)),
        _ => ("/", theme::fg(Token::Muted)),
    };
    let text = if app.mode == Mode::Search {
        format!("{prefix}{}\u{2588}", app.query)
    } else if app.query.is_empty() {
        "press / to search, ? for help".to_owned()
    } else {
        format!("{prefix}{}", app.query)
    };
    frame.render_widget(Paragraph::new(Line::styled(text, style)), area);
}

/// The status bar: counts, the active caveat, and any transient message.
fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(message) = &app.message {
        let style = theme::fg(Token::Warn);
        frame.render_widget(Paragraph::new(Line::styled(message.clone(), style)), area);
        return;
    }

    let mut spans = vec![Span::styled(
        format!("{} rows", app.rows().len()),
        theme::fg(Token::Muted),
    )];
    if let Some(row) = app.selected()
        && let Some(caveat) = app.projects[row.project].caveat()
    {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(caveat, theme::fg(Token::Warn)));
    }
    if app.inverted {
        spans.push(Span::styled("  inverted", theme::fg(Token::KindGit)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The key reference, shown over the tree.
fn draw_help(frame: &mut Frame, area: Rect) {
    const KEYS: &[(&str, &str)] = &[
        ("j / k, arrows", "move"),
        ("l / right / enter", "expand, or step in"),
        ("h / left", "collapse, or step out"),
        ("g / G", "first / last row"),
        ("/", "search by glob: serde*, @types/*"),
        ("n / N", "next / previous match"),
        ("esc", "clear the search"),
        ("i", "invert: what depends on this"),
        ("r", "re-fetch the selected package"),
        ("?", "close this help"),
        ("q / ctrl-c", "quit"),
    ];

    // One row per entry: the paragraph does not wrap, so this height is exact.
    let width = 58.min(area.width.saturating_sub(4));
    let height = (KEYS.len() as u16 + 2).min(area.height.saturating_sub(2));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    let lines: Vec<Line> = KEYS
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(format!("{key:>18}  "), theme::bold(Token::KindWorkspace)),
                Span::styled(*what, theme::fg(Token::Text)),
            ])
        })
        .collect();

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::fg(Token::Border))
                .title(Span::styled(" keys ", theme::fg(Token::Muted))),
        ),
        popup,
    );
}
