//! Rendering. Reads [`App`]; never mutates it beyond scrolling to the selection.

mod detail;
pub mod link;
mod tree;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::{App, Mode};
use crate::theme::{self, Token};

/// The tree table's column header, which occupies the first row of the pane's
/// interior.
///
/// It is not a row the pointer can select, and it is not a row the viewport can
/// scroll a selection into, so both calculations have to step over it.
const TREE_HEADER: u16 = 1;

/// How many rows the tree body can show inside a pane `height` rows tall.
///
/// The single source for both the viewport handed to [`App::scroll_into_view`]
/// and the [`Geometry`] a pointer is resolved against. Deriving them separately
/// is how they drifted apart: the header was added to the tree long after the
/// pointer mapping was written, and only one of the two learned about it.
fn tree_viewport(height: u16) -> u16 {
    height.saturating_sub(2 + TREE_HEADER)
}

/// Where the last frame put things, so a pointer position can be resolved back
/// to what the user was pointing at.
///
/// Rendering is the only place that knows the pane rectangles, and it recomputes
/// them every frame from the terminal size. Returning them is cheaper and far
/// less error-prone than deriving the same layout a second time in the event
/// loop and hoping the two stay in step.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Geometry {
    /// The tree pane, borders included.
    pub tree: Rect,
    /// The detail pane, borders included.
    pub detail: Rect,
    /// Index of the first row drawn in the tree body.
    pub tree_offset: usize,
    /// How many rows the tree body can show.
    pub tree_height: u16,
    /// How many rows the tree actually has, so a click past the end is ignored.
    pub row_count: usize,
}

impl Geometry {
    /// The row index at screen position `(x, y)`, if that position is a row.
    ///
    /// Returns `None` for the borders, for a point outside the tree pane, and
    /// for the empty space below the last row — clicking past the end should do
    /// nothing rather than jump to the bottom.
    #[must_use]
    pub fn row_at(&self, x: u16, y: u16) -> Option<usize> {
        let inner = self.tree_body();
        if x < inner.x || x >= inner.right() || y < inner.y || y >= inner.bottom() {
            return None;
        }
        let index = self.tree_offset + usize::from(y - inner.y);
        (index < self.row_count).then_some(index)
    }

    /// Whether `(x, y)` falls on a row's disclosure marker.
    ///
    /// The marker sits after the row's indent, so this needs the row's depth;
    /// the caller supplies it because only [`crate::app::App`] knows the rows.
    #[must_use]
    pub fn on_marker(&self, x: u16, depth: usize) -> bool {
        let inner = self.tree_body();
        let Ok(indent) = u16::try_from(depth * 2) else {
            return false;
        };
        let start = inner.x.saturating_add(indent);
        x >= start && x < start.saturating_add(2)
    }

    /// Whether `(x, y)` falls on the draggable divider between the panes.
    #[must_use]
    pub fn on_divider(&self, x: u16, y: u16) -> bool {
        // The panes abut, so the divider is the tree's right border column.
        self.tree.width > 0
            && x == self.tree.right().saturating_sub(1)
            && y >= self.tree.y
            && y < self.tree.bottom()
    }

    /// The tree pane's share of the width if the divider were dropped at `x`,
    /// as a percentage.
    ///
    /// Clamping to a sensible range is [`crate::app::App`]'s job, since it owns
    /// the split; this only converts a column to a proportion.
    #[must_use]
    pub fn split_at(&self, x: u16) -> u16 {
        let total = self.tree.width.saturating_add(self.detail.width);
        if total == 0 {
            return 0;
        }
        let offset = x.saturating_sub(self.tree.x);
        u16::try_from(u32::from(offset) * 100 / u32::from(total)).unwrap_or(100)
    }

    /// The rows of the tree pane: its interior, less the border and the column
    /// header above them.
    fn tree_body(&self) -> Rect {
        Rect {
            x: self.tree.x.saturating_add(1),
            y: self.tree.y.saturating_add(1 + TREE_HEADER),
            width: self.tree.width.saturating_sub(2),
            height: self.tree_height,
        }
    }
}

/// Draw the whole UI for one frame, reporting where everything landed.
pub fn draw(frame: &mut Frame, app: &mut App) -> Geometry {
    // One clock reading for the whole frame, so every spinner on it agrees.
    app.tick();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(3),    // tree + detail
            Constraint::Length(1), // search line
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(app.split),
            Constraint::Percentage(100 - app.split),
        ])
        .split(chunks[1]);

    // The border, the title, and the column header all take rows off the height
    // the tree can actually fill.
    let viewport = tree_viewport(panes[0].height);
    app.scroll_into_view(usize::from(viewport));

    draw_header(frame, chunks[0], app);
    tree::draw(frame, panes[0], app);
    detail::draw(frame, panes[1], app);
    draw_search(frame, chunks[2], app);
    draw_status(frame, chunks[3], app);

    if app.mode == Mode::Help {
        draw_help(frame, frame.area());
    }

    Geometry {
        tree: panes[0],
        detail: panes[1],
        tree_offset: app.offset,
        tree_height: viewport,
        row_count: app.rows().len(),
    }
}

/// The header: the wordmark, what was scanned, and the totals.
///
/// The wordmark is hard left and is the only thing painted in the brand colour,
/// so it stays recognisable as the product rather than as one more coloured
/// label among many.
fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::styled("dependable", theme::bold(Token::Brand))];

    if let Some(root) = &app.root {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            root.display().to_string(),
            theme::fg(Token::Muted),
        ));
    }

    if !app.projects.is_empty() {
        spans.push(Span::styled(
            format!("   {} packages", app.package_count()),
            theme::fg(Token::Muted),
        ));
    }

    // Only packages already looked up can be counted, so this is a floor rather
    // than a total, and it appears only once there is something to report.
    let vulnerable = app.vulnerable_count();
    if vulnerable > 0 {
        spans.push(Span::styled(
            format!("   {vulnerable} vulnerable"),
            theme::bold(Token::Critical),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
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

    if app.scanning {
        frame.render_widget(
            Paragraph::new(Line::styled(
                format!("{} scanning for projects…", app.spinner()),
                theme::fg(Token::Muted),
            )),
            area,
        );
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
    /// Width the key names are right-aligned within.
    const KEY_COLUMN: usize = 18;

    const KEYS: &[(&str, &str)] = &[
        ("j / k, arrows", "move"),
        ("l / right / enter", "expand, step in, or follow a pointer"),
        ("h / left", "collapse, or step out"),
        ("g / G", "first / last row"),
        ("/", "search by glob: serde*, @types/*"),
        ("n / N", "next / previous match"),
        ("esc", "clear the search"),
        ("i", "invert: what depends on this"),
        ("r", "re-fetch the selected package"),
        ("o", "open this package's link in a browser"),
        ("click / scroll", "select a row, or open it by its marker"),
        ("drag the divider", "resize the panes"),
        ("shift-drag", "select text (bypasses mouse reporting)"),
        ("?", "close this help"),
        ("q / ctrl-c", "quit"),
    ];

    // Sized to its longest entry rather than to a guess, so adding a binding
    // cannot silently truncate the one that explains it.
    let widest = KEYS
        .iter()
        .map(|(_, what)| what.chars().count())
        .max()
        .unwrap_or(0);
    let content = u16::try_from(KEY_COLUMN + 2 + widest + 2).unwrap_or(u16::MAX);

    // One row per entry: the paragraph does not wrap, so this height is exact.
    let width = content.min(area.width.saturating_sub(4));
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
                Span::styled(
                    format!("{key:>KEY_COLUMN$}  "),
                    theme::bold(Token::KindWorkspace),
                ),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A 40x12 tree pane at the origin, scrolled down by five rows.
    fn geometry() -> Geometry {
        Geometry {
            tree: Rect {
                x: 0,
                y: 0,
                width: 40,
                height: 12,
            },
            detail: Rect {
                x: 40,
                y: 0,
                width: 40,
                height: 12,
            },
            tree_offset: 5,
            tree_height: tree_viewport(12),
            row_count: 100,
        }
    }

    #[test]
    fn a_click_in_the_body_resolves_to_the_row_under_it() {
        let g = geometry();
        // The first body row sits at y=2: below the top border, and below the
        // column header the table draws under it. It shows the row the offset
        // starts at.
        assert_eq!(g.row_at(10, 2), Some(5));
        assert_eq!(g.row_at(10, 3), Some(6));
        assert_eq!(g.row_at(10, 10), Some(13));
    }

    #[test]
    fn the_column_header_is_not_a_row() {
        // The table draws NAME / VERSION / AGE / STATUS on the first interior
        // row. Reading it as a row shifted every click and hover down one, so a
        // click on a parent selected the child beneath it.
        assert_eq!(geometry().row_at(10, 1), None);
    }

    #[test]
    fn the_body_stops_where_the_table_stops_drawing_rows() {
        // Three rows go to the border, the title, and the header, so the last
        // row of a twelve-row pane is at y=10, not y=11.
        let g = geometry();
        assert_eq!(g.row_at(10, 10), Some(13), "the last drawn row");
        assert_eq!(g.row_at(10, 11), None, "the bottom border");
    }

    #[test]
    fn the_borders_are_not_rows() {
        let g = geometry();
        assert_eq!(g.row_at(10, 0), None, "top border");
        assert_eq!(g.row_at(0, 5), None, "left border");
        assert_eq!(g.row_at(39, 5), None, "right border");
    }

    #[test]
    fn a_click_outside_the_pane_is_not_a_row() {
        let g = geometry();
        assert_eq!(g.row_at(50, 5), None, "over the detail pane");
        assert_eq!(g.row_at(10, 30), None, "below the pane");
    }

    #[test]
    fn a_click_past_the_last_row_selects_nothing() {
        // Clicking the empty space under a short tree should do nothing, not
        // jump to the bottom.
        let short = Geometry {
            row_count: 3,
            tree_offset: 0,
            ..geometry()
        };
        assert_eq!(short.row_at(10, 4), Some(2), "the last row");
        assert_eq!(short.row_at(10, 5), None, "the empty space below it");
    }

    #[test]
    fn the_viewport_leaves_room_for_the_border_and_the_header() {
        // The value `scroll_into_view` is given and the one a pointer is
        // resolved against are the same number, so a selection can never scroll
        // to a row a click cannot reach.
        assert_eq!(tree_viewport(12), 9);
        assert_eq!(tree_viewport(3), 0, "no room for any row");
        assert_eq!(tree_viewport(0), 0, "a pane dragged away entirely");
    }

    #[test]
    fn the_marker_is_hit_only_after_the_row_indent() {
        let g = geometry();
        // Depth 0: the marker occupies the first two body columns.
        assert!(g.on_marker(1, 0));
        assert!(g.on_marker(2, 0));
        assert!(!g.on_marker(3, 0), "past the marker is the name");

        // Depth 2 indents it by four columns.
        assert!(!g.on_marker(2, 2));
        assert!(g.on_marker(5, 2));
        assert!(g.on_marker(6, 2));
        assert!(!g.on_marker(7, 2));
    }

    #[test]
    fn the_divider_is_the_column_between_the_panes() {
        let g = geometry();
        assert!(g.on_divider(39, 5));
        assert!(!g.on_divider(38, 5), "inside the tree");
        assert!(!g.on_divider(40, 5), "inside the detail pane");
        assert!(!g.on_divider(39, 20), "below both panes");
    }

    #[test]
    fn a_zero_sized_pane_resolves_nothing() {
        // A terminal can be resized to nothing mid-drag; the arithmetic must not
        // underflow or report a hit.
        let empty = Geometry::default();
        assert_eq!(empty.row_at(0, 0), None);
        assert!(!empty.on_divider(0, 0));
    }
}
