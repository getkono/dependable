//! OSC 8 hyperlinks, and the shortened text shown in place of a raw URL.
//!
//! # How a link reaches the screen
//!
//! ratatui has no notion of a link: its buffer is a grid of cells, each holding
//! a symbol and a style, and a `Span` cannot carry a URL. What it does have is
//! [`CellDiffOption::ForcedWidth`], which exists so a cell whose symbol is an
//! escape sequence can report the width it actually occupies on screen rather
//! than the width of the bytes in it.
//!
//! So a whole hyperlink — the opening OSC 8, the visible text, and the
//! terminator — goes into one cell, and that cell declares the width of the
//! visible text alone. The diff then emits the symbol verbatim and steps over
//! the columns the text covers, which is exactly the behaviour a link needs.
//!
//! Terminals that do not understand OSC 8 ignore the sequence and print the
//! text, so this degrades to plain text rather than to visible escape noise.
//! The `o` key opens the same URL for terminals where clicking is not an option.

use std::num::NonZeroU16;

use ratatui::buffer::{Buffer, Cell, CellDiffOption, CellWidth};
use ratatui::layout::Rect;
use ratatui::style::Style;

/// Start of a hyperlink: `ESC ] 8 ; ; <url> ESC \`.
fn open(url: &str) -> String {
    format!("\x1b]8;;{url}\x1b\\")
}

/// End of a hyperlink: the same sequence with an empty URL.
const CLOSE: &str = "\x1b]8;;\x1b\\";

/// Write `text` at `(x, y)` as a hyperlink to `url`.
///
/// Does nothing when the position is outside `area`, and truncates when the text
/// would overrun the area's right edge — a link is never worth corrupting the
/// layout for.
pub fn write(buf: &mut Buffer, area: Rect, x: u16, y: u16, url: &str, text: &str, style: Style) {
    if x < area.x || x >= area.right() || y < area.y || y >= area.bottom() {
        return;
    }
    let available = area.right() - x;
    let text = truncate(text, available);
    let Some(width) = NonZeroU16::new(text.cell_width()) else {
        return;
    };

    let Some(cell) = buf.cell_mut((x, y)) else {
        return;
    };
    cell.set_symbol(&format!("{}{text}{CLOSE}", open(url)));
    cell.set_style(style);
    cell.set_diff_option(CellDiffOption::ForcedWidth(width));

    // The link's own cell covers these columns, and the diff steps over them.
    // Blanking them keeps the buffer an honest picture of the screen, so a later
    // frame that removes the link redraws the right cells.
    for offset in 1..width.get() {
        if let Some(covered) = buf.cell_mut((x + offset, y)) {
            *covered = Cell::EMPTY;
        }
    }
}

/// Shorten `text` to at most `width` columns, marking the cut with an ellipsis.
fn truncate(text: &str, width: u16) -> String {
    if text.cell_width() <= width {
        return text.to_owned();
    }
    if width <= 1 {
        return "…".to_owned();
    }
    let mut out = String::new();
    for ch in text.chars() {
        if out.as_str().cell_width() + 1 >= width {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}

/// The readable form of a URL: what a person would say out loud.
///
/// Registries publish URLs in whatever shape their ecosystem writes them, and
/// the noise is never the informative part. npm in particular stores
/// `git+https://github.com/facebook/react.git`, of which only the middle
/// twenty characters tell the reader anything.
///
/// The full URL is still what the link points at; only the label is shortened.
#[must_use]
pub fn display_url(url: &str) -> String {
    let trimmed = url
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git://")
        .trim_start_matches("ssh://")
        .trim_start_matches("www.")
        .trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    if trimmed.is_empty() {
        url.to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// The URL a hyperlink should point at, normalised from what a registry stored.
///
/// The label may be shortened for reading, but the target has to remain
/// something a browser can open: npm's `git+…` prefix is a package-manager
/// convention, not a scheme any browser knows.
#[must_use]
pub fn target_url(url: &str) -> String {
    let trimmed = url.trim().trim_start_matches("git+");
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_owned();
    }
    if let Some(rest) = trimmed.strip_prefix("git://") {
        return format!("https://{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@") {
        return format!("https://{rest}");
    }
    // A bare `github:owner/repo` shorthand, or a bare host and path.
    if let Some(rest) = trimmed.strip_prefix("github:") {
        return format!("https://github.com/{rest}");
    }
    format!("https://{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn area() -> Rect {
        Rect {
            x: 0,
            y: 0,
            width: 20,
            height: 3,
        }
    }

    #[test]
    fn a_link_occupies_only_the_columns_its_text_covers() {
        let mut buf = Buffer::empty(area());
        write(
            &mut buf,
            area(),
            2,
            1,
            "https://example.com",
            "example",
            Style::default(),
        );

        let cell = buf.cell((2, 1)).expect("in bounds");
        assert_eq!(
            cell.cell_width(),
            7,
            "the cell reports the width of the visible text, not of the escapes"
        );
        assert!(cell.symbol().contains("\x1b]8;;https://example.com\x1b\\"));
        assert!(cell.symbol().contains("example"));
        assert!(cell.symbol().ends_with(CLOSE));
    }

    #[test]
    fn the_columns_the_link_covers_are_left_blank() {
        // They are stepped over by the diff, so anything left in them would be a
        // lie about what is on screen.
        let mut buf = Buffer::empty(area());
        buf.set_string(0, 1, "xxxxxxxxxxxxxxxxxxxx", Style::default());
        write(
            &mut buf,
            area(),
            2,
            1,
            "https://example.com",
            "example",
            Style::default(),
        );

        for x in 3..9 {
            assert_eq!(buf.cell((x, 1)).unwrap().symbol(), " ", "column {x}");
        }
        assert_eq!(
            buf.cell((9, 1)).unwrap().symbol(),
            "x",
            "the column after the link is untouched"
        );
    }

    #[test]
    fn a_link_is_truncated_rather_than_overrunning_the_pane() {
        let mut buf = Buffer::empty(area());
        write(
            &mut buf,
            area(),
            15,
            1,
            "https://example.com",
            "a-very-long-label",
            Style::default(),
        );
        let cell = buf.cell((15, 1)).expect("in bounds");
        assert!(cell.cell_width() <= 5, "must fit the remaining columns");
        assert!(cell.symbol().contains('…'));
    }

    #[test]
    fn a_position_outside_the_area_writes_nothing() {
        let mut buf = Buffer::empty(area());
        write(
            &mut buf,
            area(),
            50,
            1,
            "https://example.com",
            "example",
            Style::default(),
        );
        assert_eq!(buf.cell((0, 1)).unwrap().symbol(), " ");
    }

    #[test]
    fn a_link_keeps_the_style_it_was_given() {
        let mut buf = Buffer::empty(area());
        let style = Style::default().fg(Color::Blue);
        write(&mut buf, area(), 0, 0, "https://e.com", "e", style);
        assert_eq!(buf.cell((0, 0)).unwrap().fg, Color::Blue);
    }

    #[test]
    fn a_url_reads_as_the_part_that_identifies_it() {
        assert_eq!(
            display_url("https://github.com/serde-rs/serde"),
            "github.com/serde-rs/serde"
        );
        assert_eq!(
            display_url("git+https://github.com/facebook/react.git"),
            "github.com/facebook/react",
            "npm stores a git+ prefix and a .git suffix that say nothing"
        );
        assert_eq!(display_url("https://www.example.com/"), "example.com");
    }

    #[test]
    fn a_shortened_label_still_points_at_something_openable() {
        assert_eq!(
            target_url("git+https://github.com/facebook/react.git"),
            "https://github.com/facebook/react",
            "git+ is a package-manager convention, not a browser scheme"
        );
        assert_eq!(target_url("git://github.com/a/b"), "https://github.com/a/b");
        assert_eq!(
            target_url("github:owner/repo"),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            target_url("https://example.com"),
            "https://example.com",
            "an ordinary URL is left alone"
        );
    }

    #[test]
    fn a_url_that_is_only_noise_is_kept_verbatim() {
        // Better to show something odd than to show nothing at all.
        assert_eq!(display_url("https://"), "https://");
    }
}
