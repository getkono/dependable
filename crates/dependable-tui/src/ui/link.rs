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

/// Write `text` at `(x, y)` as a hyperlink to `url`, claiming the rest of the row.
///
/// Does nothing when the position is outside `area`, and truncates when the text
/// would overrun the area's right edge — a link is never worth corrupting the
/// layout for.
///
/// # Why it claims the whole tail
///
/// A forced-width cell prints its symbol and the diff then *steps over* the
/// columns it covers, so those columns are never compared against the previous
/// frame. The buffer records them as blank, but the screen holds whatever the
/// link printed there. A shorter link replacing a longer one would therefore
/// leave the tail of the old one on screen — `github.com/serde-rs/serde`
/// followed by the `mltree` of the `roxmltree` link it replaced.
///
/// Padding the symbol with spaces out to the edge of `area` makes every link
/// repaint its own tail, whatever the previous frame drew. The padding sits
/// *after* the terminator, so it is not part of the link. The consequence is
/// that a link owns the rest of its row: nothing may be drawn to its right.
pub fn write(buf: &mut Buffer, area: Rect, x: u16, y: u16, url: &str, text: &str, style: Style) {
    if x < area.x || x >= area.right() || y < area.y || y >= area.bottom() {
        return;
    }
    let available = area.right() - x;
    let text = truncate(text, available);
    if text.is_empty() {
        return;
    }
    let Some(width) = NonZeroU16::new(available) else {
        return;
    };
    let padding = " ".repeat(usize::from(available.saturating_sub(text.cell_width())));

    let visible = format!("{text}{padding}");

    // Record what the screen will actually show in the columns the link covers,
    // one character per cell, *before* the escape goes in.
    //
    // Blanking them instead is a lie the next frame believes: the terminal has
    // printed the label there, so a following frame that draws plain text over
    // the same row compares its spaces against blanks, finds them equal, and
    // emits nothing — leaving `1.3B` followed by the `-lang-owner` of the link
    // it replaced. The diff steps over these cells while the link is present,
    // so their only job is to describe the screen for the frame after this one.
    for (offset, ch) in visible.chars().enumerate() {
        let Ok(offset) = u16::try_from(offset) else {
            break;
        };
        if offset >= width.get() {
            break;
        }
        if let Some(covered) = buf.cell_mut((x + offset, y)) {
            *covered = Cell::EMPTY;
            covered.set_char(ch);
            covered.set_style(style);
        }
    }

    let Some(cell) = buf.cell_mut((x, y)) else {
        return;
    };
    cell.set_symbol(&format!("{}{text}{CLOSE}{padding}", open(url)));
    cell.set_style(style);
    cell.set_diff_option(CellDiffOption::ForcedWidth(width));
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
    fn a_link_carries_its_url_its_text_and_a_terminator() {
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
        assert!(
            cell.symbol()
                .starts_with("\x1b]8;;https://example.com\x1b\\")
        );
        assert!(cell.symbol().contains("example"));
        assert!(
            cell.symbol().contains(CLOSE),
            "the link is terminated before its padding"
        );
    }

    #[test]
    fn a_link_repaints_the_whole_row_so_a_shorter_one_cannot_leave_a_tail() {
        // The regression this guards: the diff steps over the columns a forced
        // -width cell covers, so they are never compared against the previous
        // frame. A shorter link replacing a longer one left the old link's tail
        // on screen -- `github.com/serde-rs/serde` followed by `mltree`.
        let mut long = Buffer::empty(area());
        write(
            &mut long,
            area(),
            2,
            1,
            "https://example.com/one",
            "a-long-label-here",
            Style::default(),
        );

        let mut short = Buffer::empty(area());
        write(
            &mut short,
            area(),
            2,
            1,
            "https://example.com/two",
            "short",
            Style::default(),
        );

        assert_eq!(
            long.cell((2, 1)).unwrap().cell_width(),
            short.cell((2, 1)).unwrap().cell_width(),
            "both links claim the same columns, so neither can leave a tail"
        );
        assert!(
            short.cell((2, 1)).unwrap().symbol().ends_with(' '),
            "the shorter link pads out to the edge"
        );
    }

    #[test]
    fn the_padding_is_outside_the_link() {
        let mut buf = Buffer::empty(area());
        write(
            &mut buf,
            area(),
            2,
            1,
            "https://e.com",
            "e",
            Style::default(),
        );
        let symbol = buf.cell((2, 1)).unwrap().symbol().to_owned();
        let close = symbol.find(CLOSE).expect("terminated");
        assert!(
            symbol[..close].ends_with('e'),
            "only the label is inside the link: {symbol:?}"
        );
        assert!(
            symbol[close + CLOSE.len()..].chars().all(|c| c == ' '),
            "everything after the terminator is padding: {symbol:?}"
        );
    }

    #[test]
    fn the_covered_columns_record_what_the_screen_will_show() {
        // The diff steps over these while the link is present, so their only job
        // is to describe the screen for the *next* frame. Recording them blank
        // is a lie that frame believes: it compares its own spaces against them,
        // finds them equal, emits nothing, and leaves the label on screen.
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

        let covered: String = (3..9).map(|x| buf.cell((x, 1)).unwrap().symbol()).collect();
        assert_eq!(covered, "xample", "the label as the terminal will print it");
        for x in 9..20 {
            assert_eq!(
                buf.cell((x, 1)).unwrap().symbol(),
                " ",
                "padding clears column {x}"
            );
        }
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
        assert_eq!(cell.cell_width(), 5, "exactly the remaining columns");
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
}
