//! Translate key presses into [`Action`]s.
//!
//! Kept apart from the event loop so the whole keymap is testable without a
//! terminal, and so the bindings are readable in one place.

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};

use crate::app::{Action, Direction, End, Mode};
use crate::rows::Row;
use crate::ui::Geometry;

/// How many rows one notch of the wheel moves.
///
/// Three is what most terminals and editors use; one notch moving one row makes
/// a long tree feel unscrollable.
const WHEEL_ROWS: isize = 3;

/// The action a key press means in the current mode, if any.
///
/// Returns `None` for keys with no binding, which the loop ignores.
#[must_use]
pub fn action_for(key: KeyEvent, mode: Mode) -> Option<Action> {
    // Windows reports both press and release; acting on both double-counts.
    if key.kind == KeyEventKind::Release {
        return None;
    }
    // Ctrl-C quits from anywhere, including mid-search.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
    {
        return Some(Action::Quit);
    }
    match mode {
        Mode::Search => search_key(key),
        Mode::Help => Some(match key.code {
            KeyCode::Char('q') => Action::Quit,
            _ => Action::ToggleHelp,
        }),
        Mode::Browse => browse_key(key),
    }
}

/// Keys while typing a query. Everything printable extends the query, so `q` and
/// `j` must not be read as commands here.
fn search_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::ClearSearch),
        KeyCode::Enter => Some(Action::CommitSearch),
        KeyCode::Backspace => Some(Action::SearchBackspace),
        KeyCode::Up => Some(Action::Move(-1)),
        KeyCode::Down => Some(Action::Move(1)),
        KeyCode::Char(c) => Some(Action::SearchInput(c)),
        _ => None,
    }
}

/// Keys while navigating the tree.
fn browse_key(key: KeyEvent) -> Option<Action> {
    let shifted = key.modifiers.contains(KeyModifiers::SHIFT);
    Some(match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('j') | KeyCode::Down => Action::Move(1),
        KeyCode::Char('k') | KeyCode::Up => Action::Move(-1),
        KeyCode::PageDown => Action::Move(10),
        KeyCode::PageUp => Action::Move(-10),
        KeyCode::Home => Action::JumpTo(End::Top),
        KeyCode::End => Action::JumpTo(End::Bottom),
        KeyCode::Char('g') => Action::JumpTo(End::Top),
        KeyCode::Char('G') => Action::JumpTo(End::Bottom),
        KeyCode::Right | KeyCode::Char('l') => Action::Expand,
        KeyCode::Left | KeyCode::Char('h') => Action::Collapse,
        KeyCode::Enter | KeyCode::Char(' ') => Action::Toggle,
        KeyCode::Char('/') => Action::BeginSearch,
        KeyCode::Esc => Action::ClearSearch,
        KeyCode::Char('n') if shifted => Action::CycleMatch(Direction::Backward),
        KeyCode::Char('N') => Action::CycleMatch(Direction::Backward),
        KeyCode::Char('n') => Action::CycleMatch(Direction::Forward),
        KeyCode::Char('i') => Action::ToggleInvert,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('o') => Action::OpenLink,
        KeyCode::Char('?') => Action::ToggleHelp,
        _ => return None,
    })
}

/// The action a mouse event means, if any.
///
/// Pure over the pointer position, the last frame's [`Geometry`], and the rows
/// it described, so every mapping below is testable without a terminal — the
/// same property that makes the keymap testable.
///
/// `rows` supplies each row's depth, which is what decides whether a click
/// landed on a disclosure marker or on the name beside it. `dragging` says
/// whether a divider drag is already under way: the pointer wanders well off
/// the divider mid-drag, and a drag that began in the tree must not resize.
#[must_use]
pub fn action_for_mouse(
    event: MouseEvent,
    mode: Mode,
    geometry: &Geometry,
    rows: &[Row],
    dragging: bool,
) -> Option<Action> {
    // The help overlay covers the panes, so a click behind it would act on
    // something the user cannot see.
    if mode == Mode::Help {
        return match event.kind {
            MouseEventKind::Down(MouseButton::Left) => Some(Action::ToggleHelp),
            _ => None,
        };
    }

    let (x, y) = (event.column, event.row);
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if geometry.on_divider(x, y) {
                return Some(Action::BeginDrag);
            }
            let index = geometry.row_at(x, y)?;
            // The marker is the affordance for opening a row; the name beside
            // it only selects, so a click never expands something unintended.
            let depth = rows.get(index)?.depth;
            if geometry.on_marker(x, depth) {
                Some(Action::ToggleAt(index))
            } else {
                Some(Action::Select(index))
            }
        }
        MouseEventKind::Drag(MouseButton::Left) if dragging => {
            Some(Action::SetSplit(geometry.split_at(x)))
        }
        MouseEventKind::Up(MouseButton::Left) if dragging => Some(Action::EndDrag),
        // Tracking the pointer is what tells the user a row is clickable.
        MouseEventKind::Moved => Some(Action::Hover(geometry.row_at(x, y))),
        MouseEventKind::ScrollDown => Some(Action::Move(WHEEL_ROWS)),
        MouseEventKind::ScrollUp => Some(Action::Move(-WHEEL_ROWS)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn browse_keys_navigate() {
        assert_eq!(
            action_for(press(KeyCode::Char('j')), Mode::Browse),
            Some(Action::Move(1))
        );
        assert_eq!(
            action_for(press(KeyCode::Char('G')), Mode::Browse),
            Some(Action::JumpTo(End::Bottom))
        );
        assert_eq!(
            action_for(press(KeyCode::Right), Mode::Browse),
            Some(Action::Expand)
        );
    }

    #[test]
    fn typing_in_search_is_never_read_as_a_command() {
        // `q` would quit in browse mode; while searching it must be a character.
        assert_eq!(
            action_for(press(KeyCode::Char('q')), Mode::Search),
            Some(Action::SearchInput('q'))
        );
        assert_eq!(
            action_for(press(KeyCode::Char('/')), Mode::Search),
            Some(Action::SearchInput('/'))
        );
    }

    #[test]
    fn arrows_still_move_the_selection_while_searching() {
        assert_eq!(
            action_for(press(KeyCode::Down), Mode::Search),
            Some(Action::Move(1))
        );
    }

    #[test]
    fn ctrl_c_quits_from_every_mode() {
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        for mode in [Mode::Browse, Mode::Search, Mode::Help] {
            assert_eq!(action_for(ctrl_c, mode), Some(Action::Quit), "{mode:?}");
        }
    }

    #[test]
    fn a_key_release_is_ignored() {
        // Windows delivers press and release; acting on both moves twice per key.
        let mut release = press(KeyCode::Char('j'));
        release.kind = KeyEventKind::Release;
        assert_eq!(action_for(release, Mode::Browse), None);
    }

    #[test]
    fn any_key_closes_the_help_overlay() {
        assert_eq!(
            action_for(press(KeyCode::Char('x')), Mode::Help),
            Some(Action::ToggleHelp)
        );
        assert_eq!(
            action_for(press(KeyCode::Char('q')), Mode::Help),
            Some(Action::Quit)
        );
    }

    #[test]
    fn shift_n_cycles_backwards() {
        assert_eq!(
            action_for(press(KeyCode::Char('N')), Mode::Browse),
            Some(Action::CycleMatch(Direction::Backward))
        );
        assert_eq!(
            action_for(press(KeyCode::Char('n')), Mode::Browse),
            Some(Action::CycleMatch(Direction::Forward))
        );
    }

    #[test]
    fn an_unbound_key_does_nothing() {
        assert_eq!(action_for(press(KeyCode::F(5)), Mode::Browse), None);
    }

    // --- pointer ---

    use ratatui::layout::Rect;

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
                width: 60,
                height: 12,
            },
            tree_offset: 0,
            tree_height: 9,
            row_count: 20,
        }
    }

    /// Rows at increasing depth, so marker positions differ between them.
    fn rows() -> Vec<Row> {
        (0..20)
            .map(|i| Row {
                path: vec![i],
                depth: i % 3,
                kind: crate::rows::RowKind::Package,
                project: 0,
                node: None,
                name: format!("pkg-{i}"),
                version: String::new(),
                node_kind: None,
                has_children: true,
                redirect: None,
                expanded: false,
                cyclic: false,
                matched: false,
            })
            .collect()
    }

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn click(column: u16, row: u16) -> MouseEvent {
        mouse(MouseEventKind::Down(MouseButton::Left), column, row)
    }

    #[test]
    fn clicking_a_row_selects_it() {
        // The first row is drawn at y=2, below the border and the column header.
        // Row 1 is at depth 1, so its marker is indented past column 10.
        assert_eq!(
            action_for_mouse(click(10, 3), Mode::Browse, &geometry(), &rows(), false),
            Some(Action::Select(1))
        );
    }

    #[test]
    fn clicking_the_marker_expands_rather_than_only_selecting() {
        // Row 0 is at depth 0, so its marker is the first two body columns.
        assert_eq!(
            action_for_mouse(click(1, 2), Mode::Browse, &geometry(), &rows(), false),
            Some(Action::ToggleAt(0))
        );
        // The name beside it only selects.
        assert_eq!(
            action_for_mouse(click(6, 2), Mode::Browse, &geometry(), &rows(), false),
            Some(Action::Select(0))
        );
    }

    #[test]
    fn the_marker_moves_with_the_rows_indent() {
        // Row 2 is at depth 2, so its marker sits four columns further right.
        assert_eq!(
            action_for_mouse(click(1, 4), Mode::Browse, &geometry(), &rows(), false),
            Some(Action::Select(2)),
            "the indent before a deep row is not its marker"
        );
        assert_eq!(
            action_for_mouse(click(5, 4), Mode::Browse, &geometry(), &rows(), false),
            Some(Action::ToggleAt(2))
        );
    }

    #[test]
    fn the_wheel_scrolls_several_rows_at_a_time() {
        let g = geometry();
        assert_eq!(
            action_for_mouse(
                mouse(MouseEventKind::ScrollDown, 5, 5),
                Mode::Browse,
                &g,
                &rows(),
                false
            ),
            Some(Action::Move(3))
        );
        assert_eq!(
            action_for_mouse(
                mouse(MouseEventKind::ScrollUp, 5, 5),
                Mode::Browse,
                &g,
                &rows(),
                false
            ),
            Some(Action::Move(-3))
        );
    }

    #[test]
    fn dragging_the_divider_resizes_only_once_the_drag_has_begun() {
        let g = geometry();
        // The divider is the tree's right border column.
        assert_eq!(
            action_for_mouse(click(39, 5), Mode::Browse, &g, &rows(), false),
            Some(Action::BeginDrag)
        );

        let drag = mouse(MouseEventKind::Drag(MouseButton::Left), 60, 5);
        assert_eq!(
            action_for_mouse(drag, Mode::Browse, &g, &rows(), false),
            None,
            "a drag that began in the tree must not resize"
        );
        assert_eq!(
            action_for_mouse(drag, Mode::Browse, &g, &rows(), true),
            Some(Action::SetSplit(60))
        );
        assert_eq!(
            action_for_mouse(
                mouse(MouseEventKind::Up(MouseButton::Left), 60, 5),
                Mode::Browse,
                &g,
                &rows(),
                true
            ),
            Some(Action::EndDrag)
        );
    }

    #[test]
    fn a_click_behind_the_help_overlay_closes_it_instead() {
        // The overlay covers the panes, so acting on what is behind it would
        // hit something the user cannot see.
        assert_eq!(
            action_for_mouse(click(10, 2), Mode::Help, &geometry(), &rows(), false),
            Some(Action::ToggleHelp)
        );
    }

    #[test]
    fn clicking_outside_the_tree_does_nothing() {
        let g = geometry();
        assert_eq!(
            action_for_mouse(click(70, 5), Mode::Browse, &g, &rows(), false),
            None,
            "over the detail pane"
        );
        assert_eq!(
            action_for_mouse(click(10, 0), Mode::Browse, &g, &rows(), false),
            None,
            "on the border"
        );
        assert_eq!(
            action_for_mouse(click(10, 1), Mode::Browse, &g, &rows(), false),
            None,
            "on the column header"
        );
    }

    #[test]
    fn a_click_past_the_last_row_does_nothing() {
        let short = Geometry {
            row_count: 2,
            ..geometry()
        };
        assert_eq!(
            action_for_mouse(click(10, 5), Mode::Browse, &short, &rows(), false),
            None
        );
    }

    #[test]
    fn scrolling_still_works_while_searching() {
        // The search box takes the keyboard, not the pointer.
        assert_eq!(
            action_for_mouse(
                mouse(MouseEventKind::ScrollDown, 5, 5),
                Mode::Search,
                &geometry(),
                &rows(),
                false
            ),
            Some(Action::Move(3))
        );
    }
}
