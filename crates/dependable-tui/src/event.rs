//! Translate key presses into [`Action`]s.
//!
//! Kept apart from the event loop so the whole keymap is testable without a
//! terminal, and so the bindings are readable in one place.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{Action, Direction, End, Mode};

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
        KeyCode::Char('?') => Action::ToggleHelp,
        _ => return None,
    })
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
}
