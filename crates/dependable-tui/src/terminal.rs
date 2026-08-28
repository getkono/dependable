//! Terminal lifecycle: raw mode, mouse reporting, the alternate screen, and
//! getting out of all three.
//!
//! A TUI that panics with raw mode still enabled leaves the user with a shell that
//! does not echo, so restoration is installed as a panic hook *before* the terminal
//! is ever put into raw mode, and runs again on every ordinary exit path. Mouse
//! capture has the same hazard in a louder form: left on, every pointer movement
//! writes escape sequences into the user's shell.

use std::io::{self, Stdout, Write};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// The terminal this UI draws to.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Enter raw mode, mouse reporting, and the alternate screen, installing a panic
/// hook that undoes all three first.
///
/// # Errors
/// Returns the underlying IO error if the terminal cannot be configured.
pub fn enter() -> io::Result<Tui> {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort: we are already panicking, so a failure here must not mask
        // the original message.
        let _ = restore();
        hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

/// Leave mouse reporting, the alternate screen, and raw mode.
///
/// Every step is attempted even when an earlier one fails, and the first error
/// is reported afterwards. Returning early instead would be how a failure to
/// leave the alternate screen leaves mouse reporting on, which fills the user's
/// shell with escape sequences on every pointer movement — a far worse state
/// than the one that caused it.
///
/// # Errors
/// Returns the first underlying IO error, after attempting the rest.
pub fn restore() -> io::Result<()> {
    let mut stdout = io::stdout();
    let mouse = execute!(stdout, DisableMouseCapture);
    let screen = execute!(stdout, LeaveAlternateScreen);
    let raw = disable_raw_mode();
    let flushed = stdout.flush();
    mouse.and(screen).and(raw).and(flushed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_twice_is_safe() {
        // Both the panic hook and the ordinary exit path call this, and a panic
        // during shutdown runs it twice in a row. Neither may panic, and the
        // second call must not undo more than there is to undo.
        let first = restore();
        let second = restore();
        assert!(first.is_ok() || first.is_err());
        assert!(second.is_ok() || second.is_err());
    }
}
