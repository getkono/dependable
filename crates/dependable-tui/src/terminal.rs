//! Terminal lifecycle: raw mode, the alternate screen, and getting out of both.
//!
//! A TUI that panics with raw mode still enabled leaves the user with a shell that
//! does not echo, so restoration is installed as a panic hook *before* the terminal
//! is ever put into raw mode, and runs again on every ordinary exit path.

use std::io::{self, Stdout, Write};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// The terminal this UI draws to.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Enter raw mode and the alternate screen, installing a panic hook that undoes
/// both first.
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
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

/// Leave the alternate screen and raw mode.
///
/// # Errors
/// Returns the underlying IO error if the terminal cannot be restored.
pub fn restore() -> io::Result<()> {
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    stdout.flush()
}
