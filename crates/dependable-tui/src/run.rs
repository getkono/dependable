//! The event loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dependable_fetch::Checker;
use ratatui::crossterm::event::{self, Event};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::app::{Action, App, Mode};
use crate::data::{self, Message};
use crate::model::{PackageData, PackageKey};
use crate::{TuiError, terminal, ui};

/// How long the selection must sit still before its data is requested.
///
/// Holding a cursor key scrolls through dozens of rows a second; without this,
/// every one of them would start a request nothing will ever display.
const SETTLE: Duration = Duration::from_millis(180);

/// How long to wait for a key before redrawing anyway, so in-flight results and
/// terminal resizes appear promptly.
const TICK: Duration = Duration::from_millis(100);

/// How the UI was asked to start.
#[derive(Debug, Clone)]
pub struct TuiOptions {
    /// Directory to scan.
    pub path: PathBuf,
    /// How many directories deep to search for manifests.
    pub depth: usize,
}

/// Run the UI until the user quits.
///
/// # Errors
/// Returns [`TuiError`] if the terminal cannot be configured or drawn to.
pub async fn run(options: TuiOptions, checker: Arc<Checker>) -> Result<(), TuiError> {
    // Refuse before touching raw mode. On Unix crossterm can put `/dev/tty` into
    // raw mode even when our own stdout is a pipe, which would swallow the
    // caller's keystrokes and write escape codes into whatever is reading us.
    if !is_terminal() {
        return Err(TuiError::NotATerminal);
    }

    let (tx, rx) = mpsc::unbounded_channel();
    spawn_discovery(&options, tx.clone());

    let mut terminal = terminal::enter()?;
    // Restore the terminal on every exit path, not just the happy one.
    let outcome = event_loop(&mut terminal, checker, tx, rx).await;
    let restored = terminal::restore();
    outcome.and(restored.map_err(TuiError::from))
}

/// Whether both ends are attached to a terminal.
fn is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Discover projects off the render thread: it reads the filesystem, which on a
/// large tree is long enough to be felt.
fn spawn_discovery(options: &TuiOptions, tx: UnboundedSender<Message>) {
    let (path, depth) = (options.path.clone(), options.depth);
    tokio::task::spawn_blocking(move || {
        let (projects, notices) = data::discover_projects(&path, depth);
        for notice in notices {
            let _ = tx.send(Message::Notice(notice));
        }
        let _ = tx.send(Message::Projects(projects));
    });
}

/// Read keys, apply actions, request data, draw. Never awaits the network.
async fn event_loop(
    terminal: &mut terminal::Tui,
    checker: Arc<Checker>,
    tx: UnboundedSender<Message>,
    mut rx: UnboundedReceiver<Message>,
) -> Result<(), TuiError> {
    let mut app = App::new(Vec::new());
    let mut loading = true;
    let mut pending: Option<(PackageKey, std::time::Instant)> = None;
    // Only redraw when something actually changed: an idle UI should cost nothing.
    let mut dirty = true;
    // Where the last frame put the panes and rows, for resolving pointer events.
    let mut geometry = ui::Geometry::default();

    loop {
        if dirty {
            terminal.draw(|frame| {
                if loading && app.projects.is_empty() {
                    app.message = Some("scanning for projects…".to_owned());
                }
                geometry = ui::draw(frame, &mut app);
            })?;
            dirty = false;
        }

        if app.quit {
            return Ok(());
        }

        // Drain everything the background tasks have finished.
        while let Ok(message) = rx.try_recv() {
            dirty = true;
            match message {
                Message::Projects(projects) => {
                    app = App::new(projects);
                    loading = false;
                }
                Message::Package(key, data) => app.set_data(key, data),
                Message::Notice(text) => app.message = Some(text),
            }
        }

        // Start the lookup for a selection that has settled.
        if let Some((key, since)) = pending.clone()
            && since.elapsed() >= SETTLE
        {
            pending = None;
            if !app.packages.contains_key(&key) {
                app.set_data(key.clone(), PackageData::Loading);
                data::spawn_lookup(Arc::clone(&checker), key, tx.clone());
                dirty = true;
            }
        }

        // Blocking reads happen on this thread, but only for a tick at a time, so
        // results and resizes still surface promptly.
        if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key) => {
                    if let Some(action) = crate::event::action_for(key, app.mode) {
                        let quitting = action == Action::Quit;
                        app.apply(action);
                        if quitting {
                            return Ok(());
                        }
                        dirty = true;
                    }
                }
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }

        // Queue the current selection if nothing is known about it yet.
        if app.mode != Mode::Help
            && let Some(key) = app.selected_key()
            && !app.packages.contains_key(&key)
            && pending.as_ref().is_none_or(|(k, _)| *k != key)
        {
            pending = Some((key, std::time::Instant::now()));
        }
    }
}
