//! The interactive terminal UI for exploring a project's dependencies.
//!
//! `dependable` opens this when it is run in a terminal with no subcommand. It
//! renders the resolved dependency forest for every project it discovers, lets the
//! user descend into sub-dependencies as far as the graph goes, and shows each
//! package's public metadata, freshness, and known vulnerabilities.
//!
//! # Design
//!
//! The tree is built **offline** from lockfiles, so it appears instantly. Network
//! data is fetched only for the package that is actually selected, and cached, so
//! browsing a large workspace costs a request per package looked at rather than one
//! per package present.
//!
//! [`app::App`] holds all the state and is free of IO and of ratatui, so navigation,
//! expansion, and search are unit-testable without a terminal.

pub mod app;
pub mod data;
pub mod event;
pub mod filter;
pub mod model;
pub mod open;
pub mod rows;
pub mod run;
pub mod spinner;
pub mod terminal;
pub mod theme;
pub mod ui;
pub mod url;

pub use run::{TuiOptions, run};

/// An error that stopped the UI.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TuiError {
    /// The terminal could not be configured or drawn to.
    #[error("terminal error: {0}")]
    Io(#[from] std::io::Error),
    /// There is no terminal to draw on.
    #[error(
        "not a terminal: the interactive UI needs stdin and stdout attached to \
         one. Use `dependable check`, `list`, or `tree` for piped or CI output."
    )]
    NotATerminal,
}
