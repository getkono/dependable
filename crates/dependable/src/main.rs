//! `dependable` — check dependency versions and known vulnerabilities.

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

mod cli;
mod config;
mod fix;
mod output;
mod runner;

use cli::{Cli, Command, TuiArgs};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    // The UI owns the screen: a tracing subscriber writing to stderr would draw
    // straight over the alternate screen, so it is not installed on that path.
    if !matches!(cli.command, Some(Command::Tui(_))) && cli.command.is_some() {
        init_tracing(cli.verbose());
    }

    let result = match cli.command {
        Some(Command::Check(args)) => runner::run_check(args).await,
        Some(Command::List(args)) => runner::run_list(args).await,
        Some(Command::Tree(args)) => runner::run_tree(args),
        Some(Command::Fix(args)) => runner::run_fix(args).await,
        Some(Command::Tui(args)) => runner::run_tui(args).await,
        #[cfg(feature = "report")]
        Some(Command::Report(args)) => runner::run_report(args),
        // A bare `dependable` opens the UI, but only where there is a user to
        // drive it. Piped or in CI it must behave exactly as it always has.
        None if interactive() => runner::run_tui(TuiArgs::default()).await,
        None => return usage(),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

/// Whether this process is attached to a terminal a person is actually using.
///
/// Both ends must be a TTY: output alone being a terminal is not enough, because
/// the UI is driven by keystrokes it could not receive with stdin redirected.
/// `TERM=dumb` is honored as the conventional way to say "no cursor addressing",
/// and it is what many editors set for their embedded shells.
fn interactive() -> bool {
    use std::io::IsTerminal;

    // `TERM` is routinely unset on Windows, so only an explicit `dumb` counts
    // against us; absence says nothing either way.
    let dumb = std::env::var("TERM").is_ok_and(|term| term == "dumb");
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && !dumb
}

/// Print the long help to stderr and exit 2 — what a bare `dependable` did before
/// the UI existed, preserved for pipes, scripts, and CI.
fn usage() -> ExitCode {
    // Stderr, not stdout: this is the "you did not say what to do" path, and
    // anything reading our stdout must not receive a help screen as data.
    eprint!("{}", Cli::command().render_long_help());
    ExitCode::from(2)
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let default = if verbose {
        "dependable=debug,dependable_fetch=debug"
    } else {
        "warn"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
