//! `dependable` — check dependency versions and known vulnerabilities.

use std::process::ExitCode;

use clap::Parser;

mod cli;
mod config;
mod discover;
mod fix;
mod output;
mod runner;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose());

    let result = match cli.command {
        Command::Check(args) => runner::run_check(args).await,
        Command::List(args) => runner::run_list(args).await,
        Command::Tree(args) => runner::run_tree(args),
        Command::Fix(args) => runner::run_fix(args).await,
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
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
