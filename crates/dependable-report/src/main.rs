//! The `dependable-report` binary.
//!
//! Its eventual job is to render a report from the JSON that
//! `dependable check --format json` writes, so CI can produce an HTML or SARIF
//! artifact from a check that already ran, without re-fetching anything.
//!
//! Nothing is rendered yet: the crate is a scaffold, so this reports that and
//! exits `2` (the CLI's "could not do the job" code), leaving stdout empty so a
//! pipeline reading it as data never receives a message instead.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "dependable-report v{} is a scaffold.",
        dependable_report::VERSION
    );
    eprintln!("error: report rendering is not implemented yet");
    ExitCode::from(2)
}
