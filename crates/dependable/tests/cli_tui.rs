//! The interactive entry point, exercised the way CI and pipes see it.
//!
//! Every test here runs with stdout redirected to a pipe, so the binary is never
//! attached to a terminal. That is exactly the situation these tests exist to
//! pin down: the whole existing test suite depends on piped stdout behaving as it
//! always has, and a TUI that starts anyway would corrupt all of it.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

#[test]
fn a_bare_invocation_still_prints_help_to_stderr_and_exits_2() {
    let out = run(&[]);

    assert_eq!(
        out.status.code(),
        Some(2),
        "the exit code scripts already depend on must not change"
    );
    assert!(
        out.stdout.is_empty(),
        "help must never reach stdout, which callers read as data: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Usage: dependable"), "{stderr}");
    assert!(stderr.contains("check"), "{stderr}");
}

#[test]
fn a_bare_invocation_emits_no_terminal_escape_codes() {
    // If the UI started here it would write escape sequences into the pipe.
    let out = run(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains('\u{1b}'),
        "no escape sequences may be written when not attached to a terminal"
    );
}

#[test]
fn the_tui_subcommand_refuses_a_pipe_instead_of_hanging() {
    let out = run(&["tui"]);

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "nothing may be written to stdout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a terminal"), "{stderr}");
    assert!(
        !stderr.contains('\u{1b}'),
        "raw mode must not have been entered: {stderr}"
    );
}

#[test]
fn the_tui_subcommand_is_documented_in_help() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tui"), "{stdout}");
}

#[test]
fn the_other_subcommands_still_work() {
    // Making the subcommand optional must not have changed how they parse.
    for args in [
        vec!["tree", "--help"],
        vec!["check", "--help"],
        vec!["list", "--help"],
        vec!["fix", "--help"],
    ] {
        let out = run(&args);
        assert!(out.status.success(), "{args:?} failed");
    }
}

#[test]
fn an_unknown_subcommand_is_still_an_error() {
    // An optional subcommand must not turn a typo into a silent UI launch.
    let out = run(&["chekc"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized") || stderr.contains("unexpected"),
        "{stderr}"
    );
}
