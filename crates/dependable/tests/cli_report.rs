//! The scaffolded `report` subcommand, and the surface it must not disturb.
//!
//! `report` is registered but hidden, and it fails loudly. These tests pin both:
//! that invoking it is an honest error rather than a silent success, and that it
//! stays off the help screen until it can actually render something.
#![cfg(feature = "report")]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

fn version() -> &'static str {
    // The workspace keeps every crate's version in lockstep, so the CLI's own
    // version is the version the message names.
    env!("CARGO_PKG_VERSION")
}

#[test]
fn report_fails_loudly_instead_of_pretending_to_render() {
    let out = run(&["report"]);

    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "stdout is where a report would go; a scaffold must leave it empty: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not implemented yet"), "{stderr}");
    assert!(stderr.contains(version()), "{stderr}");
}

#[test]
fn report_with_a_path_behaves_the_same_and_echoes_it() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let out = run(&["report", dir]);

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "nothing may reach stdout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not implemented yet"), "{stderr}");
    assert!(stderr.contains("fixtures"), "{stderr}");
}

#[test]
fn report_is_not_advertised_on_the_help_screen() {
    // Releases are cut from `master`, so a command that cannot do its job must
    // not appear in help — while the commands that do work still must.
    let out = run(&["--help"]);

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for command in ["check", "list", "tree", "fix", "tui"] {
        assert!(stdout.contains(command), "`{command}` vanished: {stdout}");
    }
    assert!(
        !stdout.contains("report"),
        "the scaffolded command must stay hidden: {stdout}"
    );
}

#[test]
fn report_still_parses_its_own_arguments() {
    let out = run(&["report", "--help"]);

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--verbose"), "{stdout}");
}
