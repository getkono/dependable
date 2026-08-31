//! End-to-end behaviour of the `report` subcommand.
//!
//! `report` renders one self-contained HTML document. These tests pin where that
//! document goes (stdout by default, a file with `--output`), that the command is
//! advertised on the help screen now that it can do its job, and that a template
//! override which is unknown or malformed is a hard error rather than a silent
//! fall back to the built-in.
//!
//! Hermetic: every rendering test points at a temporary tree whose only manifest
//! belongs to an ecosystem the supplied config disables, so the skip happens at
//! the in-memory registry lookup, before any network access.
#![cfg(feature = "report")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

/// An Elixir manifest plus a config disabling Elixir: discovery finds it, the
/// checker declines it, and nothing touches the network.
const MIX_EXS: &str = "defmodule Sample.MixProject do\n  use Mix.Project\n  defp deps do\n    [{:phoenix, \"~> 1.7\"}]\n  end\nend\n";
const DISABLE_ELIXIR: &str = "[elixir]\nenabled = false\n";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create the work directory");
    dir
}

/// A tree with one manifest whose ecosystem the config turns off.
fn hermetic_tree(name: &str) -> (PathBuf, PathBuf) {
    let dir = workdir(name);
    fs::write(dir.join("mix.exs"), MIX_EXS).expect("write mix.exs");
    let config = dir.join("dependable.toml");
    fs::write(&config, DISABLE_ELIXIR).expect("write the config");
    (dir, config)
}

#[test]
fn report_writes_a_document_to_stdout() {
    let (dir, config) = hermetic_tree("report_stdout");

    let out = run(&[
        "report",
        dir.to_str().expect("a UTF-8 path"),
        "--config",
        config.to_str().expect("a UTF-8 path"),
        "--no-vuln",
    ]);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.starts_with("<!doctype html>"), "{stdout}");
    assert!(stdout.contains("</html>"), "{stdout}");
    assert!(stdout.contains("1. Executive summary"), "{stdout}");
    // The skip reached the document, not only the console.
    assert!(stdout.contains("Skipped mix.exs"), "{stdout}");
}

#[test]
fn report_output_flag_writes_a_file_and_leaves_stdout_empty() {
    let (dir, config) = hermetic_tree("report_output_file");
    let target = dir.join("report.html");

    let out = run(&[
        "report",
        dir.to_str().expect("a UTF-8 path"),
        "--config",
        config.to_str().expect("a UTF-8 path"),
        "--no-vuln",
        "--output",
        target.to_str().expect("a UTF-8 path"),
    ]);

    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stdout.is_empty(),
        "stdout must stay clean when --output is given"
    );
    let written = fs::read_to_string(&target).expect("the report file");
    assert!(written.starts_with("<!doctype html>"), "{written}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("wrote"), "{stderr}");
}

#[test]
fn report_on_a_tree_with_no_manifests_says_so_and_exits_zero() {
    let dir = workdir("report_no_manifests");

    let out = run(&["report", dir.to_str().expect("a UTF-8 path")]);

    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stdout.is_empty(),
        "nothing to report, nothing on stdout"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("No supported manifests found."), "{stderr}");
}

#[test]
fn report_rejects_an_unknown_template_override_name() {
    let (dir, config) = hermetic_tree("report_unknown_override");
    let templates = dir.join("dependable-templates");
    fs::create_dir_all(&templates).expect("create the override directory");
    fs::write(templates.join("sections.html"), "<p>mine</p>").expect("write the override");

    let out = run(&[
        "report",
        dir.to_str().expect("a UTF-8 path"),
        "--config",
        config.to_str().expect("a UTF-8 path"),
        "--no-vuln",
    ]);

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "a rejected override renders nothing");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("sections.html"), "{stderr}");
    assert!(stderr.contains("report.html"), "the valid set: {stderr}");
    assert!(
        stderr.contains("ecosystems.html"),
        "the valid set: {stderr}"
    );
}

#[test]
fn report_ignores_unrelated_files_in_the_override_directory() {
    let (dir, config) = hermetic_tree("report_override_readme");
    let templates = dir.join("dependable-templates");
    fs::create_dir_all(&templates).expect("create the override directory");
    fs::write(templates.join("README.md"), "how to theme this report").expect("write the README");

    let out = run(&[
        "report",
        dir.to_str().expect("a UTF-8 path"),
        "--config",
        config.to_str().expect("a UTF-8 path"),
        "--no-vuln",
    ]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "a README is ignored, not rejected: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn report_rejects_a_malformed_template_override() {
    let (dir, config) = hermetic_tree("report_malformed_override");
    let templates = dir.join("dependable-templates");
    fs::create_dir_all(&templates).expect("create the override directory");
    fs::write(templates.join("summary.html"), "{% for x in %}").expect("write the override");

    let out = run(&[
        "report",
        dir.to_str().expect("a UTF-8 path"),
        "--config",
        config.to_str().expect("a UTF-8 path"),
        "--no-vuln",
    ]);

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "no half-rendered document");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("summary.html"), "{stderr}");
    assert!(
        !stderr.contains("Executive summary"),
        "a broken override must not silently fall back to the built-in: {stderr}"
    );
}

#[test]
fn report_uses_a_supplied_styles_override() {
    let (dir, config) = hermetic_tree("report_styles_override");
    let templates = dir.join("dependable-templates");
    fs::create_dir_all(&templates).expect("create the override directory");
    fs::write(
        templates.join("styles.css"),
        "body { color: rebeccapurple }",
    )
    .expect("write the override");

    let out = run(&[
        "report",
        dir.to_str().expect("a UTF-8 path"),
        "--config",
        config.to_str().expect("a UTF-8 path"),
        "--no-vuln",
    ]);

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("body { color: rebeccapurple }"), "{stdout}");
    assert!(
        !stdout.contains("--accent"),
        "the built-in CSS must be replaced"
    );
}

#[test]
fn report_is_advertised_on_the_help_screen() {
    // It was hidden only while it was a scaffold that could not do its job. That
    // reason has expired.
    let out = run(&["--help"]);

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for command in ["check", "list", "tree", "fix", "tui", "report"] {
        assert!(stdout.contains(command), "`{command}` vanished: {stdout}");
    }
}

#[test]
fn report_still_parses_its_own_arguments() {
    let out = run(&["report", "--help"]);

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--manifest",
        "--config",
        "--depth",
        "--no-vuln",
        "--output",
        "--quiet",
        "--verbose",
    ] {
        assert!(stdout.contains(flag), "`{flag}` is missing: {stdout}");
    }
    // The formats and gates that deliberately do not exist here.
    assert!(!stdout.contains("--format"), "HTML is the format: {stdout}");
    assert!(
        !stdout.contains("--fail-on"),
        "a report never gates a build: {stdout}"
    );
}

/// The one non-hermetic test: a real tree, real crates.io, real OSV.
#[test]
#[ignore = "hits crates.io and OSV; run with `mise run test:live`"]
fn report_renders_a_real_tree_end_to_end() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    let out = run(&["report", dir, "--depth", "2"]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("<!doctype html>"), "{stdout}");
    assert!(stdout.contains("5. Ecosystem breakdown"), "{stdout}");
}
