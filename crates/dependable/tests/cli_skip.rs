//! End-to-end: a manifest whose ecosystem is disabled in config is skipped with a
//! warning, never aborting the run. Hermetic — the skip happens at the in-memory
//! registry lookup, before any network access. Every ecosystem now has a parser, so
//! `list` (which doesn't consult the registry) surfaces the deps instead of skipping.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

const MIX_EXS: &str = "defmodule Sample.MixProject do\n  use Mix.Project\n  defp deps do\n    [{:phoenix, \"~> 1.7\"}]\n  end\nend\n";
const DISABLE_ELIXIR: &str = "[elixir]\nenabled = false\n";

/// A fresh scratch directory no other test process can pick, named after `name`.
///
/// The directory is removed when the returned guard drops, so bind it to a named
/// variable (`_tmp`, not `_`) for the length of the test.
fn workdir(name: &str) -> (TempDir, PathBuf) {
    let tmp = tempfile::Builder::new()
        .prefix(name)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let dir = tmp.path().to_path_buf();
    (tmp, dir)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

#[test]
fn check_skips_disabled_ecosystem() {
    let (_tmp, dir) = workdir("skip_check_disabled");
    fs::write(dir.join("mix.exs"), MIX_EXS).unwrap();
    let config = dir.join("dependable.toml");
    fs::write(&config, DISABLE_ELIXIR).unwrap();

    let output = run(&[
        "check",
        dir.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--no-vuln",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "expected exit 0; stderr: {stderr}");
    assert!(
        stderr.contains("skipping"),
        "expected a skip note; stderr: {stderr}"
    );
}

#[test]
fn list_surfaces_supported_manifest() {
    let (_tmp, dir) = workdir("list_supported");
    fs::write(dir.join("mix.exs"), MIX_EXS).unwrap();

    let output = run(&["list", dir.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    // `list` never consults the registry, so the Elixir dep is surfaced, not skipped.
    assert!(
        stdout.contains("phoenix"),
        "expected deps listed; stdout: {stdout}"
    );
}
