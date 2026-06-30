//! End-to-end: a manifest whose ecosystem has no checker yet is skipped with a
//! warning, never aborting the run. Hermetic — the unsupported manifest is
//! dropped before any network access. Uses Dart (`pubspec.yaml`), which is
//! detected but has no parser/fetcher.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const PUBSPEC: &str = "name: sample\ndependencies:\n  http: ^1.0.0\n";

fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

#[test]
fn check_skips_unsupported_manifest() {
    let dir = workdir("skip_check_dart");
    fs::write(dir.join("pubspec.yaml"), PUBSPEC).unwrap();

    let output = run(&["check", dir.to_str().unwrap(), "--no-vuln"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "expected exit 0; stderr: {stderr}");
    assert!(
        stderr.contains("skipping"),
        "expected a skip note; stderr: {stderr}"
    );
}

#[test]
fn list_skips_unsupported_manifest() {
    let dir = workdir("skip_list_dart");
    fs::write(dir.join("pubspec.yaml"), PUBSPEC).unwrap();

    let output = run(&["list", dir.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "expected exit 0; stderr: {stderr}");
    assert!(
        stderr.contains("skipping"),
        "expected a skip note; stderr: {stderr}"
    );
}
