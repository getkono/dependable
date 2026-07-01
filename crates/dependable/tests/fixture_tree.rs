//! End-to-end: `dependable tree` over a committed workspace fixture. Fully
//! offline — the graph comes from the fixture's `Cargo.lock`. Piped stdout is
//! not a TTY, so labels are plain (uncolored) and assertable as text.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-workspace")
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

#[test]
fn tree_distinguishes_workspace_and_external() {
    let out = run(&["tree", fixture().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Workspace members are tagged; external crates are not.
    assert!(stdout.contains("app v0.1.0 (workspace)"), "{stdout}");
    assert!(stdout.contains("util v0.1.0 (workspace)"), "{stdout}");
    assert!(stdout.contains("leftpad v1.2.0"), "{stdout}");
    assert!(!stdout.contains("leftpad v1.2.0 (workspace)"), "{stdout}");
    // Git dependency is tagged.
    assert!(stdout.contains("gitdep v0.3.0 (git)"), "{stdout}");
    // The inter-member edge app -> util is present, and leftpad (shared by app
    // and util) is collapsed on its second appearance.
    assert!(
        stdout.contains("├── util") || stdout.contains("└── util"),
        "{stdout}"
    );
    assert!(stdout.contains("(*)"), "expected a dedupe marker; {stdout}");
}

#[test]
fn invert_shows_downstream_dependents() {
    // Who depends on leftpad? Both util and app (transitively).
    let out = run(&[
        "tree",
        fixture().to_str().unwrap(),
        "--invert",
        "-p",
        "leftpad",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("leftpad v1.2.0"), "{stdout}");
    assert!(stdout.contains("util"), "{stdout}");
    assert!(stdout.contains("app"), "{stdout}");
}

#[test]
fn depth_limit_truncates() {
    let out = run(&["tree", fixture().to_str().unwrap(), "--depth", "0"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    // Roots only: members appear, their dependencies do not.
    assert!(stdout.contains("app v0.1.0 (workspace)"), "{stdout}");
    assert!(!stdout.contains("leftpad"), "{stdout}");
}

#[test]
fn json_format_emits_graph() {
    let out = run(&["tree", fixture().to_str().unwrap(), "--format", "json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("\"kind\": \"workspace\""), "{stdout}");
    assert!(stdout.contains("\"kind\": \"git\""), "{stdout}");
    assert!(stdout.contains("\"edges\""), "{stdout}");
}
