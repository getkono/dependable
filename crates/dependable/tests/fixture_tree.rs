//! End-to-end: `dependable tree` over a committed workspace fixture. Fully
//! offline — the graph comes from the fixture's `Cargo.lock`. Labels are
//! asserted as plain text, which [`run`] pins the child's environment to make
//! true rather than inferring it from the pipe.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-workspace")
}

/// `dependable` with the given arguments, its output left unstyled.
///
/// A pipe is not a TTY, so the labels come out plain by default — but that is a
/// default, not a guarantee. `FORCE_COLOR` overrides it, and the child inherits
/// whatever exported it: a terminal multiplexer, a task runner, a CI image. The
/// assertions below are about the shape of the tree rather than its colour, so
/// the environment is pinned here instead of assumed, and the tests state the
/// same thing in a coloured terminal as in a bare one.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .env_remove("FORCE_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
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
fn a_member_used_by_another_member_points_at_its_own_tree() {
    let out = run(&["tree", fixture().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());

    // Under `app`, `util` is a pointer: no second copy of its subtree.
    assert!(
        stdout.contains("└── util v0.1.0 (workspace) (see root)"),
        "{stdout}"
    );
    // And `util`'s own entry is the one that expands — it used to be the empty
    // `(*)` stub, because the first crate to reach it won the expansion.
    assert!(
        stdout.contains("util v0.1.0 (workspace)\n└── leftpad v1.2.0 (*)"),
        "{stdout}"
    );
    assert_eq!(
        stdout.matches("smallvec").count(),
        1,
        "leftpad's subtree is drawn once; {stdout}"
    );
}

#[test]
fn no_dedupe_expands_every_occurrence_in_place() {
    let out = run(&["tree", fixture().to_str().unwrap(), "--no-dedupe"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());

    assert!(!stdout.contains("(see root)"), "{stdout}");
    assert!(!stdout.contains("(*)"), "{stdout}");
    assert_eq!(
        stdout.matches("smallvec").count(),
        3,
        "under app, under app->util, and under util's own entry; {stdout}"
    );
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
