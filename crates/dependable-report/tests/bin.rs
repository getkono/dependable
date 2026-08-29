//! The scaffolded binary, exercised the way a pipeline would invoke it.

use std::process::Command;

#[test]
fn the_binary_reports_that_it_is_a_scaffold_and_exits_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_dependable-report"))
        .output()
        .expect("run dependable-report");

    assert_eq!(
        out.status.code(),
        Some(2),
        "a scaffold must not look like a successful render"
    );
    assert!(
        out.stdout.is_empty(),
        "stdout is the report; nothing else may be written there: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(dependable_report::VERSION),
        "the version is how a user tells which scaffold they hit: {stderr}"
    );
    assert!(stderr.contains("not implemented yet"), "{stderr}");
}
