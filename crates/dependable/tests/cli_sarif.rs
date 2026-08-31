//! End-to-end: `dependable check --format sarif` emits a SARIF v2.1.0 log.
//!
//! Hermetic. The fixture's only dependency is a `path = "..."` one, which is a
//! `Local` item and so fails `Item::is_checkable()` — no registry request is ever
//! made — and `--no-vuln` skips OSV. Nothing here touches the network.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// A manifest whose sole dependency is local, so the check resolves entirely
/// offline and the SARIF log is a valid, empty-result document.
const CARGO_TOML: &str = "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\nhelper = { path = \"helper\" }\n";

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

fn check_sarif(dir: &std::path::Path) -> std::process::Output {
    run(&[
        "check",
        dir.to_str().unwrap(),
        "--format",
        "sarif",
        "--no-vuln",
    ])
}

#[test]
fn check_format_sarif_emits_a_valid_log() {
    let dir = workdir("sarif_check");
    fs::write(dir.join("Cargo.toml"), CARGO_TOML).unwrap();

    let output = check_sarif(&dir);
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "expected exit 0; stderr: {stderr}");

    // stdout holds the document and nothing else — no table, no summary line.
    let log: Value = serde_json::from_str(&stdout).expect("stdout is a single JSON document");

    assert_eq!(log["version"], "2.1.0");
    assert!(
        log["$schema"]
            .as_str()
            .expect("a $schema")
            .ends_with("sarif-schema-2.1.0.json")
    );
    let runs = log["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 1);

    let driver = &runs[0]["tool"]["driver"];
    assert_eq!(driver["name"], "dependable");
    let rules = driver["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["id"], "DEP001");
    assert_eq!(rules[1]["id"], "DEP002");

    // `results` must be present even with nothing to report: an absent `results`
    // means the run produced none because it failed.
    assert!(
        runs[0].get("results").is_some(),
        "`results` must always be emitted"
    );
    assert!(
        runs[0]["results"]
            .as_array()
            .expect("results is an array")
            .is_empty(),
        "the fixture's only dependency is local, so nothing is reported"
    );
}

#[test]
fn sarif_output_is_byte_deterministic() {
    let dir = workdir("sarif_deterministic");
    fs::write(dir.join("Cargo.toml"), CARGO_TOML).unwrap();

    let first = check_sarif(&dir);
    let second = check_sarif(&dir);

    assert!(first.status.success());
    assert_eq!(
        first.stdout, second.stdout,
        "no timestamp is serialized, so two runs over one tree agree byte for byte"
    );
}

#[test]
fn sarif_is_offered_for_check_and_rejected_for_list() {
    let help = run(&["check", "--help"]);
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(
        help_text.contains("sarif"),
        "`check --help` should advertise sarif; got: {help_text}"
    );

    let list_help = run(&["list", "--help"]);
    let list_help_text = String::from_utf8_lossy(&list_help.stdout);
    assert!(
        !list_help_text.contains("sarif"),
        "`list --help` must not advertise a format it cannot emit; got: {list_help_text}"
    );

    let rejected = run(&["list", ".", "--format", "sarif"]);
    assert!(
        !rejected.status.success(),
        "`list --format sarif` must be a clap error, not a silent fallback"
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("sarif"),
        "the clap error should name the invalid value; got: {stderr}"
    );
}
