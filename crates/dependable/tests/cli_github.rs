//! End-to-end: the GitHub Actions side channels — annotations on **stderr** and
//! the job summary — behave the way a workflow needs them to.
//!
//! Hermetic, and instantly so. The fixture points the Rust registry at
//! `http://127.0.0.1:1`, where the connection is refused immediately rather than
//! timing out, and a registry failure becomes a per-dependency
//! `DependencyStatus::Error` rather than aborting the run. Every dependency
//! therefore lands as a `::notice` without a byte leaving the machine.
//!
//! **Hermeticity trap:** this suite may itself be running inside GitHub Actions,
//! where `GITHUB_ACTIONS` and `GITHUB_STEP_SUMMARY` are already set — a leaked
//! `GITHUB_STEP_SUMMARY` would append to the real job summary. Every child
//! process below therefore removes all three variables before setting whatever
//! it means to set. `env_clear()` is deliberately *not* used: it would strip
//! `PATH` and `HOME`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Two registry dependencies, on known lines: `serde` is line 6 and `tokio`
/// line 7, one-based, which is what the annotations must report.
const CARGO_TOML: &str = "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\ntokio = \"1.20\"\n";

/// A registry nothing is listening on: `connect` fails at once.
const CONFIG: &str = "[rust]\nregistry = \"http://127.0.0.1:1\"\n";

fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("Cargo.toml"), CARGO_TOML).unwrap();
    fs::write(dir.join(".dependable.toml"), CONFIG).unwrap();
    dir
}

/// A `dependable check` over `dir` with the ambient GitHub variables cleared,
/// then `env` applied on top.
fn check(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let config = dir.join(".dependable.toml");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependable"));
    command
        .arg("check")
        .arg(dir)
        .arg("--config")
        .arg(&config)
        .args(["--no-vuln", "--no-cache"])
        .args(args)
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITHUB_WORKSPACE")
        .env_remove("GITHUB_STEP_SUMMARY");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().expect("run dependable")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn annotations_ride_stderr_so_stdout_stays_one_json_document() {
    let dir = workdir("github_json_and_annotations");
    let output = check(
        &dir,
        &["--format", "json", "--annotations", "always"],
        &[("GITHUB_WORKSPACE", dir.to_str().unwrap())],
    );

    let stdout = String::from_utf8(output.stdout.clone()).expect("utf-8 stdout");
    let stderr = stderr_of(&output);

    // This is the whole design in one assertion: the document parses *and* the
    // annotations were emitted.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is a single JSON document");
    assert_eq!(parsed["summary"]["error"], 2, "{stdout}");
    assert!(
        !stdout.contains("::notice"),
        "stdout carried a command: {stdout}"
    );
    assert!(
        stderr.contains("::notice "),
        "no annotation on stderr: {stderr}"
    );
}

#[test]
fn annotations_carry_a_repo_relative_file_and_a_one_based_line() {
    let dir = workdir("github_annotation_shape");
    let output = check(
        &dir,
        &["--annotations", "always"],
        &[("GITHUB_WORKSPACE", dir.to_str().unwrap())],
    );
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("::notice file=Cargo.toml,line=6,endLine=6,"),
        "serde is on line 6: {stderr}"
    );
    assert!(
        stderr.contains("::notice file=Cargo.toml,line=7,endLine=7,"),
        "tokio is on line 7: {stderr}"
    );
    // Byte offsets are not character columns, so no column is ever claimed.
    assert!(!stderr.contains("col="), "{stderr}");
    assert!(!stderr.contains("endColumn="), "{stderr}");
    // `:` is escaped in the property and left alone in the message.
    assert!(stderr.contains("title=dependable%3A "), "{stderr}");
    assert!(stderr.contains("could not be checked: "), "{stderr}");
}

#[test]
fn never_silences_every_command() {
    let dir = workdir("github_never");
    let output = check(
        &dir,
        &["--annotations", "never"],
        &[("GITHUB_ACTIONS", "true")],
    );
    let stderr = stderr_of(&output);
    assert!(!stderr.contains("::"), "{stderr}");
}

#[test]
fn auto_is_off_when_the_runner_is_not_present() {
    let dir = workdir("github_auto_off");
    let output = check(&dir, &[], &[]);
    let stderr = stderr_of(&output);
    assert!(!stderr.contains("::"), "{stderr}");
}

#[test]
fn auto_is_on_under_the_runner() {
    let dir = workdir("github_auto_on");
    let output = check(&dir, &[], &[("GITHUB_ACTIONS", "true")]);
    let stderr = stderr_of(&output);
    assert!(stderr.contains("::notice "), "{stderr}");
}

#[test]
fn the_step_summary_is_written_and_appended_to() {
    let dir = workdir("github_summary");
    let summary = dir.join("summary.md");
    let env = [
        ("GITHUB_WORKSPACE", dir.to_str().unwrap()),
        ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
    ];

    let first = check(&dir, &["--annotations", "always"], &env);
    assert!(first.status.success(), "{}", stderr_of(&first));
    let once = fs::read_to_string(&summary).expect("a summary file");
    assert!(once.contains("## dependable"), "{once}");
    assert!(once.contains("2 dependencies checked"), "{once}");
    assert!(once.contains("### Errors (2)"), "{once}");

    // Appending, not clobbering: two runs in one step concatenate.
    check(&dir, &["--annotations", "always"], &env);
    let twice = fs::read_to_string(&summary).expect("a summary file");
    assert!(twice.len() > once.len());
    assert_eq!(twice.matches("## dependable").count(), 2, "{twice}");
}

#[test]
fn the_summary_is_not_written_when_annotations_are_off() {
    let dir = workdir("github_summary_never");
    let summary = dir.join("summary.md");
    check(
        &dir,
        &["--annotations", "never"],
        &[("GITHUB_STEP_SUMMARY", summary.to_str().unwrap())],
    );
    assert!(
        !summary.exists(),
        "the single off-switch must cover the summary too"
    );
}

#[test]
fn an_unwritable_summary_warns_without_changing_the_exit_code() {
    let dir = workdir("github_summary_unwritable");
    // A directory, so opening it for append fails.
    let blocked = dir.join("blocked");
    fs::create_dir_all(&blocked).unwrap();

    let clean = check(&dir, &["--annotations", "always"], &[]);
    let broken = check(
        &dir,
        &["--annotations", "always"],
        &[("GITHUB_STEP_SUMMARY", blocked.to_str().unwrap())],
    );

    assert_eq!(clean.status.code(), broken.status.code());
    assert_eq!(broken.status.code(), Some(0));
    let stderr = stderr_of(&broken);
    assert!(
        stderr.contains("warning: could not write GitHub step summary"),
        "{stderr}"
    );
    // Still annotated: one side channel failing must not take the other down.
    assert!(stderr.contains("::notice "), "{stderr}");
}

#[test]
fn annotations_do_not_move_the_exit_code() {
    let dir = workdir("github_exit_codes");
    let lenient = check(
        &dir,
        &["--annotations", "always", "--fail-on", "none"],
        &[("GITHUB_WORKSPACE", dir.to_str().unwrap())],
    );
    let strict = check(
        &dir,
        &["--annotations", "always", "--fail-on", "any"],
        &[("GITHUB_WORKSPACE", dir.to_str().unwrap())],
    );

    assert_eq!(lenient.status.code(), Some(0));
    assert_eq!(strict.status.code(), Some(1));
    // Identical findings either way: the level is independent of the gate.
    assert_eq!(stderr_of(&lenient), stderr_of(&strict));
}

#[test]
fn quiet_empties_stdout_but_keeps_the_annotations() {
    let dir = workdir("github_quiet");
    let output = check(
        &dir,
        &["--quiet", "--annotations", "always"],
        &[("GITHUB_WORKSPACE", dir.to_str().unwrap())],
    );

    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    // `-q` means "only print errors", and the annotations *are* the errors.
    assert!(stderr_of(&output).contains("::notice "));
}

/// A `Package.swift` is a Swift program, so it declares nothing readable. The
/// pins are the dependency list, and every versioned one is `Undetermined`:
/// Swift publishes no registry, so no currency can be established for any of them.
const PACKAGE_SWIFT: &str = "// swift-tools-version:5.10\nimport PackageDescription\n\nlet package = Package(name: \"SampleApp\")\n";

/// Two `remoteSourceControl` pins carrying versions — two `Undetermined` rows,
/// and not one row of any other status.
const PACKAGE_RESOLVED: &str = r#"{
  "pins" : [
    {
      "identity" : "swift-nio",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/apple/swift-nio.git",
      "state" : { "revision" : "635b2589494c97e48c62514bc8b37ced762e0a62", "version" : "2.65.0" }
    },
    {
      "identity" : "swift-log",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/apple/swift-log.git",
      "state" : { "revision" : "9cb486020ebf03bfa5b5df985387a14a98744537", "version" : "1.5.4" }
    }
  ],
  "version" : 2
}"#;

/// A Swift project, with a `Package.resolved` beside it only when `resolved` says so.
///
/// Deliberately *not* [`workdir`]: a `Cargo.toml` in the same directory would
/// contribute rows of its own and the counts below would stop meaning anything.
fn swift_workdir(name: &str, resolved: bool) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("Package.swift"), PACKAGE_SWIFT).unwrap();
    if resolved {
        fs::write(dir.join("Package.resolved"), PACKAGE_RESOLVED).unwrap();
    }
    fs::write(dir.join(".dependable.toml"), CONFIG).unwrap();
    dir
}

/// The undetermined case: the pins were read, and not one of them could be
/// checked for a newer version.
///
/// Every one is `Undetermined`, a status the renderer does not annotate, so no
/// table is built — and an empty table set used to reach the all-clear line. That
/// line is the same false claim of currency the table heading, the HTML report,
/// `manifests_unread` in JSON and `DEP003` in SARIF were all changed to stop
/// making; the job summary is the one a pull request actually renders.
#[test]
fn the_summary_never_calls_an_undetermined_swift_project_clean() {
    let dir = swift_workdir("github_swift_undetermined", true);
    let summary = dir.join("summary.md");
    let output = check(
        &dir,
        &["--annotations", "always"],
        &[
            ("GITHUB_WORKSPACE", dir.to_str().unwrap()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let markdown = fs::read_to_string(&summary).expect("a summary file");

    assert!(
        !markdown.contains("No outdated or vulnerable dependencies found."),
        "nothing was found because nothing could be checked: {markdown}"
    );
    assert!(markdown.contains("2 dependencies checked"), "{markdown}");
    assert!(markdown.contains("2 undetermined"), "{markdown}");
    assert!(markdown.contains("**Coverage caveat**"), "{markdown}");
    assert!(
        markdown.contains("2 dependencies could not be checked for a newer version"),
        "{markdown}"
    );
}

/// The unread case, which this feature calls the common state: Apple advises a
/// library package not to commit its `Package.resolved`, so there is nothing to
/// read and the run produces no rows at all.
///
/// Worse than the undetermined case, because every status count is a tally of
/// rows that *were* read: with no rows the totals line is a row of zeros
/// identical to a project with no dependencies. Only the caveat separates them.
#[test]
fn the_summary_never_calls_an_unread_swift_project_clean() {
    let dir = swift_workdir("github_swift_unread", false);
    let summary = dir.join("summary.md");
    let output = check(
        &dir,
        &["--annotations", "always"],
        &[
            ("GITHUB_WORKSPACE", dir.to_str().unwrap()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let markdown = fs::read_to_string(&summary).expect("a summary file");
    let stderr = stderr_of(&output);

    assert!(
        !markdown.contains("No outdated or vulnerable dependencies found."),
        "a project nothing was read from must never render as a clean one: {markdown}"
    );
    assert!(markdown.contains("**Coverage caveat**"), "{markdown}");
    assert!(
        markdown.contains("The dependency list for 1 manifest could not be read"),
        "{markdown}"
    );
    // Named, the way `DEP003` names it: the fact belongs to a file.
    assert!(markdown.contains("`Package.swift`"), "{markdown}");

    // And the pull request itself hears about it. With no rows there is no
    // per-dependency annotation to emit, so without this one the annotation
    // channel is silent — which is exactly what a clean project looks like.
    assert!(
        stderr.contains(
            "::notice file=Package.swift,title=dependable%3A dependency list could not be read::"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("means nothing was looked at, not that nothing is wrong."),
        "{stderr}"
    );
}

/// The guard on the guard: gating the all-clear line must not withhold it from a
/// run that genuinely earned it.
#[test]
fn a_genuinely_clean_run_still_gets_the_all_clear() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("github_clean_all_clear");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // No dependencies at all: nothing to check, and nothing left unchecked.
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(dir.join(".dependable.toml"), CONFIG).unwrap();

    let summary = dir.join("summary.md");
    let output = check(
        &dir,
        &["--annotations", "always"],
        &[
            ("GITHUB_WORKSPACE", dir.to_str().unwrap()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let markdown = fs::read_to_string(&summary).expect("a summary file");

    assert!(
        markdown.contains("No outdated or vulnerable dependencies found."),
        "{markdown}"
    );
    assert!(!markdown.contains("Coverage caveat"), "{markdown}");
}
