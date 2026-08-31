//! End-to-end: the `[policy]` block of `.dependable.toml` gates `dependable
//! check`'s exit code.
//!
//! Hermetic. The fixture declares nothing but path dependencies, so no registry
//! fetch task and no OSV query is built — yet every declared dependency still
//! yields a result for the policy engine to judge.
//!
//! Exit codes under test: `0` clean, `1` policy violation (the same code
//! `--fail-on` already produces), `2` a policy that cannot be enforced.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A denied package that the fixture actually declares.
const DENY_LEFT_PAD: &str = "[policy]\ndenied_packages = [{ name = \"left-pad\" }]\n";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-policy")
}

/// A config file of our own, so no test reads the repository's real
/// `.dependable.toml`.
fn config(name: &str, content: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create the scratch directory");
    let path = dir.join("dependable.toml");
    fs::write(&path, content).expect("write the config");
    path
}

fn check(config: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let fixture = fixture();
    let mut args = vec![
        "check",
        fixture.to_str().expect("fixture path"),
        "--config",
        config.to_str().expect("config path"),
    ];
    args.extend_from_slice(extra);
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependable"));
    command.args(&args);
    // Inherited overrides would silently change what is under test.
    for key in [
        "DEPENDABLE_NO_POLICY",
        "DEPENDABLE_MAX_CVSS",
        "DEPENDABLE_FAIL_ON_SEVERITY",
        "DEPENDABLE_MAX_MAJOR_BEHIND",
    ] {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().expect("run dependable")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("an exit code")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_denied_package_fails_the_check() {
    let config = config("policy_denied", DENY_LEFT_PAD);

    let output = check(&config, &["--no-vuln"], &[]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 1, "stderr: {stderr}");
    // The config key is in the message, so the failing line is the line to edit.
    assert!(stderr.contains("denied_packages"), "stderr: {stderr}");
    assert!(stderr.contains("left-pad"), "stderr: {stderr}");
}

#[test]
fn the_same_run_without_the_rule_passes() {
    // The control: the fixture itself is clean, so exit 1 above came from the
    // policy and nothing else.
    let config = config("policy_clean", "[policy]\ndenied_packages = []\n");

    let output = check(&config, &["--no-vuln"], &[]);

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
}

#[test]
fn a_cvss_rule_without_vulnerability_scanning_fails_fast() {
    // Every score would be `None`, so the gate would pass vacuously. That is a
    // configuration error, not a pass.
    let config = config("policy_no_vuln", "[policy]\nmax_cvss = 7.0\n");

    let output = check(&config, &["--no-vuln"], &[]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 2, "stderr: {stderr}");
    assert!(stderr.contains("max_cvss"), "stderr: {stderr}");
    assert!(stderr.contains("--no-vuln"), "stderr: {stderr}");
}

#[test]
fn a_mistyped_policy_key_fails_the_run_rather_than_disabling_the_gate() {
    let config = config("policy_typo", "[policy]\nmax_cvvs = 7.0\n");

    let output = check(&config, &["--no-vuln"], &[]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 2, "stderr: {stderr}");
    assert!(stderr.contains("max_cvvs"), "stderr: {stderr}");
}

#[test]
fn an_unknown_severity_band_fails_the_run_and_lists_the_valid_ones() {
    let config = config("policy_band", "[policy]\nfail_on_severity = \"nope\"\n");

    let output = check(&config, &["--no-vuln"], &[]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 2, "stderr: {stderr}");
    assert!(stderr.contains("critical"), "stderr: {stderr}");
}

#[test]
fn a_typo_outside_the_policy_block_is_also_an_error() {
    // This used to assert the opposite: only `[policy]` was strict, and a typo anywhere
    // else was silently dropped. That leniency was not a smaller version of the same
    // safety — it was the hole. A dropped `[global]` key resets the table it is in, so
    // one mistyped character put `fail_on` back to `none` and disarmed the CI gate,
    // with nothing on stderr to say why.
    let config = config("policy_other_typo", "[global]\nconcurrencyy = 4\n");

    let output = check(&config, &["--no-vuln"], &[]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 2, "stderr: {stderr}");
    // The message names the offending key and the ones that would have worked.
    assert!(stderr.contains("concurrencyy"), "stderr: {stderr}");
    assert!(stderr.contains("concurrency"), "stderr: {stderr}");
}

#[test]
fn the_kill_switch_disables_the_gate_without_a_flag() {
    let config = config("policy_kill_switch", DENY_LEFT_PAD);

    let output = check(&config, &["--no-vuln"], &[("DEPENDABLE_NO_POLICY", "1")]);

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
}

#[test]
fn an_environment_override_reaches_the_same_gate() {
    // No `[policy]` block at all: the rule arrives entirely from the environment,
    // and still hits the "not enforceable" precondition.
    let config = config("policy_env", "[global]\nconcurrency = 4\n");

    let output = check(&config, &["--no-vuln"], &[("DEPENDABLE_MAX_CVSS", "7.0")]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 2, "stderr: {stderr}");
    assert!(stderr.contains("max_cvss"), "stderr: {stderr}");
}

#[test]
fn an_unusable_environment_override_is_an_error_not_a_silent_no_op() {
    let config = config("policy_env_bad", "[global]\nconcurrency = 4\n");

    let output = check(
        &config,
        &["--no-vuln"],
        &[("DEPENDABLE_MAX_CVSS", "very-bad")],
    );
    let stderr = stderr(&output);

    assert_eq!(code(&output), 2, "stderr: {stderr}");
    assert!(stderr.contains("DEPENDABLE_MAX_CVSS"), "stderr: {stderr}");
}

#[test]
fn a_violation_is_still_reported_under_quiet() {
    // The findings explain the exit code, so suppressing them would leave a red
    // build with nothing to read.
    let config = config("policy_quiet", DENY_LEFT_PAD);

    let output = check(&config, &["--no-vuln", "--quiet"], &[]);
    let stderr = stderr(&output);

    assert_eq!(code(&output), 1, "stderr: {stderr}");
    assert!(stderr.contains("denied_packages"), "stderr: {stderr}");
}

#[test]
fn json_output_stays_machine_readable_while_findings_go_to_stderr() {
    let config = config("policy_json", DENY_LEFT_PAD);

    let output = check(&config, &["--no-vuln", "--format", "json"], &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = stderr(&output);

    assert_eq!(code(&output), 1, "stderr: {stderr}");
    serde_json::from_str::<serde_json::Value>(&stdout).expect("stdout is valid JSON");
    assert!(
        !stdout.contains("denied_packages"),
        "findings belong on stderr; stdout: {stdout}"
    );
    assert!(stderr.contains("denied_packages"), "stderr: {stderr}");
}

/// Live: enrichment → CVSS → gate, end to end against crates.io and OSV.
///
/// The hermetic tests above prove the plumbing; only a real advisory proves the
/// score actually arrives. `time = "=0.2.7"` in the Rust fixture carries a known
/// RUSTSEC advisory, and `max_cvss = 0.1` fails on any rated advisory at all.
#[test]
#[ignore = "hits crates.io and OSV; run with `mise run test:live`"]
fn a_real_advisory_trips_the_cvss_gate() {
    let config = config("policy_live", "[policy]\nmax_cvss = 0.1\n");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-rust");

    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args([
            "check",
            fixture.to_str().expect("fixture path"),
            "--config",
            config.to_str().expect("config path"),
        ])
        .env_remove("DEPENDABLE_NO_POLICY")
        .env_remove("DEPENDABLE_MAX_CVSS")
        .output()
        .expect("run dependable");
    let stderr = stderr(&output);

    assert_eq!(code(&output), 1, "stderr: {stderr}");
    assert!(stderr.contains("max_cvss"), "stderr: {stderr}");
    assert!(stderr.contains("time"), "stderr: {stderr}");
}
