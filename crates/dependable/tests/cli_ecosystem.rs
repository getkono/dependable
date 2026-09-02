//! End-to-end: `--ecosystem` narrows which manifests a run reads.
//!
//! Hermetic. Every assertion is made against `list --format json`, which parses
//! from disk and never reaches a registry, or against a `check`/`fix` invocation
//! whose selection is empty or Rust-only over a tree with no lockfile to resolve.
//! The point being pinned is that the flag changes the *inventory* — the failure
//! mode of the flag this replaces was that it parsed, was advertised, and was read
//! by nothing.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const CARGO_TOML: &str =
    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.100\"\n";
const PACKAGE_JSON: &str = "{\n  \"name\": \"web\",\n  \"version\": \"0.1.0\",\n  \"dependencies\": { \"react\": \"^18.0.0\" }\n}\n";
const CARGO_TOML_NO_DEPS: &str = "[package]\nname = \"solo\"\nversion = \"0.1.0\"\n";
const GO_MOD: &str = "module example.com/svc\n\ngo 1.21\n\nrequire github.com/google/uuid v1.6.0\n";
const MIX_EXS: &str = "defmodule Sample.MixProject do\n  use Mix.Project\n  defp deps do\n    [{:phoenix, \"~> 1.7\"}]\n  end\nend\n";
const DENO_JSON: &str = "{\n  \"imports\": { \"chalk\": \"npm:chalk@^5.3.0\" }\n}\n";
const PNPM_WORKSPACE: &str = "packages:\n  - 'packages/*'\n\ncatalog:\n  lodash: \"4.17.21\"\n";

/// A scratch directory of its own per test, under Cargo's per-target temp dir.
fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ecosystem")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

fn write(dir: &Path, rel: &str, content: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create the parent directory");
    }
    fs::write(path, content).expect("write the manifest");
}

/// A polyglot repository: one project per ecosystem, each in its own directory so
/// that nothing about the layout depends on two manifests sharing a path.
fn polyglot(name: &str) -> PathBuf {
    let dir = workdir(name);
    write(&dir, "rust/Cargo.toml", CARGO_TOML);
    write(&dir, "web/package.json", PACKAGE_JSON);
    write(&dir, "svc/go.mod", GO_MOD);
    dir
}

/// Colour is pinned off rather than inherited: this repository has had tests go
/// red from an ambient `FORCE_COLOR` in the developer's shell, and `--help` is
/// asserted on as text.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("FORCE_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("COLORTERM")
        .env_remove("DEPENDABLE_FAIL_ON")
        .output()
        .expect("run dependable")
}

fn list_json(dir: &Path, extra: &[&str]) -> Value {
    let mut args = vec![
        "list",
        dir.to_str().expect("utf-8 path"),
        "--format",
        "json",
    ];
    args.extend_from_slice(extra);
    let output = run(&args);
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}

/// The manifest path of every project in the document, `/`-separated as the
/// schema promises, sorted so the assertion does not depend on walk order.
fn manifests(doc: &Value) -> Vec<String> {
    let mut paths: Vec<String> = doc["projects"]
        .as_array()
        .expect("projects array")
        .iter()
        .map(|p| p["manifest"].as_str().expect("a manifest path").to_owned())
        .collect();
    paths.sort();
    paths
}

/// The acceptance boundary. The flag this replaces parsed, appeared in `--help`
/// claiming to restrict the run, and was read by nothing — so the one thing worth
/// asserting is that the *inventory* is different, not that the flag is accepted.
#[test]
fn ecosystem_narrows_the_inventory_to_what_was_asked_for() {
    let dir = polyglot("narrows");

    let all = list_json(&dir, &[]);
    assert_eq!(
        manifests(&all),
        ["rust/Cargo.toml", "svc/go.mod", "web/package.json"],
        "without the flag every ecosystem is read"
    );

    let rust = list_json(&dir, &["--ecosystem", "rust"]);
    assert_eq!(manifests(&rust), ["rust/Cargo.toml"]);
    assert_eq!(rust["summary"]["projects"], 1);
    assert_eq!(
        rust["summary"]["by_ecosystem"],
        serde_json::json!({ "Rust": 1 }),
        "the summary counts what was read, not what was on disk"
    );
}

/// An ecosystem is not a filename. `Npm` owns three manifest spellings, and
/// filtering by ecosystem has to cover all of them without the user naming any.
#[test]
fn an_ecosystem_covers_every_manifest_spelling_it_owns() {
    let dir = workdir("spellings");
    write(&dir, "rust/Cargo.toml", CARGO_TOML);
    write(&dir, "web/package.json", PACKAGE_JSON);
    write(&dir, "edge/deno.json", DENO_JSON);
    write(&dir, "mono/pnpm-workspace.yaml", PNPM_WORKSPACE);

    let doc = list_json(&dir, &["--ecosystem", "npm"]);
    assert_eq!(
        manifests(&doc),
        [
            "edge/deno.json",
            "mono/pnpm-workspace.yaml",
            "web/package.json"
        ],
        "one ecosystem, three spellings, and no Cargo.toml"
    );
}

/// Two values are a union, not a contradiction — the same reading
/// `--manifest-glob` gives a repeated pattern.
#[test]
fn two_ecosystems_are_a_union_not_a_contradiction() {
    let dir = polyglot("union");
    let doc = list_json(&dir, &["--ecosystem", "rust", "--ecosystem", "npm"]);
    assert_eq!(manifests(&doc), ["rust/Cargo.toml", "web/package.json"]);
}

/// An ecosystem nobody has a manifest for is an answer, not a tool error: exit 0,
/// and a line saying what was searched and what was there instead. The generic
/// "No supported manifests found." would be a falsehood here — the repository is
/// full of manifests, the filter removed them — so it must not also be printed.
///
/// `check` reaches no registry because the selection is empty before any fetcher
/// is constructed, which is also what makes this assertable offline.
#[test]
fn check_narrows_discovery_without_touching_the_network() {
    let dir = workdir("empty_selection");
    write(&dir, "mix.exs", MIX_EXS);

    let output = run(&[
        "check",
        dir.to_str().expect("utf-8 path"),
        "--ecosystem",
        "rust",
        "--no-vuln",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "an empty selection is exit 0: {stderr}"
    );
    assert!(
        stderr.contains("no manifest for Rust"),
        "say what was asked for: {stderr}"
    );
    assert!(
        stderr.contains("Elixir"),
        "and what was there instead: {stderr}"
    );
    assert!(
        !stderr.contains("No supported manifests found."),
        "the generic line contradicts the specific one: {stderr}"
    );
}

/// `--manifest` names one file and skips discovery, so there is no discovered set
/// for an ecosystem to narrow. clap rejects the pair rather than letting one of
/// them be silently ignored — the same contract `--manifest-glob` has.
#[test]
fn ecosystem_and_manifest_are_mutually_exclusive() {
    let output = run(&["list", "--manifest", "Cargo.toml", "--ecosystem", "rust"]);
    assert!(!output.status.success(), "the combination must be rejected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--ecosystem"), "{stderr}");
}

/// A flag whose accepted values are not advertised is a guessing game, and the
/// one value clap would otherwise spell wrong (`c-sharp`) is the reason to pin
/// each of them rather than the flag name alone.
///
/// The check is scoped to clap's own list of accepted values, so it cannot pass
/// on an incidental substring elsewhere in the help — `go` appears inside
/// `cargo`.
#[test]
fn the_flag_is_advertised_with_the_values_it_accepts() {
    for command in ["check", "list", "fix"] {
        let output = run(&[command, "--help"]);
        assert!(output.status.success(), "{command} --help failed");
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("--ecosystem"), "{command}: {help}");

        let advertised = help
            .lines()
            .find(|line| line.trim_start().starts_with("[possible values:"))
            .unwrap_or_else(|| panic!("{command} --help must list the accepted values: {help}"));
        for value in [
            "rust", "go", "npm", "python", "php", "dart", "csharp", "elixir", "jvm",
        ] {
            assert!(
                advertised.contains(value),
                "{command} --help must advertise `{value}`: {advertised}"
            );
        }
    }
}

/// Discovery's unread-manifest notices are advice to *enable* something. Telling
/// someone to wire up Gradle during a run they restricted to Rust is noise they
/// asked not to receive, so the request is composed into the notice predicate as
/// well as into the manifest set.
#[test]
fn an_ecosystem_filter_silences_advice_about_ecosystems_it_excluded() {
    let dir = workdir("notices");
    write(&dir, "rust/Cargo.toml", CARGO_TOML);
    write(&dir, "legacy/build.gradle", "dependencies { }\n");

    let path = dir.to_str().expect("utf-8 path");
    let default = run(&["list", path, "--format", "json"]);
    let default = String::from_utf8_lossy(&default.stderr).into_owned();
    assert!(
        default.contains("build.gradle"),
        "an unread Gradle build is worth saying so about: {default}"
    );

    let filtered = run(&["list", path, "--format", "json", "--ecosystem", "rust"]);
    assert!(filtered.status.success());
    let filtered = String::from_utf8_lossy(&filtered.stderr).into_owned();
    assert!(
        !filtered.contains("build.gradle"),
        "`--ecosystem rust` is an answer about the JVM, not a question: {filtered}"
    );
}

/// `fix` writes to the user's files. Without the flag here, `dependable fix`
/// would rewrite manifests the matching `dependable check` deliberately left out
/// — the stated reason `--manifest-glob` is on `fix` at all.
///
/// Hermetic by construction rather than by mocking: the only Rust manifest in the
/// tree declares no dependencies, so the narrowed run has nothing to look up, and
/// the npm and Go manifests it excluded are the ones that would have gone to a
/// registry. A `fix` that ignored `--ecosystem` would therefore also be the one
/// that reached the network.
#[test]
fn fix_rewrites_only_the_ecosystem_it_was_pointed_at() {
    let dir = workdir("fix_scope");
    write(&dir, "rust/Cargo.toml", CARGO_TOML_NO_DEPS);
    write(&dir, "web/package.json", PACKAGE_JSON);
    write(&dir, "svc/go.mod", GO_MOD);

    let output = run(&[
        "fix",
        dir.to_str().expect("utf-8 path"),
        "--ecosystem",
        "rust",
        "--dry-run",
        "--no-vuln",
    ]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "{combined}");
    assert!(
        !combined.contains("go.mod"),
        "a manifest outside the requested ecosystem must not be considered: {combined}"
    );
    assert!(
        !combined.contains("package.json"),
        "nor an npm one: {combined}"
    );

    // And nothing on disk moved — `--dry-run`, and the excluded files were never
    // even read.
    assert_eq!(
        fs::read_to_string(dir.join("svc/go.mod")).expect("read go.mod"),
        GO_MOD
    );
    assert_eq!(
        fs::read_to_string(dir.join("web/package.json")).expect("read package.json"),
        PACKAGE_JSON
    );
}
