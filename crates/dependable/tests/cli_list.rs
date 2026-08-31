//! End-to-end: `dependable list` reports the projects in a repository and the
//! dependencies each declares. Hermetic — `list` parses manifests and lockfiles from
//! disk and never touches the network unless `--features` is passed.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable");
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 output")
}

fn list_json(path: &Path, extra: &[&str]) -> Value {
    let mut args = vec!["list", path.to_str().unwrap(), "--format", "json"];
    args.extend_from_slice(extra);
    serde_json::from_str(&run(&args)).expect("valid JSON")
}

/// One project by name, or a panic naming what was found instead.
fn project<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["projects"]
        .as_array()
        .expect("projects array")
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("no project {name} in {}", doc["projects"]))
}

fn dependency<'a>(project: &'a Value, name: &str) -> &'a Value {
    project["dependencies"]
        .as_array()
        .expect("dependencies array")
        .iter()
        .find(|d| d["name"] == name)
        .unwrap_or_else(|| panic!("no dependency {name}"))
}

#[test]
fn reports_every_project_in_a_workspace_with_its_identity() {
    let doc = list_json(&fixture("sample-workspace"), &[]);
    assert_eq!(doc["schema"], "dependable.list/v1");
    assert_eq!(doc["summary"]["projects"], 3);
    assert_eq!(doc["summary"]["by_ecosystem"]["Rust"], 3);

    let app = project(&doc, "app");
    assert_eq!(app["version"], "0.1.0");
    assert_eq!(app["role"], "package");
    // Paths are `/`-separated on every platform: the document is consumed by tooling
    // that joins them with paths from git and other tools, which speak `/`.
    assert_eq!(app["manifest"], "crates/app/Cargo.toml");

    // The workspace root declares no package of its own.
    let root = doc["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["manifest"] == "Cargo.toml")
        .expect("workspace root");
    assert_eq!(root["role"], "workspace");
    assert_eq!(root["name"], Value::Null);
}

/// Every dependency carries where it came from and whether the package itself depends
/// on it — the distinctions an inventory exists to make.
#[test]
fn dependencies_carry_source_kind_and_locked_version() {
    let doc = list_json(&fixture("sample-workspace"), &[]);
    let app = project(&doc, "app");

    let leftpad = dependency(app, "leftpad");
    assert_eq!(leftpad["source"], "registry");
    assert_eq!(leftpad["kind"], "normal");
    assert_eq!(leftpad["direct"], true);
    // The workspace lockfile sits above the member, and is reported by path.
    assert_eq!(leftpad["locked"], "1.2.0");
    assert_eq!(app["lockfile"], "Cargo.lock");

    assert_eq!(dependency(app, "util")["source"], "local");
    assert_eq!(dependency(app, "gitdep")["source"], "git");
}

#[test]
fn no_lock_file_omits_locked_versions() {
    let doc = list_json(&fixture("sample-workspace"), &["--no-lock-file"]);
    let app = project(&doc, "app");
    assert_eq!(app["lockfile"], Value::Null);
    assert_eq!(dependency(app, "leftpad")["locked"], Value::Null);
}

/// npm splits runtime from development dependencies, and an inventory has to preserve
/// the split — a `devDependencies` entry ships with nobody.
#[test]
fn npm_dev_dependencies_are_distinguished() {
    let doc = list_json(&fixture("sample-npm"), &[]);
    let app = project(&doc, "sample-app");
    assert_eq!(app["version"], "0.1.0");
    assert_eq!(app["ecosystem"], "npm");

    assert_eq!(dependency(app, "react")["kind"], "normal");
    assert_eq!(dependency(app, "typescript")["kind"], "dev");
    assert_eq!(dependency(app, "typescript")["locked"], "5.4.2");
    assert_eq!(dependency(app, "local-ui")["source"], "local");
}

/// The text format is one tab-separated record per dependency, project first.
#[test]
fn text_format_emits_one_line_per_dependency() {
    let path = fixture("sample-npm");
    let out = run(&["list", path.to_str().unwrap(), "--format", "text"]);
    let react = out
        .lines()
        .find(|l| l.contains("\treact\t"))
        .expect("a react line");
    let fields: Vec<&str> = react.split('\t').collect();
    assert_eq!(fields[0], "sample-app");
    assert_eq!(fields[1], "npm");
    assert_eq!(fields[2], "package.json");
    assert_eq!(fields[3], "react");
    assert_eq!(fields[4], "^18.0.0");
    assert_eq!(fields[5], "normal");
    assert_eq!(fields[6], "registry");
    assert_eq!(fields[7], "18.0.0");
    // The license field always exists, so the record keeps a fixed arity; it is
    // an em-dash until `--licenses` fetches one.
    assert_eq!(fields[8], "—");
    assert_eq!(fields.len(), 9);
    assert_eq!(out.lines().count(), 4);
}

/// Licenses live on registry metadata, not in a manifest, so `list` must not go
/// looking for them unless it is asked to — this file's whole contract.
#[test]
fn licenses_are_absent_and_offline_unless_asked_for() {
    let doc = list_json(&fixture("sample-npm"), &[]);
    let react = dependency(project(&doc, "sample-app"), "react");
    assert_eq!(
        react.get("license"),
        None,
        "no `license` key without --licenses"
    );
}

/// The opt-in path end to end. Ignored by default: it reaches the real registry.
#[test]
#[ignore = "network"]
fn licenses_are_reported_when_asked_for() {
    let doc = list_json(&fixture("sample-workspace"), &["--licenses"]);
    let app = project(&doc, "app");
    assert!(
        dependency(app, "serde")
            .get("license")
            .and_then(Value::as_str)
            .is_some_and(|l| l.contains("MIT")),
        "{:?}",
        dependency(app, "serde")
    );
}

/// The default format stays human-readable, and now names the package it describes.
#[test]
fn table_format_labels_each_project() {
    let path = fixture("sample-npm");
    let out = run(&["list", path.to_str().unwrap()]);
    assert!(
        out.starts_with("package.json — sample-app v0.1.0 — npm (4 dependencies)"),
        "unexpected header: {out}"
    );
    assert!(
        out.contains("typescript ~5.4.0 (locked 5.4.2) (dev)"),
        "{out}"
    );
}

#[test]
fn manifest_glob_narrows_discovery_without_letting_a_star_cross_a_slash() {
    let root = fixture("sample-monorepo");
    let doc = list_json(
        &root,
        &["--depth", "4", "--manifest-glob", "services/*/Cargo.toml"],
    );

    let manifests: Vec<&str> = doc["projects"]
        .as_array()
        .expect("projects array")
        .iter()
        .map(|p| p["manifest"].as_str().expect("a manifest path"))
        .collect();
    assert_eq!(
        manifests,
        vec!["services/a/Cargo.toml", "services/b/Cargo.toml"],
        "`tools/` is outside the pattern and `services/a/nested/` is a level too deep"
    );
}

#[test]
fn manifest_glob_and_manifest_are_mutually_exclusive() {
    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args([
            "list",
            "--manifest",
            "Cargo.toml",
            "--manifest-glob",
            "*/Cargo.toml",
        ])
        .output()
        .expect("run dependable");
    assert!(!output.status.success(), "the combination must be rejected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--manifest-glob"), "{stderr}");
}

/// A member's `dep.workspace = true` states no version of its own, and an inventory that
/// reported it that way would hide both the version in force and where it came from.
#[test]
fn workspace_members_report_the_constraint_the_root_declares() {
    let doc = list_json(&fixture("sample-workspace-inherit"), &[]);

    let app = project(&doc, "app");
    let leftpad = dependency(app, "leftpad");
    assert_eq!(leftpad["constraint"], "1.0.0", "from the root");
    assert_eq!(leftpad["source"], "inherited");
    assert_eq!(leftpad["inherited"], true);
    assert_eq!(leftpad["kind"], "normal");
    // The lockfile is applied *after* inheritance, so the locked version is chosen
    // against the constraint the root supplied rather than against an empty one.
    assert_eq!(leftpad["locked"], "1.0.5");
    assert_eq!(
        app["lockfile"], "Cargo.lock",
        "the fixture's own, not the repo's"
    );

    // The section the *member* declared it in survives inheritance, and so does an
    // alternate registry named only at the root.
    let rightpad = dependency(app, "rightpad");
    assert_eq!(rightpad["constraint"], "2.0.0");
    assert_eq!(rightpad["kind"], "dev");
    assert_eq!(rightpad["registry"], "internal");

    // Every member that opts in gets its own entry, against its own manifest.
    let util = project(&doc, "util");
    assert_eq!(dependency(util, "leftpad")["constraint"], "1.0.0");
    assert_eq!(dependency(util, "leftpad")["inherited"], true);
}

/// Cargo resolves a member's `path` entry to the path whatever the root says about a
/// crate of that name. Matching on the name alone would hand this one the root's version.
#[test]
fn a_path_override_is_not_treated_as_inherited() {
    let doc = list_json(&fixture("sample-workspace-inherit"), &[]);
    let util = dependency(project(&doc, "app"), "util");

    assert_eq!(util["source"], "local");
    assert_eq!(util["inherited"], false);
    assert_eq!(util["constraint"], Value::Null);
}

/// The root's `[workspace.dependencies]` are central declarations, not dependencies of
/// the root — and it inherits nothing, because it is what everything else inherits from.
#[test]
fn the_workspace_root_declares_rather_than_inherits() {
    let doc = list_json(&fixture("sample-workspace-inherit"), &[]);
    let root = doc["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["manifest"] == "Cargo.toml")
        .expect("workspace root");

    assert_eq!(root["role"], "workspace");
    for name in ["leftpad", "rightpad", "util"] {
        let declaration = dependency(root, name);
        assert_eq!(declaration["kind"], "workspace", "{name}");
        assert_eq!(declaration["direct"], false, "{name}");
        assert_eq!(declaration["inherited"], false, "{name}");
    }
}
