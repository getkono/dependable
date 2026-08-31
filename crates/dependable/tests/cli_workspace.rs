//! End-to-end: `check` resolves a Cargo workspace member's `dep.workspace = true`
//! against the root, and says which manifest the constraint came from.
//!
//! Hermetic, and instantly so. The fixture points the Rust registry at
//! `http://127.0.0.1:1`, where the connection is refused at once rather than timing
//! out, and a registry failure becomes a per-dependency `DependencyStatus::Error`
//! rather than aborting the run. `--no-cache` keeps a warm disk cache from answering
//! in the registry's place, and a `.git` marker stops both the lockfile walk and the
//! workspace walk escaping into the repository this test runs inside.
//!
//! What is under test is what the *parse and resolve* stages produced — the constraint
//! in force and where it came from — which the document reports whatever the registry
//! said.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const ROOT: &str = "[workspace]\nresolver = \"2\"\nmembers = [\"crates/app\"]\n\n[workspace.dependencies]\nserde = \"1.0.100\"\nhelper = { path = \"crates/helper\" }\n";

/// `serde` inherits a registry version; `helper` inherits a path, which Cargo resolves
/// to the path and which therefore has no version to check.
const MEMBER: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde.workspace = true\nhelper.workspace = true\n";

/// A registry nothing is listening on: `connect` fails at once.
const CONFIG: &str = "[rust]\nregistry = \"http://127.0.0.1:1\"\n";

fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("crates/app")).unwrap();
    // A repository boundary: without it both upward walks climb out of the temp dir and
    // into this repository, which has a `Cargo.lock` of its own.
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join("Cargo.toml"), ROOT).unwrap();
    fs::write(dir.join("crates/app/Cargo.toml"), MEMBER).unwrap();
    fs::write(dir.join("dependable.toml"), CONFIG).unwrap();
    dir
}

fn check_json(dir: &Path, args: &[&str]) -> Value {
    let config = dir.join("dependable.toml");
    let mut args: Vec<&str> = args.to_vec();
    args.extend_from_slice(&["--config", config.to_str().unwrap()]);
    args.extend_from_slice(&["--format", "json", "--no-vuln", "--no-cache"]);
    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable");
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}

fn result<'a>(doc: &'a Value, manifest_suffix: &str, name: &str) -> &'a Value {
    doc["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|r| {
            r["name"] == name
                && r["manifest"]
                    .as_str()
                    .is_some_and(|m| m.replace('\\', "/").ends_with(manifest_suffix))
        })
        .unwrap_or_else(|| panic!("no {name} in {manifest_suffix}: {}", doc["results"]))
}

/// The defect this feature exists for: scanning the member alone left the root outside
/// the run, and the crate went unchecked entirely.
#[test]
fn a_member_checked_on_its_own_still_gets_the_roots_constraint() {
    let dir = workdir("workspace_member_alone");
    let member = dir.join("crates/app/Cargo.toml");

    let doc = check_json(&dir, &["check", "--manifest", member.to_str().unwrap()]);

    let serde = result(&doc, "crates/app/Cargo.toml", "serde");
    assert_eq!(serde["current"], "1.0.100", "the root's constraint");
    assert_eq!(
        serde["inherited_from"]
            .as_str()
            .expect("attribution")
            .replace('\\', "/"),
        format!("{}/Cargo.toml", dir.to_str().unwrap().replace('\\', "/")),
        "the manifest the constraint came from"
    );
    // The registry was asked, which is the whole point — it just was not listening.
    assert_eq!(serde["status"], "ERROR");

    // A path declaration is inherited as a path dependency: nothing to look up, and
    // nothing to attribute a version to.
    let helper = result(&doc, "crates/app/Cargo.toml", "helper");
    assert_eq!(helper["status"], "LOCAL");
    assert!(helper["inherited_from"].is_null(), "{helper}");
}

/// Scanning the whole workspace reports the crate at the root *and* at each member that
/// opts in — one entry per declaration, because each is a place a reader has to look.
#[test]
fn a_whole_workspace_scan_reports_the_root_and_the_member() {
    let dir = workdir("workspace_whole_scan");

    let doc = check_json(&dir, &["check", dir.to_str().unwrap()]);

    let declared = result(&doc, "/Cargo.toml", "serde");
    assert_eq!(declared["kind"], "workspace");
    assert!(
        declared["inherited_from"].is_null(),
        "the root declares it rather than inheriting it: {declared}"
    );

    let inherited = result(&doc, "crates/app/Cargo.toml", "serde");
    assert_eq!(inherited["kind"], "normal");
    assert_eq!(inherited["current"], "1.0.100");

    // Per declaration, not per package — `unique_packages` is the deduplicated number.
    assert_eq!(doc["summary"]["manifests"], 2);
    assert_eq!(doc["summary"]["unique_packages"], 1, "serde is one package");
}
