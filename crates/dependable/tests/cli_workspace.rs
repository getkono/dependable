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
    // Canonical on both sides: the reported root is symlink-resolved, and on macOS the
    // temp directory is reached through one.
    let expected = dir
        .canonicalize()
        .expect("canonical")
        .join("Cargo.toml")
        .to_string_lossy()
        .replace('\\', "/");
    // Windows canonicalization yields the `\\?\` extended-length form, which the reported
    // path drops; slash-normalized, that prefix reads as `//?/`.
    let expected = expected.strip_prefix("//?/").unwrap_or(&expected);
    assert_eq!(
        serde["inherited_from"]
            .as_str()
            .expect("attribution")
            .replace('\\', "/"),
        expected,
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

    // Not `/Cargo.toml`: the member's path ends with that too, so a suffix that loose
    // picks whichever result happens to come first.
    let declared = result(&doc, "workspace_whole_scan/Cargo.toml", "serde");
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

/// `Path::parent` is lexical: the parent of `../sibling` is `..`, whose parent is `""` —
/// and every `join` onto `""` resolves against the **current directory**, a sibling of the
/// target rather than an ancestor of it. So `dependable list --manifest ../other/Cargo.toml`
/// run from inside a workspace handed `../other` that workspace's declarations, and the
/// `.git` boundary did not catch it, because that check lands on the current directory too.
///
/// Two deliberate departures from the other tests here. The layout goes in the *system*
/// temp directory rather than `CARGO_TARGET_TMPDIR`, because the latter lives inside this
/// repository — which is itself a Cargo workspace, and a genuine ancestor, so the walk
/// would legitimately find it and mask the bug. And it runs in a separate process, so the
/// working directory it needs is not global state shared with every other test.
#[test]
fn a_relative_path_never_adopts_the_current_directorys_workspace() {
    /// Distinctive, so the assertion can name the workspace that must not be consulted.
    const SIBLING_ROOT: &str =
        "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"9.9.9\"\n";

    let base = std::env::temp_dir().join("dependable-test-relative-workspace-escape");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("myworkspace")).unwrap();
    fs::create_dir_all(base.join("standalone")).unwrap();
    let base = base.canonicalize().expect("canonical");

    fs::write(base.join("myworkspace/Cargo.toml"), SIBLING_ROOT).unwrap();
    // A sibling of that workspace, belonging to nothing.
    fs::write(
        base.join("standalone/Cargo.toml"),
        "[package]\nname = \"standalone\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde.workspace = true\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .current_dir(base.join("myworkspace"))
        .args([
            "list",
            "--manifest",
            "../standalone/Cargo.toml",
            "--format",
            "json",
        ])
        .output()
        .expect("run dependable");
    let doc: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let dependency = &doc["projects"][0]["dependencies"][0];
    assert_eq!(dependency["name"], "serde");
    assert_ne!(
        dependency["constraint"], "9.9.9",
        "took the constraint from a workspace that is not an ancestor: {dependency}"
    );
    assert_eq!(dependency["inherited"], false, "{dependency}");
}

/// `workspace_root` names the manifest that *governs* this one, whether or not anything
/// came from it — so `inherited_from`, which claims a constraint's origin, has to say
/// more than that. Naming a manifest as the source of a version it never declared would
/// be worse than saying nothing, especially beside a warning that says the opposite.
#[test]
fn a_constraint_the_root_never_declared_is_attributed_to_nobody() {
    let dir = workdir("workspace_undeclared_attribution");
    fs::write(
        dir.join("crates/app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ntokio.workspace = true\n",
    )
    .unwrap();

    let member = dir.join("crates/app/Cargo.toml");
    let doc = check_json(&dir, &["check", "--manifest", member.to_str().unwrap()]);

    let tokio = result(&doc, "crates/app/Cargo.toml", "tokio");
    assert_eq!(tokio["status"], "LOCAL", "nothing to check: {tokio}");
    assert!(
        tokio["inherited_from"].is_null(),
        "the root declares no tokio: {tokio}"
    );
}
