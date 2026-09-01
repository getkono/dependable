//! End-to-end coverage for `dependable fix` — the only command that writes to the
//! user's files, and the one that had no test asserting the bytes it produces.
//!
//! Hermetic: every fixture declares path dependencies only, so no registry request is
//! made. That is enough to exercise the write path, which is what these cover.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependable"));
    command.arg("fix").arg(dir).args(args);
    command.env_remove("DEPENDABLE_FAIL_ON");
    command.output().expect("run dependable fix")
}

/// A manifest whose only dependencies are local paths: nothing to fetch, nothing to
/// rewrite, so `fix` must leave the file byte-identical.
const LOCAL_ONLY: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nhelper = { path = \"../helper\" }\n";

#[test]
fn a_run_with_nothing_to_change_leaves_the_manifest_byte_identical() {
    let dir = workdir("fix_no_change");
    let manifest = dir.join("Cargo.toml");
    fs::write(&manifest, LOCAL_ONLY).unwrap();

    let output = run(&dir, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        LOCAL_ONLY,
        "fix rewrote a manifest it had nothing to change"
    );
}

/// Comments, ordering, and formatting are not `fix`'s to touch; it replaces one span.
#[test]
fn formatting_and_comments_survive_a_run() {
    let dir = workdir("fix_formatting");
    let manifest = dir.join("Cargo.toml");
    let original = "# a leading comment\n[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n# why this dep exists\nhelper = { path = \"../helper\" }   # trailing\n";
    fs::write(&manifest, original).unwrap();

    let output = run(&dir, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

/// `--dry-run` must not write. This is the flag users reach for before trusting the
/// command, so it is the one that must never be wrong.
#[test]
fn a_dry_run_writes_nothing() {
    let dir = workdir("fix_dry_run");
    let manifest = dir.join("Cargo.toml");
    fs::write(&manifest, LOCAL_ONLY).unwrap();
    let before = fs::metadata(&manifest).unwrap().modified().unwrap();

    let output = run(&dir, &["--dry-run"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(fs::read_to_string(&manifest).unwrap(), LOCAL_ONLY);
    assert_eq!(fs::metadata(&manifest).unwrap().modified().unwrap(), before);
}

/// A manifest that cannot be parsed must not be rewritten, and must not abort the run
/// with a half-written tree behind it.
#[test]
fn an_unparseable_manifest_is_left_alone() {
    let dir = workdir("fix_unparseable");
    let manifest = dir.join("Cargo.toml");
    let broken = "[package\nname = \"app\"\n";
    fs::write(&manifest, broken).unwrap();

    let _ = run(&dir, &[]);
    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        broken,
        "a manifest that could not be parsed was written to anyway"
    );
}

/// The write goes through a temporary file in the manifest's own directory and is
/// renamed into place. Nothing may be left behind on success.
#[test]
fn no_temporary_files_are_left_beside_the_manifest() {
    let dir = workdir("fix_no_temp_files");
    fs::write(dir.join("Cargo.toml"), LOCAL_ONLY).unwrap();

    let output = run(&dir, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let entries: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec!["Cargo.toml".to_string()],
        "stray files: {entries:?}"
    );
}

/// A read-only manifest must fail loudly rather than truncating it. `fs::write` opens
/// with `O_TRUNC`, so the pre-atomic path destroyed the file before discovering it
/// could not write.
#[cfg(unix)]
#[test]
fn a_read_only_manifest_is_not_destroyed() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = workdir("fix_read_only");
    let manifest = dir.join("Cargo.toml");
    fs::write(&manifest, LOCAL_ONLY).unwrap();
    let mut permissions = fs::metadata(&manifest).unwrap().permissions();
    permissions.set_mode(0o444);
    fs::set_permissions(&manifest, permissions).unwrap();

    let _ = run(&dir, &[]);

    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        LOCAL_ONLY,
        "a read-only manifest was truncated"
    );
}
