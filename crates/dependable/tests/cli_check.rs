//! End-to-end: what `dependable check`'s default table says about each row.
//!
//! Hermetic. The fixture declares only path sources and a dangling `$name`
//! override, so no registry fetch is built, and `--no-vuln` builds no OSV query.

use std::fs;
use std::process::Command;

/// #121. An override is usually a security pin, and `list` and `check --format json`
/// both said so while `check`'s table rendered it exactly like an ordinary
/// dependency. The row now carries the same ` (override)` label `list` prints.
///
/// The `dev` row is the other half: `check` calls out only the override kind, so a
/// dev dependency stays unlabelled rather than every row growing a suffix.
#[test]
fn the_table_labels_an_override_and_only_an_override() {
    let tmp = tempfile::Builder::new()
        .prefix("check_override_label")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("create the scratch directory");
    let dir = tmp.path();
    fs::write(
        dir.join("package.json"),
        "{\"name\":\"app\",\"devDependencies\":{\"helper\":\"file:./helper\"},\
         \"overrides\":{\"lodash\":\"$nope\",\"pinned\":\"file:./pinned\"}}\n",
    )
    .expect("write the manifest");
    // An empty config, so no test reads the repository's real `.dependable.toml`.
    let config = dir.join("dependable.toml");
    fs::write(&config, "").expect("write the config");

    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .arg("check")
        .arg(dir)
        .arg("--config")
        .arg(&config)
        .args(["--no-vuln", "--no-cache"])
        .env_remove("DEPENDABLE_FAIL_ON")
        .env("NO_COLOR", "1")
        .current_dir(dir)
        .output()
        .expect("run dependable check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    let row = |name: &str| {
        stdout
            .lines()
            .find(|line| line.starts_with(name))
            .unwrap_or_else(|| panic!("no row for {name}:\n{stdout}"))
            .to_owned()
    };
    // Both override rows, whatever their source: the label is about the kind.
    assert!(row("lodash").starts_with("lodash (override) "), "{stdout}");
    assert!(row("pinned").starts_with("pinned (override) "), "{stdout}");
    assert!(
        !row("helper").contains('('),
        "a dev dependency was labelled:\n{stdout}"
    );
}
