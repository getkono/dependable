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

// ---------------------------------------------------------------------------
// Declined updates (issue #93)
//
// `check` reports an update, `fix` cannot rewrite the constraint that carries it,
// and until now `fix` said "Everything is already up to date." — the contradiction
// this section falsifies. Proving it needs a registry that actually offers a newer
// release, so these run against a throwaway HTTP server on loopback: hermetic, no
// dependency added, and the real fetch path rather than a stub of it.
// ---------------------------------------------------------------------------

/// A single-shot registry: a path-to-JSON-body table served on loopback.
///
/// Deliberately minimal rather than a mock-server crate. `dependable` has no
/// dev-dependencies at all, and the two registries these tests need — an npm
/// packument and a PyPI release map — are each one GET returning one document.
/// Every response closes the connection, so no keep-alive state has to be modelled.
fn registry(routes: Vec<(String, String)>) -> String {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let addr = listener.local_addr().expect("read the bound port");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let routes = routes.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().expect("clone the socket"));
                let mut request = String::new();
                if reader.read_line(&mut request).is_err() {
                    return;
                }
                // Drain the headers so the client is never left writing into a
                // socket nobody is reading, which some stacks report as a reset
                // rather than as the response we are about to send.
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                let body = routes
                    .iter()
                    .find(|(route, _)| *route == path)
                    .map(|(_, body)| body.clone());
                let response = match body {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                         {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: \
                             close\r\n\r\n"
                        .to_string(),
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    format!("http://{addr}")
}

/// An npm abbreviated packument: the version keys and the `latest` dist-tag are
/// all the version checker reads.
fn packument(versions: &[&str], latest: &str) -> String {
    let entries: Vec<String> = versions
        .iter()
        .map(|v| format!("\"{v}\":{{\"name\":\"lodash\",\"version\":\"{v}\"}}"))
        .collect();
    format!(
        "{{\"name\":\"lodash\",\"dist-tags\":{{\"latest\":\"{latest}\"}},\"versions\":{{{}}}}}",
        entries.join(",")
    )
}

/// A crates.io sparse-index body: one JSON document per line, and `vers` is the
/// only field the version list is built from.
fn index(versions: &[&str]) -> String {
    versions
        .iter()
        .map(|v| format!("{{\"vers\":\"{v}\"}}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Point the ecosystem fetchers at `base` and switch OSV off, so a run touches
/// nothing but the loopback registry.
///
/// All three registries every time, including the Cargo one: a fixture with no
/// manifest of a given kind never asks, and a shared config is one fewer thing
/// for a new test to get subtly wrong.
fn write_config(dir: &Path, base: &str) -> PathBuf {
    let config = dir.join(".dependable.toml");
    fs::write(
        &config,
        format!(
            "[npm]\nregistry = \"{base}\"\n\n[python]\nregistry = \"{base}/pypi\"\n\n\
             [rust]\nregistry = \"{base}\"\n\n[php]\nregistry = \"{base}\"\n\n\
             [vulnerability]\nenabled = false\n"
        ),
    )
    .unwrap();
    config
}

fn run_with_config(dir: &Path, config: &Path, args: &[&str]) -> Output {
    run_in(dir, dir, config, args)
}

/// Run `fix` over `scan` from inside `home`, which is also the process's working
/// directory. Separate arguments because the workspace-member case turns on the
/// two differing: the scan root is the member, and the workspace root that owns
/// the constraint sits above it.
fn run_in(home: &Path, scan: &Path, config: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependable"));
    command
        .arg("fix")
        .arg(scan)
        .arg("--config")
        .arg(config)
        .arg("--no-cache")
        .arg("--no-vuln")
        .args(args);
    command.env_remove("DEPENDABLE_FAIL_ON");
    // A user `.npmrc` would override the configured registry and send the run at
    // the real npm.
    command.env("HOME", home);
    command.current_dir(home);
    command.output().expect("run dependable fix")
}

/// Issue #93, exactly as reported: `"lodash": "1.x"` with `1.9.0` in range and
/// `2.0.0` published. `check` reports the update; `fix` cannot write it, because a
/// bare version in npm is one release and the author asked for a line of them.
/// Before this, the run printed "Everything is already up to date." over the top
/// of it and `--dry-run` printed nothing at all.
#[test]
fn a_declined_wildcard_is_reported_instead_of_claimed_up_to_date() {
    let dir = workdir("fix_declined_wildcard");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0", "1.9.0", "2.0.0"], "2.0.0"),
    )]);
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    let original =
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"1.x\"\n  }\n}\n";
    fs::write(&manifest, original).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains(&format!(
            "note: left lodash = 1.x alone in {}: 1.9.0 is available, but a wildcard already \
             tracks new releases, and a bare version here would pin it to one",
            manifest.display()
        )),
        "no note for the declined wildcard.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "fix claimed everything was up to date over an update it declined:\n{stdout}"
    );
    assert!(
        stdout.contains("Nothing to rewrite. 1 available update left alone"),
        "stdout: {stdout}"
    );
    // Declining is still declining: the constraint is untouched.
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

/// `--dry-run` printed nothing whatsoever for the same manifest — the worst form
/// of the defect, because it is the mode people use to find out whether there is
/// anything to do.
#[test]
fn a_dry_run_reports_a_declined_wildcard_too() {
    let dir = workdir("fix_declined_wildcard_dry");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0", "1.9.0", "2.0.0"], "2.0.0"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"1.x\"\n  }\n}\n",
    )
    .unwrap();

    let output = run_with_config(&dir, &config, &["--dry-run"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("note: left lodash = 1.x alone in ")
            && stderr.contains("package.json: 1.9.0 is available, but a wildcard"),
        "stderr: {stderr}"
    );
    assert!(
        stdout.contains("Nothing to rewrite. 1 available update left alone"),
        "stdout: {stdout}"
    );
}

/// A dist-tag has been silent since long before the wildcard was. `"latest"`
/// resolves to the newest release, so the update only shows once a lockfile holds
/// an older one — and then `fix` must say why it will not pin the channel.
#[test]
fn a_declined_dist_tag_is_reported() {
    let dir = workdir("fix_declined_dist_tag");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0", "2.0.0"], "2.0.0"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"latest\"\n  }\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("package-lock.json"),
        "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \
         \"version\": \"1.0.0\"\n    }\n  }\n}\n",
    )
    .unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("note: left lodash = latest alone in ")
            && stderr.contains(
                "package.json: 2.0.0 is available, but a dist-tag names a release channel, not \
                 a version"
            ),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "{stdout}"
    );
}

/// A compound range: two bounds one version cannot carry. Python, whose
/// comma-separated spelling is a different guard from the space- and
/// `||`-separated one `a_declined_multi_clause_range_is_reported` covers.
#[test]
fn a_declined_comma_range_is_reported() {
    let dir = workdir("fix_declined_comma_range");
    let base = registry(vec![(
        "/pypi/requests/json".to_string(),
        "{\"releases\":{\"1.0.0\":[],\"1.9.0\":[],\"2.0.0\":[]}}".to_string(),
    )]);
    let config = write_config(&dir, &base);
    let manifest = dir.join("requirements.txt");
    let original = "requests>=1.0,<2.0\n";
    fs::write(&manifest, original).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("note: left requests = >=1.0,<2.0 alone in ")
            && stderr.contains(
                "requirements.txt: 1.9.0 is available, but a comma-separated range has two \
                 bounds and one version cannot carry both"
            ),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "{stdout}"
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

/// The line `fix` prints when there is genuinely nothing to do must survive: a
/// note-driven summary that fired on an ordinary up-to-date run would trade one
/// wrong message for another.
#[test]
fn a_run_with_no_declines_still_says_everything_is_up_to_date() {
    let dir = workdir("fix_no_declines");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0"], "1.0.0"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"1.0.0\"\n  }\n}\n",
    )
    .unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stdout.contains("Everything is already up to date."),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(!stderr.contains("note: left"), "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// The other ways an update is left behind
//
// A constraint refusing the rewrite is one of them, and the section above covers
// it. These are the rest: a dependency whose version lives in another file, a pin
// held back for want of `--all`, and a constraint already naming the only version
// in range. Each was silent, and each reproduced issue #93's symptom — `check`
// reports an update, `fix` prints "Everything is already up to date." — without a
// wildcard anywhere in sight.
// ---------------------------------------------------------------------------

/// A workspace member whose constraint lives in the root, scanned from the member.
/// `collect_manifests` finds only the member; `check_manifest` still resolves the
/// root, so the inherited-skip note fires — and the summary used to print
/// "Everything is already up to date." on stdout directly over it.
#[test]
fn an_inherited_skip_is_not_contradicted_by_the_summary() {
    let dir = workdir("fix_inherited_skip");
    let member = dir.join("crates/app");
    fs::create_dir_all(&member).unwrap();
    // A repository boundary: without it the lockfile and workspace walks climb
    // out of the temp directory and into the repository this test runs inside.
    fs::create_dir_all(dir.join(".git")).unwrap();
    // `2.0.0` is what makes it an update: `1.0.100` is a caret constraint, so
    // `1.0.219` satisfies it and `check` calls the member up to date. A release
    // outside the range is what `check` reports and `fix` cannot write here.
    let base = registry(vec![(
        "/se/rd/serde".to_string(),
        index(&["1.0.100", "1.0.219", "2.0.0"]),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/app\"]\n\n\
         [workspace.dependencies]\nserde = \"1.0.100\"\n",
    )
    .unwrap();
    let manifest = member.join("Cargo.toml");
    let original = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde.workspace = true\n";
    fs::write(&manifest, original).unwrap();

    let output = run_in(&dir, &member, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains("inherits serde from the workspace"),
        "no inherited-skip note.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "the summary contradicted the note printed two lines earlier:\n{stdout}"
    );
    assert!(
        stdout.contains("Nothing to rewrite. 1 available update left alone"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    // And the count came from the inherited category alone. An inherited item is
    // not rewritable, so the planner drops it before any constraint is consulted
    // and it never reaches the declined list — which is precisely why a summary
    // counting only that list contradicted the note above.
    assert!(
        !stderr.contains("note: left"),
        "this fixture must produce no constraint decline: {stderr}"
    );
    // The member's own file has no version string to rewrite, and did not gain one.
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

/// A pin is a constraint, and `--all` is the action that moves it. Left silent,
/// this reproduced issue #93 by default configuration on the commonest way a
/// dependency is deliberately held back.
#[test]
fn a_pin_held_back_for_want_of_all_is_reported() {
    let dir = workdir("fix_declined_pin");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0", "1.9.0"], "1.9.0"),
    )]);
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    let original =
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"=1.0.0\"\n  }\n}\n";
    fs::write(&manifest, original).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains("note: left lodash = =1.0.0 alone in ")
            && stderr.contains(
                "1.9.0 is available, but the constraint pins one release, and only `--all` \
                 moves a pin"
            ),
        "no note naming `--all` for the pin.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "{stdout}"
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);

    // And `--all` does the thing the note named, with nothing left to say.
    let output = run_with_config(&dir, &config, &["--all"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stdout.contains("lodash =1.0.0 → =1.9.0"),
        "stdout: {stdout}"
    );
    assert!(!stderr.contains("note: left lodash"), "stderr: {stderr}");
    assert!(
        fs::read_to_string(&manifest).unwrap().contains("=1.9.0"),
        "`--all` did not move the pin"
    );
}

/// The constraint already names the only version in range, and a newer release
/// exists outside it. Nothing to write, and — until now — nothing said: the
/// clean line went out over an update `check` had just reported. The same
/// `continue` carries a `Vulnerable` row whose only fixed release is the one
/// already in force.
#[test]
fn a_constraint_already_at_its_target_is_reported() {
    let dir = workdir("fix_already_at_target");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0", "2.0.0"], "2.0.0"),
    )]);
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    let original =
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"1.0.0\"\n  }\n}\n";
    fs::write(&manifest, original).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains("note: left lodash = 1.0.0 alone in ")
            && stderr.contains(
                "1.0.0 is available, but the constraint already names it, and nothing newer \
                 satisfies the constraint"
            ),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "{stdout}"
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

/// The summary is on stdout and the notes are on stderr, so it has to say which
/// stream to look at. "see the notes above" named nothing findable for anyone
/// redirecting one of the two — `dependable fix > fix.log` puts the summary in
/// the log and the notes on the terminal.
#[test]
fn the_summary_names_the_stream_the_notes_went_to() {
    let dir = workdir("fix_summary_names_stderr");
    let base = registry(vec![(
        "/lodash".to_string(),
        packument(&["1.0.0", "1.9.0", "2.0.0"], "2.0.0"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \"1.x\"\n  }\n}\n",
    )
    .unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stdout.contains("see the notes on stderr"),
        "stdout: {stdout}"
    );
    // The two streams stay apart: the note is not duplicated onto stdout, so the
    // summary is pointing somewhere else rather than at itself.
    assert!(!stdout.contains("note: left"), "stdout: {stdout}");
    assert!(stderr.contains("note: left lodash"), "stderr: {stderr}");
}

/// A Packagist metadata-v2 document: the `version` of each entry is all the
/// version checker reads.
fn packagist(name: &str, versions: &[&str]) -> String {
    let entries: Vec<String> = versions
        .iter()
        .map(|v| format!("{{\"version\":\"{v}\"}}"))
        .collect();
    format!("{{\"packages\":{{\"{name}\":[{}]}}}}", entries.join(","))
}

/// A space-separated range and a `||` alternation, both of which the constraint
/// front end now translates rather than rejecting — so `DeclineReason::MultiClause`
/// is reached end to end, where it used to be unreachable because such a
/// constraint became `DependencyStatus::Error` long before `fix` saw it.
#[test]
fn a_declined_multi_clause_range_is_reported() {
    let dir = workdir("fix_declined_multi_clause");
    let base = registry(vec![
        (
            "/lodash".to_string(),
            packument(&["1.0.0", "1.9.0", "2.0.0", "3.0.0"], "3.0.0"),
        ),
        (
            "/react".to_string(),
            packument(&["1.0.0", "1.9.0", "2.0.0", "3.0.0"], "3.0.0"),
        ),
    ]);
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    let original = "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"lodash\": \">=1.0.0 \
                    <2.0.0\",\n    \"react\": \"^1.0.0 || ^2.0.0\"\n  }\n}\n";
    fs::write(&manifest, original).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    for (name, constraint, target) in [
        ("lodash", ">=1.0.0 <2.0.0", "1.9.0"),
        ("react", "^1.0.0 || ^2.0.0", "2.0.0"),
    ] {
        assert!(
            stderr.contains(&format!("note: left {name} = {constraint} alone in "))
                && stderr.contains(&format!(
                    "{target} is available, but a space- or `||`-separated range has more than \
                     one clause and one version cannot carry them all"
                )),
            "no note for {name}.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
    assert!(
        !stdout.contains("Everything is already up to date."),
        "{stdout}"
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

/// A Composer stability flag. The front end now translates `2.8.*@dev` instead of
/// rejecting it, so the row carries an update and `DeclineReason::Qualifier` is
/// reached end to end — the flag qualifies the *range*, and substituting a
/// concrete release would drop it. Issue #87's harm, refused.
#[test]
fn a_declined_composer_stability_flag_is_reported() {
    let dir = workdir("fix_declined_stability_flag");
    let base = registry(vec![(
        "/p2/acme/lib.json".to_string(),
        packagist("acme/lib", &["1.0.0", "2.8.5", "3.0.0"]),
    )]);
    let config = write_config(&dir, &base);
    let manifest = dir.join("composer.json");
    let original =
        "{\n  \"name\": \"app/app\",\n  \"require\": {\n    \"acme/lib\": \"2.8.*@dev\"\n  }\n}\n";
    fs::write(&manifest, original).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains("note: left acme/lib = 2.8.*@dev alone in ")
            && stderr.contains(
                "2.8.5 is available, but an `@` qualifier — a stability flag or an alias — \
                 describes the range, not the version"
            ),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "{stdout}"
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), original);
}

// ---------------------------------------------------------------------------
// Forced versions (issue #111)
//
// An `overrides` / `resolutions` entry forces a version onto the resolved tree.
// `fix` skipped the whole kind before it ever looked at whether an update was
// waiting, so a stale forced version was indistinguishable from one with nothing
// to do — `check` reported it and `fix` answered "Everything is already up to
// date." The default is still never to write over one; `--overrides` is how the
// author asks.
// ---------------------------------------------------------------------------

/// A `package.json` forcing `lodash` to `1.0.0`, beside an ordinary dependency
/// that is already current so it contributes nothing to the counts below.
const FORCED_VERSION_MANIFEST: &str = "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \
                                       \"react\": \"^18.0.0\"\n  },\n  \"overrides\": {\n    \
                                       \"lodash\": \"1.0.0\"\n  }\n}\n";

/// `lodash` with a newer patch line and a newer major, and a `react` that has
/// only the release already declared. Written out rather than built by
/// [`packument`], which names `lodash` in every entry it writes.
fn forced_version_routes() -> Vec<(String, String)> {
    vec![
        (
            "/lodash".to_string(),
            packument(&["1.0.0", "1.9.0", "2.0.0"], "2.0.0"),
        ),
        (
            "/react".to_string(),
            "{\"name\":\"react\",\"dist-tags\":{\"latest\":\"18.0.0\"},\"versions\":\
             {\"18.0.0\":{\"name\":\"react\",\"version\":\"18.0.0\"}}}"
                .to_string(),
        ),
    ]
}

/// The defect as reported: an override with a newer release available produced no
/// output of any kind, and the run claimed to be up to date over the top of it.
#[test]
fn a_forced_version_is_reported_instead_of_silently_skipped() {
    let dir = workdir("fix_forced_version_reported");
    let base = registry(forced_version_routes());
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    fs::write(&manifest, FORCED_VERSION_MANIFEST).unwrap();

    let output = run_with_config(&dir, &config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains(&format!(
            "note: left lodash = 1.0.0 alone in {}",
            manifest.display()
        )) && stderr.contains(
            "1.9.0 is available, but an override forces this version onto the resolved \
                 tree; pass --overrides to advance it"
        ),
        "no note for the forced version.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Everything is already up to date."),
        "fix claimed everything was up to date over a forced version it left alone:\n{stdout}"
    );
    assert!(
        stdout.contains("Nothing to rewrite. 1 available update left alone"),
        "stdout: {stdout}"
    );
    // Reporting is not rewriting: the pin the author wrote is still exactly there.
    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        FORCED_VERSION_MANIFEST
    );
}

/// `--all` reaches beyond the declared constraint, and must still stop at a forced
/// version: it is the flag most likely to be aimed at a tree full of security pins.
#[test]
fn fix_all_still_leaves_a_forced_version_alone() {
    let dir = workdir("fix_forced_version_all");
    let base = registry(forced_version_routes());
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    fs::write(&manifest, FORCED_VERSION_MANIFEST).unwrap();

    let output = run_with_config(&dir, &config, &["--all"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stderr.contains("note: left lodash = 1.0.0 alone in ")
            && stderr.contains("2.0.0 is available, but an override forces this version"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        FORCED_VERSION_MANIFEST,
        "--all rewrote a forced version"
    );
}

/// Asked for by name, the forced version moves — and only then.
#[test]
fn overrides_are_rewritten_when_asked_for() {
    let dir = workdir("fix_forced_version_requested");
    let base = registry(forced_version_routes());
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    fs::write(&manifest, FORCED_VERSION_MANIFEST).unwrap();

    let output = run_with_config(&dir, &config, &["--overrides", "--all"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    let written = fs::read_to_string(&manifest).unwrap();
    assert!(
        written.contains("\"lodash\": \"2.0.0\""),
        "the forced version was not advanced: {written}"
    );
    // One span, in place: the neighbouring dependency and the formatting are not
    // this command's to touch.
    assert_eq!(
        written,
        FORCED_VERSION_MANIFEST.replace("\"lodash\": \"1.0.0\"", "\"lodash\": \"2.0.0\""),
        "more than the override's value span changed"
    );
    assert!(stdout.contains("Updated 1 dependency."), "stdout: {stdout}");
    assert!(
        !stderr.contains("note: left lodash"),
        "a rewritten override was also reported as left alone: {stderr}"
    );
}

/// `--overrides` is the destructive flag in this command, so the mode people use
/// to find out what it would do must still write nothing.
#[test]
fn a_requested_override_rewrite_honours_dry_run() {
    let dir = workdir("fix_forced_version_dry_run");
    let base = registry(forced_version_routes());
    let config = write_config(&dir, &base);
    let manifest = dir.join("package.json");
    fs::write(&manifest, FORCED_VERSION_MANIFEST).unwrap();
    let before = fs::metadata(&manifest).unwrap().modified().unwrap();

    let output = run_with_config(&dir, &config, &["--overrides", "--all", "--dry-run"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");

    assert!(
        stdout.contains("lodash 1.0.0 → 2.0.0"),
        "the dry run did not say what it would do: {stdout}"
    );
    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        FORCED_VERSION_MANIFEST,
        "a dry run rewrote a forced version"
    );
    assert_eq!(fs::metadata(&manifest).unwrap().modified().unwrap(), before);
}
