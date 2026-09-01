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

/// Point the ecosystem fetchers at `base` and switch OSV off, so a run touches
/// nothing but the loopback registry.
fn write_config(dir: &Path, base: &str) -> PathBuf {
    let config = dir.join(".dependable.toml");
    fs::write(
        &config,
        format!(
            "[npm]\nregistry = \"{base}\"\n\n[python]\nregistry = \"{base}/pypi\"\n\n\
             [vulnerability]\nenabled = false\n"
        ),
    )
    .unwrap();
    config
}

fn run_with_config(dir: &Path, config: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependable"));
    command
        .arg("fix")
        .arg(dir)
        .arg("--config")
        .arg(config)
        .arg("--no-cache")
        .arg("--no-vuln")
        .args(args);
    command.env_remove("DEPENDABLE_FAIL_ON");
    // A user `.npmrc` would override the configured registry and send the run at
    // the real npm.
    command.env("HOME", dir);
    command.current_dir(dir);
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

/// A compound range: two bounds one version cannot carry. Python, because a
/// comma-separated range is the compound form the checker actually parses — an
/// npm space range is reported as an unreadable constraint and never reaches the
/// rewrite at all.
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
