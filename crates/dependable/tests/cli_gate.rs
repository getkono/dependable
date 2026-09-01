//! End-to-end coverage for the `--fail-on` gate, driven against a throwaway HTTP
//! registry on loopback.
//!
//! Every defect these falsify shipped past a review because the suite had no way to make
//! a registry *answer*: `cli_policy.rs` and `cli_sarif.rs` stay hermetic by declaring
//! path dependencies, so no fetch is ever built and no status code is ever seen. A gate
//! that turns on the difference between "the registry said no such package", "the
//! registry did not answer", and "this run could not read the constraint" cannot be
//! tested that way at all.
//!
//! So these run the real binary against a single-shot server on `127.0.0.1:0`, in the
//! shape `cli_fix.rs` established: hermetic, no dev-dependency, and the real fetch path
//! rather than a stub of it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

/// One canned response: status code, `Content-Type`, body.
type Response = (u16, &'static str, String);

fn json(body: impl Into<String>) -> Response {
    (200, "application/json", body.into())
}

fn text(body: impl Into<String>) -> Response {
    (200, "text/plain", body.into())
}

fn xml(body: impl Into<String>) -> Response {
    (200, "application/xml", body.into())
}

/// A status with no body — the shape a proxy's `404`/`410` takes.
fn status(code: u16) -> Response {
    (code, "text/plain", String::new())
}

/// A single-shot registry: a path-to-response table served on loopback.
///
/// Deliberately minimal rather than a mock-server crate — `dependable` has no
/// dev-dependencies at all. Unlike the fixture in `cli_fix.rs` this one carries the
/// status code and content type per route, because the defects here are *about* status
/// codes and about documents that are not JSON. Every response closes the connection, so
/// no keep-alive state has to be modelled. An unrouted path is a plain `404`.
fn registry(routes: Vec<(String, Response)>) -> String {
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
                // Drain the headers so the client is never left writing into a socket
                // nobody is reading, which some stacks report as a reset rather than as
                // the response we are about to send.
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                let (code, content_type, body) = routes
                    .iter()
                    .find(|(route, _)| *route == path)
                    .map(|(_, response)| response.clone())
                    .unwrap_or_else(|| status(404));
                let reason = match code {
                    200 => "OK",
                    404 => "Not Found",
                    410 => "Gone",
                    _ => "Status",
                };
                let response = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: \
                     {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    format!("http://{addr}")
}

/// An npm abbreviated packument: the version keys and the `latest` dist-tag are all the
/// version checker reads.
fn packument(name: &str, versions: &[&str], latest: &str) -> Response {
    let entries: Vec<String> = versions
        .iter()
        .map(|v| format!("\"{v}\":{{\"name\":\"{name}\",\"version\":\"{v}\"}}"))
        .collect();
    json(format!(
        "{{\"name\":\"{name}\",\"dist-tags\":{{\"latest\":\"{latest}\"}},\"versions\":{{{}}}}}",
        entries.join(",")
    ))
}

/// Point every ecosystem fetcher at `base` and switch OSV off, so a run touches nothing
/// but the loopback registry.
fn write_config(dir: &Path, base: &str) -> PathBuf {
    let config = dir.join(".dependable.toml");
    fs::write(
        &config,
        format!(
            "[npm]\nregistry = \"{base}\"\n\n[python]\nregistry = \"{base}/pypi\"\n\n\
             [go]\nregistry = \"{base}\"\n\n[jvm]\nregistry = \"{base}\"\n\n\
             [vulnerability]\nenabled = false\n"
        ),
    )
    .unwrap();
    config
}

fn check(dir: &Path, config: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependable"));
    command
        .arg("check")
        .arg(dir)
        .arg("--config")
        .arg(config)
        .arg("--no-cache")
        .arg("--no-vuln")
        .args(args);
    command.env_remove("DEPENDABLE_FAIL_ON");
    // A user `.npmrc` would override the configured registry and send the run at the
    // real npm.
    command.env("HOME", dir);
    command.current_dir(dir);
    command.output().expect("run dependable check")
}

/// `(stdout, stderr, exit code)`.
fn outcome(output: &Output) -> (String, String, i32) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

// ---------------------------------------------------------------------------
// A registry that answers "no such module" with `410 Gone`
// ---------------------------------------------------------------------------

/// The Go module proxy protocol names **both** `404` and `410` as the not-found
/// responses, and `410 Gone` is `proxy.golang.org`'s answer for a module it will not
/// serve — the private path the 404 carve-out exists for. Reading it as a transport
/// failure marked the whole registry unreachable, so one private module took a Go
/// repository from a passing `--fail-on vulnerable` (the shipped Action's default) to
/// exit 2.
#[test]
fn a_go_module_the_proxy_answers_410_for_does_not_break_the_gate() {
    let dir = workdir("gate_go_gone");
    let base = registry(vec![
        ("/github.com/acme/private/@v/list".to_string(), status(410)),
        ("/github.com/acme/private/@latest".to_string(), status(410)),
        (
            "/github.com/stretchr/testify/@v/list".to_string(),
            text("v1.8.0\nv1.9.0\n"),
        ),
    ]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/acme/private v0.1.0\n\t\
         github.com/stretchr/testify v1.8.0\n)\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "vulnerable"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("package `github.com/acme/private` not found"),
        "a 410 was not read as an absent module:\n{stdout}"
    );
    assert!(
        !stderr.contains("the registry did not answer"),
        "one private module marked the whole registry unreachable:\n{stderr}"
    );
    assert!(
        stderr.contains("note: 1 dependency was not found in its registry"),
        "stderr: {stderr}"
    );
    // The module that *did* resolve is still evaluated.
    assert!(stdout.contains("update available"), "stdout: {stdout}");
}

// ---------------------------------------------------------------------------
// The 404 carve-out covers a 404, and nothing else
// ---------------------------------------------------------------------------

/// The regression the carve-out introduced. An unparseable constraint never reaches a
/// registry, so nothing is established about the dependency at all — but it produced the
/// same `DependencyStatus::Error` as a 404 and was exempted with them. Two dependencies
/// were left unevaluated, the note blamed a registry that was never asked, and
/// `--fail-on vulnerable` certified the build.
#[test]
fn an_unreadable_constraint_still_refuses_to_certify_the_build() {
    let dir = workdir("gate_unreadable_constraint");
    let base = registry(vec![
        (
            "/lodash".to_string(),
            packument("lodash", &["4.17.20", "4.17.21"], "4.17.21"),
        ),
        (
            "/express".to_string(),
            packument("express", &["4.19.2"], "4.19.2"),
        ),
    ]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\"name\":\"app\",\"dependencies\":{\"lodash\":\"^^^bogus\",\"express\":\"^4.19.0\"}}\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "vulnerable"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("error: cannot honour --fail-on: 1 dependency could not be evaluated"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("not found in its registry"),
        "the note blamed a registry that was never asked:\n{stderr}"
    );
}

/// The other half, which must survive the repair: a registry that answers `404` answered.
/// A private or internal package is a permanent per-dependency fact, reported and not
/// gated on, and it must not turn `--fail-on vulnerable` into exit 2 for the
/// dependencies that did resolve.
#[test]
fn a_package_the_registry_answers_404_for_does_not_break_the_gate() {
    let dir = workdir("gate_404_carve_out");
    let base = registry(vec![(
        "/express".to_string(),
        packument("express", &["4.19.2"], "4.19.2"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\"name\":\"app\",\"dependencies\":{\"@acme/internal\":\"^1.0.0\",\"express\":\
         \"^4.19.0\"}}\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "vulnerable"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("note: 1 dependency was not found in its registry, so it is not gated on"),
        "stderr: {stderr}"
    );
    // `--quiet` says "Only print errors"; a note about what was skipped is not one.
    let quiet = check(&dir, &config, &["--fail-on", "vulnerable", "-q"]);
    let (_, quiet_stderr, quiet_code) = outcome(&quiet);
    assert_eq!(quiet_code, 0);
    assert!(
        !quiet_stderr.contains("not found in its registry"),
        "`-q` still printed the note: {quiet_stderr}"
    );
}

// ---------------------------------------------------------------------------
// A `>` inside an override key's range
// ---------------------------------------------------------------------------

/// pnpm and Yarn both allow a range in an override key, and a range contains `>`.
/// Splitting on every `>` cut each key inside its own range, so the run asked the
/// registry for `=1.0.0`, `=1`, `1.0.0` and `b` — and, with a 404 no longer failing the
/// gate, said nothing about it.
#[test]
fn an_override_key_carrying_a_range_is_checked_as_its_own_package() {
    let dir = workdir("gate_override_range");
    let base = registry(vec![
        (
            "/lodash".to_string(),
            packument("lodash", &["4.17.21"], "4.17.21"),
        ),
        ("/bar".to_string(), packument("bar", &["2.0.0"], "2.0.0")),
        ("/foo".to_string(), packument("foo", &["1.0.0"], "1.0.0")),
        ("/a".to_string(), packument("a", &["1.0.0"], "1.0.0")),
    ]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\"name\":\"app\",\"overrides\":{\"lodash@>=1.0.0\":\"4.17.21\",\"foo>bar@>=1\":\
         \"2.0.0\",\"foo@>1.0.0\":\"1.0.0\",\"a@>b\":\"1.0.0\",\"quux@1>bar@^2.1.0\":\"2.0.0\"}}\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "vulnerable"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    for fragment in ["=1.0.0", "not found"] {
        assert!(
            !stdout.contains(fragment),
            "a range fragment was read as a package name:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("lodash") && stdout.contains("bar") && stdout.contains("foo"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("5 up to date"), "stdout: {stdout}");
}

// ---------------------------------------------------------------------------
// Poetry's `"*"`
// ---------------------------------------------------------------------------

/// `*` is PEP 440's and Poetry's explicit "any version", and the most common way to
/// write an unpinned dependency. It translated to the empty string, which the
/// failed-translation heuristic then read as a constraint nobody could parse — so every
/// Poetry project with an unpinned dependency was excluded from `--fail-on outdated` and
/// failed `--fail-on any`.
#[test]
fn a_poetry_wildcard_resolves_instead_of_going_undetermined() {
    let dir = workdir("gate_poetry_wildcard");
    let base = registry(vec![(
        "/pypi/requests/json".to_string(),
        json("{\"releases\":{\"2.31.0\":[],\"2.32.3\":[]}}"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry.dependencies]\nrequests = \"*\"\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "any"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("up to date") && !stdout.contains("undetermined"),
        "stdout: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// `Undetermined` says so
// ---------------------------------------------------------------------------

/// `Undetermined` was gated on by nothing and noted by nothing, so a run that could not
/// read two constraints printed a clean `--fail-on outdated` and said nothing at all
/// about them. The status stays out of the gate — `--fail-on any` already fails on it —
/// but the run now says what it could not evaluate.
#[test]
fn a_dependency_whose_version_could_not_be_read_is_noted() {
    let dir = workdir("gate_undetermined_note");
    let base = registry(vec![(
        "/express".to_string(),
        packument("express", &["4.19.2"], "4.19.2"),
    )]);
    let config = write_config(&dir, &base);
    fs::write(
        dir.join("package.json"),
        "{\"name\":\"app\",\"dependencies\":{\"express\":\"^4.19.0\"},\"overrides\":\
         {\"lodash\":\"$nope\",\"minimist\":\"$\"}}\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "outdated"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    // `"$"` names nothing, and used to reach the checker as a literal constraint and
    // hard-fail on the `$`.
    assert!(
        !stdout.contains("unparseable constraint"),
        "a dangling reference was read as a constraint:\n{stdout}"
    );
    assert!(stdout.contains("2 undetermined"), "stdout: {stdout}");
    assert!(
        stderr.contains(
            "note: 2 dependencies have a declared version this run could not read, so they are \
             not gated on"
        ),
        "stderr: {stderr}"
    );

    let quiet = check(&dir, &config, &["--fail-on", "outdated", "-q"]);
    let (_, quiet_stderr, quiet_code) = outcome(&quiet);
    assert_eq!(quiet_code, 0);
    assert!(
        !quiet_stderr.contains("could not read"),
        "`-q` still printed the note: {quiet_stderr}"
    );
}

// ---------------------------------------------------------------------------
// A 200 that lists no versions
// ---------------------------------------------------------------------------

/// A `maven-metadata.xml` that parses but names no version is not an authoritative "this
/// artifact does not exist" — a Nexus or Artifactory group repository whose upstream
/// proxy is down serves exactly such a locally-merged document. Reporting it as a 404
/// exempted it from the gate, certifying a build against a dependency nothing was ever
/// known about.
#[test]
fn a_metadata_document_listing_no_versions_is_not_exempt_from_the_gate() {
    let dir = workdir("gate_empty_metadata");
    let base = registry(vec![(
        "/com/acme/thing/maven-metadata.xml".to_string(),
        xml(
            "<metadata><groupId>com.acme</groupId><artifactId>thing</artifactId><versioning>\
             <versions></versions></versioning></metadata>",
        ),
    )]);
    let config = write_config(&dir, &base);
    fs::create_dir_all(dir.join("gradle")).unwrap();
    fs::write(
        dir.join("gradle/libs.versions.toml"),
        "[libraries]\nthing = { module = \"com.acme:thing\", version = \"1.0.0\" }\n",
    )
    .unwrap();

    let output = check(&dir, &config, &["--fail-on", "vulnerable"]);
    let (stdout, stderr, code) = outcome(&output);

    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("error: cannot honour --fail-on: the registry did not answer"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("not found in its registry"),
        "an answered-but-empty document was reported as a 404:\n{stderr}"
    );
}
