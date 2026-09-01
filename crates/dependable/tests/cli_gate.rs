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

fn text(body: impl Into<String>) -> Response {
    (200, "text/plain", body.into())
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
