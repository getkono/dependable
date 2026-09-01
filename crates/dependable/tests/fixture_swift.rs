//! Offline read of the Swift fixture, plus the statements a Swift run owes its
//! reader.
//!
//! Swift is the one ecosystem here with no registry, so its results are shaped
//! differently from every other ecosystem's: `Package.resolved` supplies the
//! dependencies, OSV supplies the only verdict there is, and *currency is never
//! claimed*. These tests hold that shape in place — the failure mode this feature
//! exists to prevent is a clean-looking Swift run that quietly means nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

use dependable_fetch::ManifestKind;
use dependable_fetch::core::{Item, PackageSource, lockfile_items, parse, swift_package_name};
use dependable_fetch::{Ecosystem, LockfileKind};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

/// The pins recorded by the `Package.resolved` at `rel`.
fn pins(rel: &str) -> Vec<Item> {
    let content = std::fs::read_to_string(fixture(rel)).expect("read the fixture");
    lockfile_items(LockfileKind::PackageResolved, &content)
        .expect("Package.resolved supplies items")
}

fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
    items
        .iter()
        .find(|item| item.name == name)
        .unwrap_or_else(|| panic!("no pin {name} in {:?}", names(items)))
}

fn names(items: &[Item]) -> Vec<&str> {
    items.iter().map(|item| item.name.as_str()).collect()
}

/// A `Package.swift` is a Swift program. The fixture deliberately assembles its
/// dependencies in a loop and behind a `#if`, which is what makes any text-level
/// reading of it wrong rather than merely partial.
#[test]
fn package_swift_declares_nothing_because_it_is_a_program() {
    let manifest = std::fs::read_to_string(fixture("sample-swift/Package.swift")).unwrap();
    assert!(manifest.contains("for (name, version) in extraPackages"));
    assert!(manifest.contains("#if canImport(Darwin)"));

    let parsed = parse(ManifestKind::PackageSwift, &manifest).expect("never fails");
    assert!(parsed.items.is_empty(), "Package.swift must not be read");
    assert_eq!(ManifestKind::PackageSwift.ecosystem(), Ecosystem::Swift);
    assert!(
        !Ecosystem::Swift.has_registry(),
        "the whole shape of this ecosystem follows from this"
    );
}

/// v3 (`originHash`, `"version": 3`) and v2 record the same pins in the same
/// shape, so a project resolved by either Xcode 15 or Swift 5.6 must read alike.
#[test]
fn v2_and_v3_package_resolved_yield_the_same_pins() {
    let v3 = pins("sample-swift/Package.resolved");
    let v2 = pins("sample-swift/legacy/Package.resolved");
    assert_eq!(v2, v3, "the format version must not change the answer");

    assert_eq!(
        names(&v3),
        [
            "github.com/apple/swift-crypto",
            "github.com/apple/swift-log",
            "github.com/apple/swift-nio",
            "github.com/apple/swift-atomics",
            "sample-helpers",
            "github.com/acme/swift-experimental",
        ],
        "every pin, in the order the file records them"
    );
}

/// `Package.resolved` records the flattened resolution. The fixture's
/// `Package.swift` declares swift-nio and never mentions swift-atomics, yet the
/// pin list holds both and marks neither apart — so nothing read from it may be
/// called a direct dependency. `list --format json` publishes that as a boolean a
/// machine reads, and `"direct": true` on a transitive pin is a claim the file
/// never made.
#[test]
fn no_pin_is_published_as_a_direct_dependency() {
    let manifest = std::fs::read_to_string(fixture("sample-swift/Package.swift")).unwrap();
    let code: String = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("swift-atomics"),
        "the fixture's transitive pin must not be declared by its manifest"
    );

    for item in pins("sample-swift/Package.resolved") {
        assert!(
            !item.kind.is_direct(),
            "{}: a flattened resolution cannot say which pins are direct",
            item.name
        );
    }

    let output = run(&[
        "list",
        "--manifest",
        fixture("sample-swift/Package.swift").to_str().unwrap(),
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("\"name\": \"github.com/apple/swift-atomics\""),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("\"direct\": true"),
        "no Swift pin may be published as direct; stdout: {stdout}"
    );
}

/// The names are what OSV keys `SwiftURL` advisories by. Scheme and `.git` left on
/// match nothing, and matching nothing is indistinguishable from being clean.
#[test]
fn a_pin_is_named_by_the_url_osv_keys_advisories_by() {
    let items = pins("sample-swift/Package.resolved");
    let nio = find(&items, "github.com/apple/swift-nio");
    assert_eq!(nio.locked_version.as_deref(), Some("2.65.0"));
    assert_eq!(
        swift_package_name("https://github.com/apple/swift-nio.git"),
        nio.name
    );
    assert_eq!(Ecosystem::Swift.osv_name(), "SwiftURL");
    assert_eq!(
        Ecosystem::Swift.package_url(&nio.name),
        "https://github.com/apple/swift-nio",
        "the repository, never an invented registry page"
    );
}

/// Every other fixture test slices the manifest at a dependency's recorded span
/// and asserts it round-trips. There is nothing to slice here, and that is the
/// assertion: a Swift version is written in `Package.resolved`, not in any file
/// this tool parsed, so nothing may point at it and `--fix` can never rewrite it.
#[test]
fn a_swift_dependency_has_no_position_and_is_never_rewritable() {
    for item in pins("sample-swift/Package.resolved") {
        assert!(
            !item.has_position(),
            "{}: no span in Package.swift means nothing may point at one",
            item.name
        );
        assert!(
            !item.is_rewritable(),
            "{}: `--fix` must never edit a Swift project",
            item.name
        );
        assert_eq!(item.version_line, 0);
        assert_eq!(item.version_col_start, item.version_col_end);
    }
}

/// A branch pin has no version to compare or to query, and a local package has no
/// registry in any ecosystem. Neither is `Undetermined`: both are states every
/// other ecosystem already reports the same way.
#[test]
fn a_branch_pin_and_a_local_package_report_what_they_always_did() {
    let items = pins("sample-swift/Package.resolved");

    let experimental = find(&items, "github.com/acme/swift-experimental");
    assert_eq!(experimental.source, PackageSource::Git);
    assert_eq!(experimental.version_constraint, "main");
    assert!(!experimental.is_checkable());

    let helpers = find(&items, "sample-helpers");
    assert_eq!(helpers.source, PackageSource::Local);
    assert!(!helpers.is_checkable());
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args(args)
        .output()
        .expect("run dependable")
}

/// The requirement the issue calls the hard part: a Swift `check` that turns up no
/// advisories must not read as "all current". Hermetic — `--no-vuln` is the only
/// network this command would have used, since there is no registry to fetch from.
#[test]
fn check_says_out_loud_that_currency_was_never_established() {
    let manifest = fixture("sample-swift/Package.swift");
    let output = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-vuln",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "expected exit 0; stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stderr.contains("Swift publishes no package registry"),
        "the limitation must be stated, not inferred; stderr: {stderr}"
    );
    assert!(
        stderr.contains("vulnerability scanning off"),
        "`--no-vuln` means no verdict at all, and the notice must not claim one ran; \
         stderr: {stderr}"
    );
    assert!(stderr.contains("`--fix` cannot apply"), "stderr: {stderr}");
    assert!(
        !stdout.contains("up to date") || stdout.contains("undetermined"),
        "no dependency may be reported current; stdout: {stdout}"
    );
}

/// `list` reads no registry at all, so it is the command that shows a Swift
/// project is *found* — and it only can because `Package.resolved` supplies the
/// items its manifest declines to.
#[test]
fn list_surfaces_the_pins_a_package_swift_never_declared() {
    let manifest = fixture("sample-swift/Package.swift");
    let output = run(&["list", "--manifest", manifest.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("github.com/apple/swift-nio"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("2.65.0"), "stdout: {stdout}");
}

/// `--no-lock-file` is documented as "do not report locked versions" — it suppresses
/// an *annotation*. A `Package.resolved` is not an annotation: it is the only
/// dependency list a Swift project has. Honouring the flag there turned
/// `list --no-lock-file` into a silent assertion that the project depends on nothing,
/// with no warning anywhere, which is the same inversion issue #85 exists to prevent.
#[test]
fn no_lock_file_does_not_empty_a_swift_dependency_list() {
    let manifest = fixture("sample-swift/Package.swift");
    let output = run(&[
        "list",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-lock-file",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("github.com/apple/swift-nio"),
        "the pins are the dependency list, not an annotation on one; stdout: {stdout}"
    );
    assert!(
        !stdout.contains("(0 dependencies)"),
        "a Swift project must never be listed as depending on nothing; stdout: {stdout}"
    );
}

/// The same flag on the command that decides the exit code. `list` was taught that a
/// `Package.resolved` is the dependency list rather than an annotation on one; `check`
/// was not, so `--no-lock-file` handed the OSV scan an empty item list. A Swift project
/// with a known-vulnerable pin then reported clean and exited 0 — a silent security
/// false negative, and the exact inversion the flag's own help text disclaims.
#[test]
fn no_lock_file_does_not_empty_what_check_scans() {
    let manifest = fixture("sample-swift/Package.swift");
    let output = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-lock-file",
        "--no-vuln",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("github.com/apple/swift-nio"),
        "the pins are what `check` has to scan; stdout: {stdout}"
    );
    assert!(
        !stdout.contains("(0 dependencies)") && !stdout.contains("nothing to check"),
        "an empty scan of a resolved project is a false clean bill; stdout: {stdout}"
    );
    assert!(
        !stderr.contains("no dependency with a version to check was found here at all"),
        "there are four; stderr: {stderr}"
    );

    // The exit code is what a CI job acts on, and it was the part that silently
    // inverted: nothing scanned means nothing found means success.
    let gated = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-lock-file",
        "--no-vuln",
        "--fail-on",
        "any",
    ]);
    assert_eq!(
        gated.status.code(),
        Some(1),
        "`--fail-on any` over four undetermined pins must fail exactly as it does without the flag"
    );

    // …and `--format json` must publish the same list, not a summary of nothing.
    let json = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-lock-file",
        "--no-vuln",
        "--format",
        "json",
    ]);
    let doc: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("`check --format json` emits JSON");
    assert_eq!(doc["summary"]["total"], 6, "{doc}");
    assert_eq!(doc["summary"]["undetermined"], 4, "{doc}");
}

/// The other half of the same flag: for a lockfile that only *annotates* a list the
/// manifest already produced, `--no-lock-file` must still suppress it. Fixing Swift
/// by ignoring the flag everywhere would have taken this with it.
#[test]
fn no_lock_file_still_suppresses_an_annotating_lockfile() {
    let manifest = fixture("sample-rust/Cargo.toml");
    let with = run(&[
        "list",
        "--manifest",
        manifest.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let without = run(&[
        "list",
        "--manifest",
        manifest.to_str().unwrap(),
        "--format",
        "json",
        "--no-lock-file",
    ]);
    let with = String::from_utf8_lossy(&with.stdout).into_owned();
    let without = String::from_utf8_lossy(&without.stdout).into_owned();

    assert!(
        with.contains("Cargo.lock") && with.contains("\"locked\": \"1.0.100\""),
        "the fixture must have a lockfile to suppress; stdout: {with}"
    );
    assert!(
        !without.contains("Cargo.lock") && !without.contains("\"locked\": \"1.0.100\""),
        "`--no-lock-file` must still ignore an annotating lockfile; stdout: {without}"
    );
}

/// Switching Swift off has to switch it off. Without the checker-level opt-in this
/// key would parse, validate, and do nothing.
#[test]
fn a_disabled_swift_ecosystem_is_skipped() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("swift_disabled");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("dependable.toml");
    std::fs::write(&config, "[swift]\nenabled = false\n").unwrap();

    let manifest = fixture("sample-swift/Package.swift");
    let output = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--no-vuln",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("skipping") && stderr.contains("Swift"),
        "a disabled ecosystem is skipped, exactly as every other one is; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("Swift publishes no package registry"),
        "nothing to say about an ecosystem that was not checked; stderr: {stderr}"
    );
}

/// `fix` used to end every run that rewrote nothing with "Everything is already up
/// to date." For a Swift project it rewrites nothing *by construction*, so that
/// line would be a flat claim of currency on the one ecosystem that can never
/// establish it.
#[test]
fn fix_never_claims_a_swift_project_is_up_to_date() {
    let manifest = fixture("sample-swift/Package.swift");
    let output = run(&["fix", "--manifest", manifest.to_str().unwrap(), "--dry-run"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        !stdout.contains("Everything is already up to date"),
        "\"we did not look\" must never be printed as \"we looked and found nothing\"; \
         stdout: {stdout}"
    );
    assert!(
        stdout.contains("could not be checked for a newer version"),
        "stdout: {stdout}"
    );
    // And the manifest is left exactly as it was.
    let before = std::fs::read_to_string(&manifest).unwrap();
    assert!(before.contains("for (name, version) in extraPackages"));
}

/// Live: the one verdict a Swift run can actually give. `SwiftURL` advisories are
/// keyed by the repository URL with no scheme and no `.git`, and getting that
/// wrong fails silently — it reports a vulnerable package as clean — so only a
/// real query proves the mapping. Ignored by default; `mise run test:live`.
#[test]
#[ignore = "queries api.osv.dev"]
fn live_osv_reports_a_known_vulnerable_swift_package() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("swift_live_osv");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Package.swift"), "// swift-tools-version:5.9\n").unwrap();
    // Vapor 4.83.0 is affected by GHSA-r6r4-5pr8-gjcp (integer overflow in URI).
    std::fs::write(
        dir.join("Package.resolved"),
        r#"{
  "pins" : [
    {
      "identity" : "vapor",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/vapor/vapor.git",
      "state" : { "revision" : "0f1b6d", "version" : "4.83.0" }
    }
  ],
  "version" : 2
}"#,
    )
    .unwrap();

    let manifest = dir.join("Package.swift");
    let output = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--include-ghsa",
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("\"VULN\""),
        "an advisory keyed by repository URL must match; stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("GHSA-r6r4-5pr8-gjcp"), "stdout: {stdout}");
}

/// A scratch directory with a `.git`, so the lockfile walk sees a repository
/// boundary exactly where a real checkout would put one.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".git")).expect("create the scratch repository");
    dir
}

/// A nested SwiftPM package must never adopt an ancestor's `Package.resolved`.
///
/// The upward walk is right for the five lockfiles that *annotate* a list some
/// manifest declared — an unused pin costs nothing. It is wrong for the one that
/// **is** the list: the nested package here declares neither of the root's
/// dependencies, and adopting them reports the root's packages as its own. With
/// scanning on that attributes the root's advisories to a project that does not
/// have the dependency — a false positive on the one verdict Swift can give — and
/// in a SwiftPM monorepo it happens to every package not yet resolved.
#[test]
fn a_nested_package_does_not_adopt_an_ancestors_package_resolved() {
    let root = scratch("swift_monorepo");
    let nested = root.join("Examples/Demo");
    std::fs::create_dir_all(&nested).unwrap();
    let manifest = std::fs::read_to_string(fixture("sample-swift/Package.swift")).unwrap();
    std::fs::write(root.join("Package.swift"), &manifest).unwrap();
    std::fs::copy(
        fixture("sample-swift/Package.resolved"),
        root.join("Package.resolved"),
    )
    .unwrap();
    std::fs::write(nested.join("Package.swift"), &manifest).unwrap();

    let output = run(&[
        "check",
        "--manifest",
        nested.join("Package.swift").to_str().unwrap(),
        "--no-vuln",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("github.com/apple/swift-nio"),
        "the nested package declares none of the root's dependencies; stdout: {stdout}"
    );
    assert!(
        stderr.contains("Package.resolved") && stderr.contains("is not here"),
        "and it must say the list is unknown rather than empty; stderr: {stderr}"
    );

    // The root itself is unaffected: its own Package.resolved sits beside it.
    let output = run(&[
        "check",
        "--manifest",
        root.join("Package.swift").to_str().unwrap(),
        "--no-vuln",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("github.com/apple/swift-nio"),
        "stdout: {stdout}"
    );
}

/// Apple advises library packages *not* to commit `Package.resolved`, so a Swift
/// project with none is the common state rather than an edge. Nothing about it may
/// read as "this project has no dependencies": `Package.swift` is a program this
/// tool declines to read, so the list was never seen, and `--fail-on any` — which
/// asks whether everything here is checked and current — must not answer yes.
#[test]
fn a_swift_project_with_no_package_resolved_says_so_and_fails_a_strict_gate() {
    let dir = scratch("swift_no_resolved");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        dir.join("Package.swift"),
    )
    .unwrap();
    let manifest = dir.join("Package.swift");

    let output = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-vuln",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is not here") && stderr.contains("`swift package resolve`"),
        "the cause must be named; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("0 dependencies here"),
        "\"we could not look\" must not be phrased as a count of what is here; \
         stderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "no gate was asked for; stderr: {stderr}"
    );

    let strict = run(&[
        "check",
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-vuln",
        "--fail-on",
        "any",
    ]);
    assert!(
        !strict.status.success(),
        "exit 0 would assert that a list nobody read is clean; stdout: {}",
        String::from_utf8_lossy(&strict.stdout)
    );
}

/// A half-written `Package.resolved` used to crash the process outright, and the
/// degradation waiting behind that crash was worse: a *prefix* of the pins,
/// presented as the whole dependency list, with the packages past the cut never
/// scanned and nothing said about it.
#[test]
fn a_truncated_package_resolved_is_reported_unread_rather_than_read_short() {
    let dir = scratch("swift_truncated");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        dir.join("Package.swift"),
    )
    .unwrap();
    let whole = std::fs::read_to_string(fixture("sample-swift/Package.resolved")).unwrap();
    // Past the first pin and into the second, so a partial scan would return a
    // plausible, and wrong, list.
    let cut = whole.find("swift-log").expect("the second pin") + 20;
    std::fs::write(dir.join("Package.resolved"), &whole[..cut]).unwrap();

    for command in [
        vec!["list", dir.to_str().unwrap()],
        vec![
            "check",
            "--manifest",
            dir.join("Package.swift").to_str().unwrap(),
            "--no-vuln",
        ],
    ] {
        let output = run(&command);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("panicked"),
            "{command:?} must not crash; stderr: {stderr}"
        );
        assert!(
            !stdout.contains("swift-crypto"),
            "{command:?}: a prefix of the pins is not a dependency list; stdout: {stdout}"
        );
        assert!(
            stderr.contains("could not be parsed"),
            "{command:?}: and the file must be reported unread; stderr: {stderr}"
        );
    }
}

/// The machine-readable twin of the exit-code inversion, and the reason it matters:
/// a CI job that parses `--format json` never sees an exit code per manifest.
///
/// Two Swift projects — one with no `Package.resolved` at all, one with a genuinely
/// empty pin set — must not produce the same document. Every status count is a tally
/// of rows that *were* read, so both are zero either way; `manifests_unread` is the
/// only field that separates "we looked and there is nothing" from "we never looked".
#[test]
fn json_distinguishes_an_unread_dependency_list_from_an_empty_one() {
    let unread = scratch("swift_json_unread");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        unread.join("Package.swift"),
    )
    .unwrap();

    let empty = scratch("swift_json_empty");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        empty.join("Package.swift"),
    )
    .unwrap();
    std::fs::write(empty.join("Package.resolved"), r#"{"pins":[],"version":2}"#).unwrap();

    let document = |dir: &Path| {
        let output = run(&[
            "check",
            "--manifest",
            dir.join("Package.swift").to_str().unwrap(),
            "--no-vuln",
            "--format",
            "json",
        ]);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("a JSON document")
    };

    let unread = document(&unread);
    let empty = document(&empty);

    assert_ne!(
        unread, empty,
        "a project nothing was read from must not serialize as a clean one"
    );
    assert_eq!(unread["summary"]["manifests_unread"], 1);
    assert_eq!(empty["summary"]["manifests_unread"], 0);
    // The pinned shape is unchanged: every documented key keeps its name and value,
    // so a consumer that does not know about the new one is unaffected.
    for key in [
        "total",
        "vulnerable",
        "error",
        "undetermined",
        "up_to_date",
        "outdated",
    ] {
        assert_eq!(unread["summary"][key], 0, "{key}");
        assert_eq!(empty["summary"][key], 0, "{key}");
    }
    assert_eq!(unread["results"].as_array().unwrap().len(), 0);
}

/// The same distinction in SARIF, which has no summary object to carry a counter:
/// the unread manifest gets a `DEP003` result naming it, and the empty one gets the
/// empty `results` array it has earned.
#[test]
fn sarif_reports_an_unread_dependency_list_as_a_finding() {
    let unread_dir = scratch("swift_sarif_unread");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        unread_dir.join("Package.swift"),
    )
    .unwrap();

    let empty = scratch("swift_sarif_empty");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        empty.join("Package.swift"),
    )
    .unwrap();
    std::fs::write(empty.join("Package.resolved"), r#"{"pins":[],"version":2}"#).unwrap();

    let results = |dir: &Path| {
        let output = run(&[
            "check",
            "--manifest",
            dir.join("Package.swift").to_str().unwrap(),
            "--no-vuln",
            "--format",
            "sarif",
        ]);
        let log: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("a SARIF document");
        log["runs"][0]["results"].as_array().cloned().unwrap()
    };

    let unread = results(&unread_dir);
    let empty = results(&empty);

    assert_eq!(
        empty.len(),
        0,
        "a resolved project with no pins genuinely has no findings"
    );
    assert_eq!(
        unread.len(),
        1,
        "an unread dependency list is a finding of its own: {unread:?}"
    );
    assert_eq!(unread[0]["ruleId"], "DEP003");
    assert_eq!(unread[0]["level"], "warning");
    assert!(
        unread[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("a uri")
            .ends_with("Package.swift"),
        "the finding must name the manifest it is about: {unread:?}"
    );
    // No package was read, so none is named — and `region` is absent because the
    // missing information is a file that is not there, not a line in this one.
    assert!(unread[0]["properties"].get("package").is_none());
    assert!(
        unread[0]["locations"][0]["physicalLocation"]
            .get("region")
            .is_none()
    );

    // `properties.status` otherwise always holds a `DependencyStatus` token, so a
    // consumer switching on it exhaustively is doing the one safe thing with the
    // key. DEP003 must not put a word there that no status can produce; the fact
    // is about the manifest and gets its own key.
    assert!(
        unread[0]["properties"].get("status").is_none(),
        "DEP003 names no dependency, so it claims no dependency status: {unread:?}"
    );
    assert_eq!(unread[0]["properties"]["dependencyListUnread"], true);

    // The strings a Code Scanning alert renders verbatim. Wrapped string literals
    // without `\` continuations carried runs of 14-18 literal spaces into them.
    let text = |value: &serde_json::Value| value.as_str().expect("a string").to_owned();
    let rule = {
        let output = run(&[
            "check",
            "--manifest",
            unread_dir.join("Package.swift").to_str().unwrap(),
            "--no-vuln",
            "--format",
            "sarif",
        ]);
        let log: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("a SARIF document");
        log["runs"][0]["tool"]["driver"]["rules"][2].clone()
    };
    assert_eq!(rule["id"], "DEP003");
    for rendered in [
        text(&unread[0]["message"]["text"]),
        text(&rule["fullDescription"]["text"]),
        text(&rule["help"]["text"]),
    ] {
        assert!(
            !rendered.contains("  "),
            "a run of spaces renders verbatim in the alert: {rendered:?}"
        );
    }
}

/// An HTML report is frequently the only artifact a reviewer ever sees, so the fact
/// that a project's dependency list went unread has to be *in the document*.
///
/// It used to reach the page only as a run note, and `report --quiet` drops notes —
/// so the quiet artifact for a Swift project with no `Package.resolved` was
/// byte-for-byte the shape of a resolved, clean one, right down to §3 asserting
/// "This manifest declares no dependencies", which nothing had established.
#[test]
fn a_quiet_html_report_still_says_the_dependency_list_went_unread() {
    let unread_dir = scratch("swift_html_unread");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        unread_dir.join("Package.swift"),
    )
    .unwrap();

    let empty_dir = scratch("swift_html_empty");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        empty_dir.join("Package.swift"),
    )
    .unwrap();
    std::fs::write(
        empty_dir.join("Package.resolved"),
        r#"{"pins":[],"version":2}"#,
    )
    .unwrap();

    let render = |dir: &Path| {
        let out = dir.join("report.html");
        let output = run(&[
            "report",
            "--manifest",
            dir.join("Package.swift").to_str().unwrap(),
            "--no-vuln",
            "--quiet",
            "--output",
            out.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The templates wrap their prose, so the rendered document carries newlines
        // inside sentences. Collapse them, or an assertion about a phrase would be
        // an assertion about where a template happens to break its lines.
        std::fs::read_to_string(&out)
            .expect("the report was written")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };

    let unread = render(&unread_dir);
    let empty = render(&empty_dir);

    assert!(
        unread.contains("no readable dependency list"),
        "the summary must carry the caveat structurally, not as a suppressible note"
    );
    assert!(
        unread.contains("could not be read"),
        "and the manifest's own section must say which project it is about"
    );
    assert!(
        !unread.contains("This manifest declares no dependencies"),
        "nothing established that; the file that would have said so was never read"
    );
    // §3's headings are what a reader skims, and a count is a claim. "(0
    // dependencies)" sat directly above the paragraph disclaiming it, so the
    // heading asserted exactly what the prose below denied.
    assert!(
        !unread.contains("Swift (0 dependencies)"),
        "the heading counted a list nobody read: {unread}"
    );
    assert!(
        unread.contains("Swift (dependency list unread)"),
        "the heading has to say the list went unread: {unread}"
    );

    // The other half: a project that really is resolved and really has no pins is
    // still reported exactly as before, with no caveat it has not earned.
    assert!(
        !empty.contains("no readable dependency list") && !empty.contains("could not be read"),
        "a resolved project with no pins has nothing to caveat"
    );
    assert!(empty.contains("This manifest declares no dependencies"));
    assert!(
        empty.contains("Swift (0 dependencies)"),
        "a resolved project with no pins really does declare none: {empty}"
    );
}

/// The same claim in the same words, in the output most runs actually look at.
/// `check`'s per-manifest heading counted the results it had, so a Swift project
/// with no readable `Package.resolved` was headed "(0 dependencies)" — a statement
/// about the project, made by a run that read nothing about it.
#[test]
fn the_check_heading_says_the_list_went_unread_rather_than_counting_zero() {
    let unread_dir = scratch("swift_check_heading_unread");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        unread_dir.join("Package.swift"),
    )
    .unwrap();

    let empty_dir = scratch("swift_check_heading_empty");
    std::fs::copy(
        fixture("sample-swift/Package.swift"),
        empty_dir.join("Package.swift"),
    )
    .unwrap();
    std::fs::write(
        empty_dir.join("Package.resolved"),
        r#"{"pins":[],"version":2}"#,
    )
    .unwrap();

    let heading = |dir: &Path| {
        let output = run(&[
            "check",
            "--manifest",
            dir.join("Package.swift").to_str().unwrap(),
            "--no-vuln",
        ]);
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let unread = heading(&unread_dir);
    assert!(
        !unread.contains("(0 dependencies)"),
        "nothing was counted because nothing was read: {unread}"
    );
    assert!(
        unread.contains("Swift (dependency list unread)"),
        "the heading has to say so: {unread}"
    );

    // And a project that really is resolved and really has no pins still counts.
    let empty = heading(&empty_dir);
    assert!(
        empty.contains("Swift (0 dependencies)"),
        "a resolved project with no pins declares none, and says so: {empty}"
    );
}
