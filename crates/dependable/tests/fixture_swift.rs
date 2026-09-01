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
            "sample-helpers",
            "github.com/acme/swift-experimental",
        ],
        "every pin, in the order the file records them"
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
