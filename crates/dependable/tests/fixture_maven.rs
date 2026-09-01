//! Offline parse of the Maven fixture: a POM's coordinates, `${property}`
//! resolution, version-span round-tripping, and what a version this file cannot
//! resolve is reported as.

use std::path::{Path, PathBuf};
use std::process::Command;

use dependable_fetch::core::{DependencyKind, Item, PackageSource, parse, parse_project};
use dependable_fetch::{Ecosystem, ManifestKind};
use serde_json::Value;

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn slice<'a>(content: &'a str, item: &Item) -> &'a str {
    let line = content.lines().nth(item.version_line).unwrap();
    &line[item.version_col_start..item.version_col_end]
}

fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
    items
        .iter()
        .find(|item| item.name == name)
        .unwrap_or_else(|| panic!("no item {name}"))
}

#[test]
fn parses_a_maven_pom() {
    let path = fixture("sample-maven/pom.xml");
    let kind = ManifestKind::detect(&path).expect("recognised by name");
    assert_eq!(kind, ManifestKind::PomXml);
    assert_eq!(kind.ecosystem(), Ecosystem::Jvm);
    assert_eq!(kind.ecosystem().osv_name(), "Maven");

    let manifest = std::fs::read_to_string(&path).unwrap();
    let parsed = parse(kind, &manifest).unwrap();

    // Only `<dependencies>` under `<project>`: the `<parent>`, the
    // `<dependencyManagement>` entry, and the plugin's own dependency are not
    // dependencies of this artifact.
    let names: Vec<&str> = parsed.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "com.google.guava:guava",
            "com.squareup.okhttp3:okhttp",
            "com.fasterxml.jackson.core:jackson-core",
            "com.fasterxml.jackson.core:jackson-databind",
            "org.springframework.boot:spring-boot-starter-web",
            "com.example:sample-shared",
            "org.junit.jupiter:junit-jupiter",
        ]
    );

    // A version stated on the dependency is rewritable where it is written.
    let guava = find(&parsed.items, "com.google.guava:guava");
    assert_eq!(guava.version_constraint, "32.1.3-jre");
    assert_eq!(slice(&manifest, guava), "32.1.3-jre");
    assert_eq!(guava.source, PackageSource::Registry);
    assert!(guava.is_rewritable());

    // A property used once points at the `<properties>` line that governs it, so
    // `--fix` rewrites the version where Maven actually reads it.
    let okhttp = find(&parsed.items, "com.squareup.okhttp3:okhttp");
    assert_eq!(okhttp.version_constraint, "4.12.0");
    assert_eq!(slice(&manifest, okhttp), "4.12.0");
    assert!(okhttp.is_rewritable());
    assert!(
        manifest
            .lines()
            .nth(okhttp.version_line)
            .unwrap()
            .contains("okhttp.version"),
        "the span belongs to the <properties> entry, not to the <dependency>"
    );

    // A property two dependencies share is resolved but never rewritten: one line
    // cannot be rewritten to two different versions.
    for artifact in ["jackson-core", "jackson-databind"] {
        let item = find(
            &parsed.items,
            &format!("com.fasterxml.jackson.core:{artifact}"),
        );
        assert_eq!(item.version_constraint, "2.17.0", "{artifact}");
        assert_eq!(item.source, PackageSource::Inherited, "{artifact}");
        assert!(item.is_checkable(), "{artifact}");
        assert!(!item.is_rewritable(), "{artifact}");
    }

    // `<scope>` is stated in the manifest, so the section is read rather than guessed.
    let junit = find(&parsed.items, "org.junit.jupiter:junit-jupiter");
    assert_eq!(junit.kind, DependencyKind::Dev);
    assert_eq!(junit.version_constraint, "5.10.2");
}

/// The required behaviour. A version supplied by a `<parent>` and one written as a
/// Maven built-in are both out of a parser's reach, and both are **reported** with no
/// constraint rather than dropped. Dropping them, the way the `csproj` parser drops an
/// MSBuild `$(…)` version, would present a POM that inherits some of its versions as
/// depending on only the rest — a short list that looks complete.
#[test]
fn a_version_this_file_cannot_resolve_is_reported_rather_than_dropped() {
    let path = fixture("sample-maven/pom.xml");
    let manifest = std::fs::read_to_string(&path).unwrap();
    let parsed = parse(ManifestKind::PomXml, &manifest).unwrap();

    for name in [
        "org.springframework.boot:spring-boot-starter-web",
        "com.example:sample-shared",
    ] {
        let item = find(&parsed.items, name);
        assert!(item.version_constraint.is_empty(), "{name}");
        assert_eq!(item.source, PackageSource::Inherited, "{name}");
        // Nothing is claimed about it: it is not fetched, not positioned, not fixed.
        assert!(!item.is_checkable(), "{name}");
        assert!(!item.has_position(), "{name}");
        assert!(!item.is_rewritable(), "{name}");
    }
}

/// A POM names itself by coordinate, and the `<parent>`'s coordinate is not it.
#[test]
fn a_pom_reports_its_own_coordinate() {
    let manifest = std::fs::read_to_string(fixture("sample-maven/pom.xml")).unwrap();
    let meta = parse_project(ManifestKind::PomXml, &manifest);
    assert_eq!(meta.name.as_deref(), Some("com.example:sample-maven"));
    assert_eq!(meta.literal_version(), Some("1.4.0"));
}

/// The other half of the requirement, at the surface a user sees: `list` is offline,
/// so it reports exactly what the parser produced. An unresolvable dependency is
/// present with a null constraint and an `inherited` source — visible, and not
/// mistaken for one that was checked.
#[test]
fn the_cli_lists_an_unresolvable_dependency_instead_of_omitting_it() {
    let output = Command::new(env!("CARGO_BIN_EXE_dependable"))
        .args([
            "list",
            fixture("sample-maven").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run dependable");
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let project = doc["projects"]
        .as_array()
        .expect("projects array")
        .iter()
        .find(|p| p["name"] == "com.example:sample-maven")
        .unwrap_or_else(|| panic!("no Maven project in {}", doc["projects"]));
    assert_eq!(project["ecosystem"], "JVM");

    let dependencies = project["dependencies"].as_array().expect("dependencies");
    let dependency = |name: &str| {
        dependencies
            .iter()
            .find(|d| d["name"] == name)
            .unwrap_or_else(|| panic!("no dependency {name}"))
    };

    let unresolved = dependency("org.springframework.boot:spring-boot-starter-web");
    assert!(unresolved["constraint"].is_null(), "{unresolved}");
    assert_eq!(unresolved["source"], "inherited");

    let guava = dependency("com.google.guava:guava");
    assert_eq!(guava["constraint"], "32.1.3-jre");
    assert_eq!(guava["source"], "registry");
}
