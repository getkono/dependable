//! Offline parse of the Maven fixture: a POM's coordinates, `${property}`
//! resolution, version-span round-tripping, and what a version this file cannot
//! resolve is reported as.
//!
//! The `check`-level tests are hermetic the same way `cli_workspace` is: the JVM
//! registry points at `http://127.0.0.1:1`, where the connection is refused at
//! once. Nothing here depends on what a registry would have said — what is under
//! test is how a dependency this file states **no version for** is classified,
//! which is decided before any request is made.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
    assert_eq!(guava["inherited"], false, "its version is its own: {guava}");

    // `source` and `inherited` describe the same fact, so they can never disagree
    // on one object. They used to: the boolean was filled in only by Cargo
    // workspace resolution, so every non-Cargo `"source": "inherited"` arrived
    // beside `"inherited": false`, and a consumer reading both got a
    // contradiction.
    for name in [
        "com.fasterxml.jackson.core:jackson-core",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.springframework.boot:spring-boot-starter-web",
    ] {
        let entry = dependency(name);
        assert_eq!(entry["source"], "inherited", "{entry}");
        assert_eq!(entry["inherited"], true, "{entry}");
    }
}

/// A registry nothing is listening on: `connect` fails at once.
const OFFLINE: &str = "[jvm]\nregistry = \"http://127.0.0.1:1\"\n";

/// A temp directory holding one `pom.xml`, walled off from this repository.
fn pom_dir(name: &str, body: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // A repository boundary, so the discovery walk stays inside the temp dir.
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join("dependable.toml"), OFFLINE).unwrap();
    fs::write(
        dir.join("pom.xml"),
        format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
             <groupId>com.example</groupId>\n  \
             <artifactId>app</artifactId>\n  \
             <version>1.0.0</version>\n{body}</project>\n"
        ),
    )
    .unwrap();
    dir
}

/// Run the CLI in `dir`. `--config` and the hermetic flags belong to the
/// subcommand, not to the binary, and `list` takes no config at all — it reads no
/// registry, so it needs none.
fn run(dir: &Path, args: &[&str]) -> Output {
    let config = dir.join("dependable.toml");
    let mut all: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    if args[0] != "list" {
        all.push("--config".to_string());
        all.push(config.to_string_lossy().into_owned());
    }
    if args[0] == "check" {
        all.push("--no-vuln".to_string());
        all.push("--no-cache".to_string());
    }
    Command::new(env!("CARGO_BIN_EXE_dependable"))
        .current_dir(dir)
        .args(all)
        .output()
        .expect("run dependable")
}

fn check_json(dir: &Path, extra: &[&str]) -> Value {
    let mut args: Vec<&str> = vec!["check", ".", "--format", "json"];
    args.extend_from_slice(extra);
    let output = run(dir, &args);
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn status_of<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("no result {name}: {}", doc["results"]))
}

/// The dominant real-world POM: a `<parent>` supplies every version, so this file
/// states none.
const PARENT_ONLY: &str = "  <parent>\n    \
     <groupId>org.springframework.boot</groupId>\n    \
     <artifactId>spring-boot-starter-parent</artifactId>\n    \
     <version>3.2.5</version>\n  \
     </parent>\n  \
     <dependencies>\n    \
     <dependency>\n      \
     <groupId>org.springframework.boot</groupId>\n      \
     <artifactId>spring-boot-starter-web</artifactId>\n    \
     </dependency>\n    \
     <dependency>\n      \
     <groupId>org.springframework.boot</groupId>\n      \
     <artifactId>spring-boot-starter-test</artifactId>\n      \
     <scope>test</scope>\n    \
     </dependency>\n  \
     </dependencies>\n";

/// `check` must not call a dependency it merely failed to read a **local** one.
///
/// `local` is what this tool prints for a Cargo `path = "../x"` and a Maven
/// `<scope>system</scope>` jar, and it means one thing: there is no registry
/// behind this. Said of `spring-boot-starter-web` — which is on Maven Central —
/// it is a plain false statement, and `LOCAL` is the wrong token for a CI job to
/// read. It also contradicted `list`, which calls the same entry `(unresolved)`.
#[test]
fn a_version_supplied_by_a_parent_is_undetermined_and_never_called_local() {
    let dir = pom_dir("maven_parent_only", PARENT_ONLY);
    let doc = check_json(&dir, &[]);

    for artifact in ["spring-boot-starter-web", "spring-boot-starter-test"] {
        let name = format!("org.springframework.boot:{artifact}");
        let result = status_of(&doc, &name);
        assert_eq!(
            result["status"], "UNDETERMINED",
            "the artifact is on Maven Central; only its version went unread: {result}"
        );
        assert_ne!(result["status"], "LOCAL", "{result}");
    }
    assert_eq!(doc["summary"]["undetermined"], 2, "{}", doc["summary"]);
    assert_eq!(
        doc["summary"]["error"], 0,
        "nothing was asked, so nothing failed"
    );
}

/// The same fact in the table and in `--format text`, since those are what a
/// person and a shell pipeline actually read.
#[test]
fn the_table_and_the_text_format_both_say_undetermined() {
    let dir = pom_dir("maven_parent_only_surfaces", PARENT_ONLY);

    let table = run(&dir, &["check", "."]);
    let stdout = String::from_utf8_lossy(&table.stdout);
    assert!(
        stdout.contains("undetermined"),
        "the table calls it undetermined: {stdout}"
    );
    assert!(!stdout.contains("local"), "and never local: {stdout}");
    assert!(
        stdout.contains("2 undetermined"),
        "the totals count it apart from the deliberately skipped: {stdout}"
    );

    let text = run(&dir, &["check", ".", "--format", "text"]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert_eq!(
        stdout.matches("UNDETERMINED").count(),
        2,
        "one stable token per unread dependency: {stdout}"
    );
}

/// A CI job that reads nothing must not go green. `--fail-on any` asks whether
/// every dependency is checked and current; an unread version answers neither.
/// The two narrower gates keep meaning what they say.
#[test]
fn fail_on_any_does_not_pass_a_pom_whose_versions_were_never_read() {
    let dir = pom_dir("maven_parent_only_gate", PARENT_ONLY);
    for (gate, expected) in [("any", false), ("outdated", true), ("vulnerable", true)] {
        let output = run(&dir, &["check", ".", "--fail-on", gate]);
        assert_eq!(
            output.status.success(),
            expected,
            "--fail-on {gate}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// Nothing anywhere used to say that a POM's versions had not been read: stderr
/// was empty, and a reader looking at a table of dashes had to infer it.
#[test]
fn a_pom_whose_versions_were_not_read_says_so_on_stderr() {
    let dir = pom_dir("maven_parent_only_warning", PARENT_ONLY);
    let output = run(&dir, &["check", ".", "--format", "json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("2 dependencies"), "{stderr}");
    assert!(stderr.contains("<parent>"), "{stderr}");
    assert!(stderr.contains("<dependencyManagement>"), "{stderr}");
    assert!(
        stderr.contains("org.springframework.boot:spring-boot-starter-web"),
        "the warning names them, so the reader knows what to fix: {stderr}"
    );
}

/// The same-file `<dependencyManagement>` case, which needs no `<parent>` at all
/// and is just as common.
#[test]
fn a_version_supplied_by_the_files_own_dependency_management_is_undetermined() {
    let dir = pom_dir(
        "maven_managed_only",
        "  <dependencyManagement>\n    \
         <dependencies>\n      \
         <dependency>\n        \
         <groupId>com.google.guava</groupId>\n        \
         <artifactId>guava</artifactId>\n        \
         <version>32.1.3-jre</version>\n      \
         </dependency>\n    \
         </dependencies>\n  \
         </dependencyManagement>\n  \
         <dependencies>\n    \
         <dependency>\n      \
         <groupId>com.google.guava</groupId>\n      \
         <artifactId>guava</artifactId>\n    \
         </dependency>\n  \
         </dependencies>\n",
    );
    let doc = check_json(&dir, &[]);
    let guava = status_of(&doc, "com.google.guava:guava");
    assert_eq!(guava["status"], "UNDETERMINED", "{guava}");
}

/// A POM that says nothing about its versions is not the same as one whose
/// dependencies genuinely have no registry. A `<scope>system</scope>` jar is
/// still `LOCAL`, and must stay that way, or the new status means nothing.
#[test]
fn a_system_scoped_jar_is_still_local() {
    let dir = pom_dir(
        "maven_system_scope",
        "  <dependencies>\n    \
         <dependency>\n      \
         <groupId>org.example</groupId>\n      \
         <artifactId>vendored</artifactId>\n      \
         <version>1.0.0</version>\n      \
         <scope>system</scope>\n      \
         <systemPath>/opt/vendored.jar</systemPath>\n    \
         </dependency>\n  \
         </dependencies>\n",
    );
    let doc = check_json(&dir, &[]);
    let vendored = status_of(&doc, "org.example:vendored");
    assert_eq!(
        vendored["status"], "LOCAL",
        "there is no registry: {vendored}"
    );
    assert_eq!(doc["summary"]["undetermined"], 0, "{}", doc["summary"]);

    // And `--fail-on any` stays green over it: it was skipped on purpose.
    let output = run(&dir, &["check", ".", "--fail-on", "any"]);
    assert!(output.status.success());
}

/// A POM whose dependencies all live in `<profiles>` used to list as
/// `(0 dependencies)` — a list that reads as complete and is not. Excluding
/// conditional dependencies stays the decision; being silent about it does not.
#[test]
fn a_pom_whose_dependencies_are_all_in_profiles_says_so() {
    let dir = pom_dir(
        "maven_profiles_only",
        "  <profiles>\n    \
         <profile>\n      \
         <id>native</id>\n      \
         <dependencies>\n        \
         <dependency>\n          \
         <groupId>com.google.guava</groupId>\n          \
         <artifactId>guava</artifactId>\n          \
         <version>32.1.3-jre</version>\n        \
         </dependency>\n      \
         </dependencies>\n    \
         </profile>\n  \
         </profiles>\n",
    );

    let listed = run(&dir, &["list", "."]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    let stderr = String::from_utf8_lossy(&listed.stderr);
    assert!(
        stdout.contains("(0 dependencies)"),
        "a profile dependency is still not listed: {stdout}"
    );
    assert!(
        stderr.contains("1 dependency declared inside <profiles>"),
        "but the reader is told why the list is empty: {stderr}"
    );

    let checked = run(&dir, &["check", "."]);
    assert!(
        String::from_utf8_lossy(&checked.stderr).contains("<profiles>"),
        "and `check` says it too: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
