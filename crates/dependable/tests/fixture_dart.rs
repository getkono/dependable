//! Offline parse of the Dart fixture: dependencies/dev_dependencies, SDK/path
//! skip, lockfile application, and version-offset round-tripping.

use std::path::{Path, PathBuf};

use dependable_fetch::ManifestKind;
use dependable_fetch::core::{Item, apply_lockfile, parse, parse_dart_pubspec_lock};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn slice<'a>(content: &'a str, item: &Item) -> &'a str {
    let line = content.lines().nth(item.version_line).unwrap();
    &line[item.version_col_start..item.version_col_end]
}

#[test]
fn parses_pubspec_yaml_and_lockfile() {
    let manifest = std::fs::read_to_string(fixture("sample-dart/pubspec.yaml")).unwrap();
    let lock = std::fs::read_to_string(fixture("sample-dart/pubspec.lock")).unwrap();
    let mut parsed = parse(ManifestKind::PubspecYaml, &manifest).unwrap();
    apply_lockfile(&mut parsed.items, &parse_dart_pubspec_lock(&lock).unwrap());

    // Only registry deps — `flutter`/`flutter_test` (SDK) and `local_pkg` (path)
    // are skipped.
    let names: Vec<&str> = parsed.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["http", "provider", "test"]);

    let http = parsed.items.iter().find(|i| i.name == "http").unwrap();
    assert_eq!(http.version_constraint, "^1.1.0");
    assert_eq!(slice(&manifest, http), "^1.1.0");
    assert_eq!(http.locked_version.as_deref(), Some("1.1.0"));

    let provider = parsed.items.iter().find(|i| i.name == "provider").unwrap();
    assert_eq!(slice(&manifest, provider), "6.0.5"); // quotes excluded
    assert_eq!(provider.locked_version.as_deref(), Some("6.0.5"));

    let test = parsed.items.iter().find(|i| i.name == "test").unwrap();
    assert_eq!(test.locked_version.as_deref(), Some("1.24.9"));
}
