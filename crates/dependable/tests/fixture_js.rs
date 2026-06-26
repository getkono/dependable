//! Offline parse of the JS-family fixtures: alias resolution, source
//! classification, lockfile application, and that recorded offsets slice back to
//! the version token.

use std::path::{Path, PathBuf};

use dependable_fetch::ManifestKind;
use dependable_fetch::core::{Item, PackageSource, apply_lockfile, parse, parse_package_lock};

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
fn parses_package_json_with_aliases_and_lockfile() {
    let manifest = std::fs::read_to_string(fixture("sample-npm/package.json")).unwrap();
    let lock = std::fs::read_to_string(fixture("sample-npm/package-lock.json")).unwrap();
    let mut parsed = parse(ManifestKind::PackageJson, &manifest).unwrap();
    apply_lockfile(&mut parsed.items, &parse_package_lock(&lock).unwrap());

    let react = parsed.items.iter().find(|i| i.name == "react").unwrap();
    assert_eq!(react.version_constraint, "^18.0.0");
    assert_eq!(slice(&manifest, react), "^18.0.0");
    assert_eq!(react.locked_version.as_deref(), Some("18.0.0"));

    // npm: alias resolves to the real name; only the version is recorded.
    let left_pad = parsed.items.iter().find(|i| i.name == "left-pad").unwrap();
    assert_eq!(left_pad.version_constraint, "1.3.0");
    assert_eq!(slice(&manifest, left_pad), "1.3.0");

    // file: spec is local, never checked.
    let local = parsed.items.iter().find(|i| i.name == "local-ui").unwrap();
    assert_eq!(local.source, PackageSource::Local);
}

#[test]
fn parses_deno_jsonc_imports() {
    let manifest = std::fs::read_to_string(fixture("sample-deno/deno.jsonc")).unwrap();
    let parsed = parse(ManifestKind::DenoJson, &manifest).unwrap();

    // Only jsr:/npm: specifiers survive; URLs and relative paths are dropped.
    assert_eq!(parsed.items.len(), 2);
    let path = parsed.items.iter().find(|i| i.name == "@std/path").unwrap();
    assert_eq!(path.source, PackageSource::Jsr);
    assert_eq!(slice(&manifest, path), "^1.0.0");
    let chalk = parsed.items.iter().find(|i| i.name == "chalk").unwrap();
    assert_eq!(chalk.source, PackageSource::Registry);
}

#[test]
fn parses_pnpm_catalogs() {
    let manifest = std::fs::read_to_string(fixture("sample-pnpm/pnpm-workspace.yaml")).unwrap();
    let parsed = parse(ManifestKind::PnpmWorkspaceYaml, &manifest).unwrap();

    let reacts: Vec<&str> = parsed
        .items
        .iter()
        .filter(|i| i.name == "react")
        .map(|i| i.version_constraint.as_str())
        .collect();
    assert!(reacts.contains(&"^18.2.0"));
    assert!(reacts.contains(&"^17.0.2"));

    let lodash = parsed.items.iter().find(|i| i.name == "lodash").unwrap();
    assert_eq!(slice(&manifest, lodash), "4.17.21"); // quotes excluded
}
