//! Offline parse of the Bun fixture, end to end through discovery.
//!
//! Bun's text lockfile sits beside an ordinary `package.json`, so the thing
//! worth proving is that the right parser is chosen from the file on disk
//! rather than from the manifest — the mistake that would silently report every
//! dependency as unlocked.

use std::path::{Path, PathBuf};

use dependable_fetch::core::{apply_lockfile, parse, parse_bun_lock};
use dependable_fetch::{LockfileKind, ManifestKind, build_project_graph, find_lockfile};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

#[test]
fn discovery_finds_bun_lock_beside_a_package_json() {
    let manifest = fixture("sample-bun/package.json");
    let (path, data) =
        find_lockfile(&manifest, ManifestKind::PackageJson).expect("bun.lock is discovered");

    assert_eq!(path, fixture("sample-bun/bun.lock"));
    assert_eq!(data.versions["react"], ["19.0.0"]);
    assert_eq!(
        data.versions["typescript"],
        ["5.4.5"],
        "the lockfile pins a patch the manifest's `^5.4.0` does not name"
    );
}

#[test]
fn bun_lock_is_recognised_as_its_own_format() {
    assert_eq!(
        LockfileKind::detect(&fixture("sample-bun/bun.lock")),
        Some(LockfileKind::BunLock)
    );
}

#[test]
fn locked_versions_reach_the_declared_dependencies() {
    let manifest = std::fs::read_to_string(fixture("sample-bun/package.json")).unwrap();
    let lock = std::fs::read_to_string(fixture("sample-bun/bun.lock")).unwrap();

    let mut parsed = parse(ManifestKind::PackageJson, &manifest).unwrap();
    apply_lockfile(&mut parsed.items, &parse_bun_lock(&lock).unwrap());

    let by = |name: &str| {
        parsed
            .items
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    assert_eq!(by("react").locked_version.as_deref(), Some("19.0.0"));
    assert_eq!(by("@acme/ui").locked_version.as_deref(), Some("2.1.0"));
    assert_eq!(by("typescript").locked_version.as_deref(), Some("5.4.5"));
}

#[test]
fn the_resolved_graph_is_transitive() {
    // `scheduler` is named by no manifest; it is reachable only through the
    // lockfile's edges, so finding it proves the graph is resolved rather than
    // a list of what was declared.
    let graph = build_project_graph(&fixture("sample-bun/package.json"), &Default::default())
        .expect("a graph is built");

    let names: Vec<&str> = graph
        .graph
        .nodes()
        .iter()
        .map(|n| n.name.as_str())
        .collect();
    assert!(names.contains(&"sample-bun"), "the root: {names:?}");
    assert!(names.contains(&"react"), "a direct dependency: {names:?}");
    assert!(
        names.contains(&"scheduler"),
        "a transitive dependency: {names:?}"
    );
}
