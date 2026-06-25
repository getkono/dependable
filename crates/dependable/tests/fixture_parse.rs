//! Offline integration test: the demo fixture parses and its lockfile applies as
//! expected (no network), exercising the parse → lockfile pipeline end to end.

use std::path::Path;

use dependable_core::{CargoTomlParser, PackageSource, Parser, apply_lockfile, parse_cargo_lock};

#[test]
fn fixture_parses_and_applies_lock() {
    let dir = Path::new("tests/fixtures/sample-rust");
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap();

    let mut parsed = CargoTomlParser.parse(&manifest).unwrap();
    apply_lockfile(&mut parsed.items, &parse_cargo_lock(&lock).unwrap());

    let find = |name: &str| parsed.items.iter().find(|i| i.name == name).unwrap();

    // Locked versions flow in from the fixture Cargo.lock.
    assert_eq!(find("serde").locked_version.as_deref(), Some("1.0.100"));
    assert_eq!(find("tokio").locked_version.as_deref(), Some("1.20.0"));
    // dev-dependencies are included.
    assert_eq!(find("anyhow").locked_version.as_deref(), Some("1.0.40"));
    // The path dependency is classified local and skipped.
    assert_eq!(find("local-thing").source, PackageSource::Local);
    // The exact pin is detected.
    assert!(find("time").is_pinned());
}
