//! Offline parse of the PHP fixture: require/require-dev, platform-package skip,
//! lockfile application, and version-offset round-tripping.

use std::path::{Path, PathBuf};

use dependable_fetch::ManifestKind;
use dependable_fetch::core::{Item, apply_lockfile, parse, parse_composer_lock};

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
fn parses_composer_json_and_lockfile() {
    let manifest = std::fs::read_to_string(fixture("sample-php/composer.json")).unwrap();
    let lock = std::fs::read_to_string(fixture("sample-php/composer.lock")).unwrap();
    let mut parsed = parse(ManifestKind::ComposerJson, &manifest).unwrap();
    apply_lockfile(&mut parsed.items, &parse_composer_lock(&lock).unwrap());

    // Only vendor/name packages — `php` and `ext-*` are skipped.
    assert_eq!(parsed.items.len(), 2);

    let monolog = parsed
        .items
        .iter()
        .find(|i| i.name == "monolog/monolog")
        .unwrap();
    assert_eq!(monolog.version_constraint, "^2.0");
    assert_eq!(slice(&manifest, monolog), "^2.0");
    assert_eq!(monolog.locked_version.as_deref(), Some("2.1.0"));

    let phpunit = parsed
        .items
        .iter()
        .find(|i| i.name == "phpunit/phpunit")
        .unwrap();
    assert_eq!(phpunit.locked_version.as_deref(), Some("9.5.0"));
}
