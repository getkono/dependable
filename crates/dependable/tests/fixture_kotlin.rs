//! Offline parse of the Kotlin fixture: a Gradle version catalog's coordinates,
//! `version.ref` resolution, version-span round-tripping, and the notice a build
//! script gets when no catalog stands beside it.

use std::path::{Path, PathBuf};

use dependable_fetch::core::{Item, PackageSource, parse};
use dependable_fetch::{Ecosystem, ManifestKind, manifest_notices};

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
fn parses_a_gradle_version_catalog() {
    let path = fixture("sample-kotlin/gradle/libs.versions.toml");
    let kind = ManifestKind::detect(&path).expect("recognised by name");
    assert_eq!(kind, ManifestKind::GradleVersionCatalog);
    assert_eq!(kind.ecosystem(), Ecosystem::Jvm);
    assert_eq!(kind.ecosystem().osv_name(), "Maven");

    let manifest = std::fs::read_to_string(&path).unwrap();
    let parsed = parse(kind, &manifest).unwrap();

    // Every declaration form yields one `groupId:artifactId`; `[plugins]`,
    // `[bundles]`, and the platform-managed entry yield none.
    let names: Vec<&str> = parsed.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "org.jetbrains.kotlin:kotlin-stdlib",
            "org.jetbrains.kotlin:kotlin-reflect",
            "com.squareup.okhttp3:okhttp",
            "org.junit.jupiter:junit-jupiter",
            "com.google.guava:guava",
            "org.apache.commons:commons-lang3",
        ]
    );

    // A version stated on the library itself is rewritable where it is written.
    let guava = find(&parsed.items, "com.google.guava:guava");
    assert_eq!(guava.version_constraint, "32.1.3-jre");
    assert_eq!(slice(&manifest, guava), "32.1.3-jre");

    let commons = find(&parsed.items, "org.apache.commons:commons-lang3");
    assert_eq!(commons.version_constraint, "3.14.0");
    assert_eq!(slice(&manifest, commons), "3.14.0");

    // A `version.ref` used once points at the `[versions]` line that governs it.
    for (name, version) in [
        ("com.squareup.okhttp3:okhttp", "4.12.0"),
        ("org.junit.jupiter:junit-jupiter", "5.10.2"),
    ] {
        let item = find(&parsed.items, name);
        assert_eq!(item.version_constraint, version, "{name}");
        assert_eq!(slice(&manifest, item), version, "{name}");
        assert!(item.is_rewritable(), "{name}");
    }

    // A `version.ref` two libraries share is resolved but never rewritten.
    for name in [
        "org.jetbrains.kotlin:kotlin-stdlib",
        "org.jetbrains.kotlin:kotlin-reflect",
    ] {
        let item = find(&parsed.items, name);
        assert_eq!(item.version_constraint, "1.9.24", "{name}");
        assert_eq!(item.source, PackageSource::Inherited, "{name}");
        assert!(item.is_checkable(), "{name}");
        assert!(!item.is_rewritable(), "{name}");
    }
}

/// Every half of the required behaviour, from one scan of a multi-module build.
///
/// The root script and **both subprojects** are silent: a Gradle catalog is
/// build-root scoped, so `<root>/gradle/libs.versions.toml` is what `app/` and
/// `core/` read, and neither has a `gradle/` directory of its own. Resolving
/// supersession in the containing directory reported all three unread and advised
/// the user to declare their dependencies in a catalog that already held them.
///
/// `legacy/` is its own build root with no catalog, so it stays visibly unread —
/// the way `bun.lockb` is. Reporting a short dependency list would be worse than
/// reporting none, because only one of the two looks wrong.
#[test]
fn only_a_build_without_a_catalog_is_reported_unread() {
    let notices = manifest_notices(&fixture("sample-kotlin"), 3, |_| true);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(
        notices[0].path,
        fixture("sample-kotlin/legacy/build.gradle")
    );

    let rendered = notices[0].to_string();
    assert!(
        rendered.contains("cannot be read without executing it"),
        "{rendered}"
    );
    assert!(rendered.contains("gradle/libs.versions.toml"), "{rendered}");
}

/// A notice is advice to enable something. `[jvm] enabled = false` has already
/// answered it, and the scan used to run regardless.
#[test]
fn a_disabled_jvm_ecosystem_gets_no_gradle_notices() {
    let notices = manifest_notices(&fixture("sample-kotlin"), 3, |eco| eco != Ecosystem::Jvm);
    assert!(notices.is_empty(), "{notices:?}");
}
