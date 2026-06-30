//! Offline parse of the Python fixtures: requirements.txt line parsing and
//! pyproject PEP 621 arrays, with version-offset round-tripping.

use std::path::{Path, PathBuf};

use dependable_fetch::ManifestKind;
use dependable_fetch::core::{Item, parse};

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
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

#[test]
fn parses_requirements_fixture() {
    let content = std::fs::read_to_string(fixture("sample-python/requirements.txt")).unwrap();
    let parsed = parse(ManifestKind::RequirementsTxt, &content).unwrap();

    assert_eq!(find(&parsed.items, "flask").version_constraint, ">=2.0");
    assert_eq!(slice(&content, find(&parsed.items, "flask")), ">=2.0");
    assert_eq!(
        find(&parsed.items, "django").version_constraint,
        ">=3.2,<4.0"
    );
    assert_eq!(slice(&content, find(&parsed.items, "celery")), ">=5.0");
    assert_eq!(slice(&content, find(&parsed.items, "uvicorn")), "==0.20");
    // The `-r` include line is skipped.
    assert!(
        parsed
            .items
            .iter()
            .all(|i| !i.name.contains("dev-requirements"))
    );
}

#[test]
fn parses_pyproject_fixture() {
    let content = std::fs::read_to_string(fixture("sample-python/pyproject.toml")).unwrap();
    let parsed = parse(ManifestKind::PyprojectToml, &content).unwrap();

    assert_eq!(find(&parsed.items, "flask").version_constraint, ">=2.0");
    assert_eq!(slice(&content, find(&parsed.items, "flask")), ">=2.0");
    assert_eq!(
        find(&parsed.items, "requests").version_constraint,
        "==2.28.1"
    );
    assert_eq!(slice(&content, find(&parsed.items, "pytest")), ">=7.0");
    assert_eq!(slice(&content, find(&parsed.items, "ruff")), ">=0.1");
}
