//! Offline parse of the Elixir fixture: registry deps from `mix.exs`, path/git
//! skip, `mix.lock` application, and version-offset round-tripping.

use std::path::{Path, PathBuf};

use dependable_fetch::ManifestKind;
use dependable_fetch::core::{Item, apply_lockfile, parse, parse_mix_lock};

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
fn parses_mix_exs_and_lockfile() {
    let manifest = std::fs::read_to_string(fixture("sample-elixir/mix.exs")).unwrap();
    let lock = std::fs::read_to_string(fixture("sample-elixir/mix.lock")).unwrap();
    let mut parsed = parse(ManifestKind::MixExs, &manifest).unwrap();
    apply_lockfile(&mut parsed.items, &parse_mix_lock(&lock).unwrap());

    // Registry deps only — `local_dep` (path) and `my_fork` (github) are skipped.
    let names: Vec<&str> = parsed.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["phoenix", "ecto_sql", "jason"]);

    let phoenix = parsed.items.iter().find(|i| i.name == "phoenix").unwrap();
    assert_eq!(phoenix.version_constraint, "~> 1.7.10");
    assert_eq!(slice(&manifest, phoenix), "~> 1.7.10"); // quotes excluded
    assert_eq!(phoenix.locked_version.as_deref(), Some("1.7.10"));

    let ecto_sql = parsed.items.iter().find(|i| i.name == "ecto_sql").unwrap();
    assert_eq!(ecto_sql.locked_version.as_deref(), Some("3.10.2"));

    let jason = parsed.items.iter().find(|i| i.name == "jason").unwrap();
    assert_eq!(jason.version_constraint, ">= 1.0.0");
    assert_eq!(jason.locked_version.as_deref(), Some("1.4.1"));
}
