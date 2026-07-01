//! Offline parse of the C# fixture: PackageReference parsing, MSBuild-property and
//! version-less skips, and version-offset round-tripping (`.csproj` has no lockfile).

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

#[test]
fn parses_csproj_package_references() {
    let manifest = std::fs::read_to_string(fixture("sample-csharp/App.csproj")).unwrap();
    let parsed = parse(ManifestKind::Csproj, &manifest).unwrap();

    // `FromProperty` ($(...)) and `Microsoft.Extensions.Hosting` (no Version) skipped.
    let names: Vec<&str> = parsed.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["Newtonsoft.Json", "Serilog"]);

    let json = parsed
        .items
        .iter()
        .find(|i| i.name == "Newtonsoft.Json")
        .unwrap();
    assert_eq!(json.version_constraint, "13.0.1");
    assert_eq!(slice(&manifest, json), "13.0.1"); // value range excludes quotes

    let serilog = parsed.items.iter().find(|i| i.name == "Serilog").unwrap();
    assert_eq!(serilog.version_constraint, "[2.10.0,3.0.0)");
    assert_eq!(slice(&manifest, serilog), "[2.10.0,3.0.0)");
}
