//! Parser for C#/.NET project files (`*.csproj`, `Directory.Packages.props`).
//!
//! A read-only DOM walk (`roxmltree`) over every `<PackageReference>` and
//! `<PackageVersion>` element, taking the package name from `Include` (or
//! `Update`) and the constraint from the `Version` attribute. The exact byte range
//! of the version value is recorded (via `Attribute::range_value`) for `--fix`.
//! Entries without a `Version` attribute (central-package-managed references) and
//! MSBuild property values (`$(SomeVersion)`) are skipped.

use super::Parser;
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `*.csproj` / `Directory.Packages.props`.
pub struct CsprojParser;

impl Parser for CsprojParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let doc = roxmltree::Document::parse(content)
            .map_err(|e| ParseError::Structural(e.to_string()))?;
        let starts = line_starts(content);
        let mut items = Vec::new();

        for node in doc.descendants() {
            let tag = node.tag_name().name();
            if tag != "PackageReference" && tag != "PackageVersion" {
                continue;
            }
            let Some(name) = node
                .attribute("Include")
                .or_else(|| node.attribute("Update"))
            else {
                continue;
            };
            // The `Version` attribute carries both the value and its source range.
            let Some(attr) = node.attributes().find(|a| a.name() == "Version") else {
                continue;
            };
            let value = attr.value();
            // MSBuild property references (`$(FooVersion)`) are not versions.
            if value.contains('$') {
                continue;
            }

            let range = attr.range_value();
            let (version_line, version_col_start) = offset_to_line_col(&starts, range.start);
            items.push(Item {
                name: name.to_string(),
                version_constraint: value.to_string(),
                source: PackageSource::Registry,
                version_line,
                version_col_start,
                version_col_end: version_col_start + (range.end - range.start),
                registry: None,
                locked_version: None,
            });
        }

        Ok(ParsedManifest {
            kind: ManifestKind::Csproj,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        CsprojParser.parse(content).unwrap()
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_package_references_with_positions() {
        let content = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n    <PackageReference Include=\"Serilog\" Version=\"[2.10.0,3.0.0)\" />\n  </ItemGroup>\n</Project>\n";
        let m = parse(content);
        assert_eq!(m.items.len(), 2);

        let json = m
            .items
            .iter()
            .find(|i| i.name == "Newtonsoft.Json")
            .unwrap();
        assert_eq!(json.version_constraint, "13.0.1");
        assert_eq!(sliced(content, json), "13.0.1"); // quotes excluded
        assert_eq!(json.source, PackageSource::Registry);

        let serilog = m.items.iter().find(|i| i.name == "Serilog").unwrap();
        assert_eq!(serilog.version_constraint, "[2.10.0,3.0.0)");
        assert_eq!(sliced(content, serilog), "[2.10.0,3.0.0)");
    }

    #[test]
    fn skips_property_versions_and_missing_versions() {
        let content = "<Project>\n  <ItemGroup>\n    <PackageReference Include=\"Managed\" />\n    <PackageReference Include=\"FromProp\" Version=\"$(SerilogVersion)\" />\n    <PackageReference Include=\"Real\" Version=\"1.2.3\" />\n  </ItemGroup>\n</Project>\n";
        let m = parse(content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["Real"]);
    }

    #[test]
    fn parses_central_package_versions() {
        let content = "<Project>\n  <ItemGroup>\n    <PackageVersion Include=\"xunit\" Version=\"2.6.1\" />\n  </ItemGroup>\n</Project>\n";
        let m = parse(content);
        let xunit = m.items.iter().find(|i| i.name == "xunit").unwrap();
        assert_eq!(xunit.version_constraint, "2.6.1");
        assert_eq!(sliced(content, xunit), "2.6.1");
    }
}
