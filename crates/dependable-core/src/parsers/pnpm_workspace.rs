//! Parser for `pnpm-workspace.yaml` catalogs.
//!
//! A focused block-style scanner (no general YAML dependency): it reads the
//! default `catalog:` map and the named `catalogs:` maps, recording each version
//! value's position for `--fix`. Only block style is supported — the universal
//! format for pnpm catalogs. Catalog entries resolve from the npm registry, so
//! the items belong to the npm ecosystem.

use super::Parser;
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `pnpm-workspace.yaml`.
pub struct PnpmWorkspaceParser;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Catalog,
    Catalogs,
}

impl Parser for PnpmWorkspaceParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let mut items = Vec::new();
        let mut section = Section::None;
        for (line_idx, raw) in content.lines().enumerate() {
            let line = strip_comment(raw);
            if line.trim().is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent == 0 {
                section = match top_level_key(line) {
                    "catalog" => Section::Catalog,
                    "catalogs" => Section::Catalogs,
                    _ => Section::None,
                };
                continue;
            }
            if section == Section::None {
                continue;
            }
            // A `name:` header (empty value) under `catalogs:` introduces a named
            // catalog — skip it; a `dep: version` entry becomes an item.
            if let Some((name, value_col, version)) = parse_entry(line) {
                items.push(Item {
                    name,
                    version_constraint: version.to_string(),
                    source: PackageSource::Registry,
                    version_line: line_idx,
                    version_col_start: value_col,
                    version_col_end: value_col + version.len(),
                    registry: None,
                    locked_version: None,
                });
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::PnpmWorkspaceYaml,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// The top-level key of an indent-0 line (`catalog:` → `catalog`).
fn top_level_key(line: &str) -> &str {
    line.split(':').next().unwrap_or("").trim()
}

/// Parse a `key: value` entry, returning the key, the byte column where the
/// (unquoted) value starts within the line, and the value. Returns `None` for a
/// header line (`name:` with no value).
fn parse_entry(line: &str) -> Option<(String, usize, &str)> {
    let colon = line.find(':')?;
    let key = line[..colon].trim();
    if key.is_empty() {
        return None;
    }
    let after = &line[colon + 1..];
    let lead_ws = after.len() - after.trim_start().len();
    let value = after.trim();
    if value.is_empty() {
        return None;
    }
    let mut value_col = colon + 1 + lead_ws;
    let mut value = value;
    // Strip matching surrounding quotes.
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value_col += 1;
        value = &value[1..value.len() - 1];
    }
    Some((key.to_string(), value_col, value))
}

/// Strip a YAML line comment (`#` preceded by whitespace or at line start, and
/// not inside quotes).
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double && (i == 0 || bytes[i - 1].is_ascii_whitespace()) => {
                return &line[..i];
            }
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        PnpmWorkspaceParser.parse(content).unwrap()
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_default_catalog_and_named_catalogs() {
        let content = "packages:\n  - 'pkgs/*'\n\ncatalog:\n  react: ^18.2.0\n  lodash: \"4.17.21\"  # pinned\n\ncatalogs:\n  legacy:\n    react: ^17.0.0\n";
        let m = parse(content);

        let react: Vec<&str> = m
            .items
            .iter()
            .filter(|i| i.name == "react")
            .map(|i| i.version_constraint.as_str())
            .collect();
        assert!(react.contains(&"^18.2.0"));
        assert!(react.contains(&"^17.0.0"));

        let lodash = m.items.iter().find(|i| i.name == "lodash").unwrap();
        assert_eq!(lodash.version_constraint, "4.17.21");
        assert_eq!(sliced(content, lodash), "4.17.21"); // quotes excluded
        assert_eq!(lodash.source, PackageSource::Registry);
    }

    #[test]
    fn records_unquoted_value_position() {
        let content = "catalog:\n  react: ^18.2.0\n";
        let m = parse(content);
        let react = m.items.iter().find(|i| i.name == "react").unwrap();
        assert_eq!(sliced(content, react), "^18.2.0");
    }

    #[test]
    fn ignores_non_catalog_sections() {
        let content = "packages:\n  - 'pkgs/*'\nonlyBuiltDependencies:\n  - esbuild\n";
        let m = parse(content);
        assert!(m.items.is_empty());
    }
}
