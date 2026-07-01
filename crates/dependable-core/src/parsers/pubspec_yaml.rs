//! Parser for Dart / Flutter `pubspec.yaml`.
//!
//! A focused block-style scanner (no general YAML dependency, mirroring
//! [`super::pnpm_workspace`]): it reads the `dependencies` and `dev_dependencies`
//! maps, recording each version value's position for `--fix`. Only direct,
//! 2-space-indented entries with an inline version constraint are checked; nested
//! maps (`sdk:` / `path:` / `git:` / `hosted:`) introduce a package header with no
//! inline value and are skipped, as is the `environment` block.

use super::Parser;
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `pubspec.yaml`.
pub struct PubspecYamlParser;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Dependencies,
}

impl Parser for PubspecYamlParser {
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
                    "dependencies" | "dev_dependencies" => Section::Dependencies,
                    _ => Section::None,
                };
                continue;
            }
            if section == Section::None {
                continue;
            }
            // Only direct children (2-space indent) are dependency entries. Deeper
            // lines belong to a nested map (`sdk:`/`path:`/`git:`) — skip them.
            if indent != 2 {
                continue;
            }
            // A `pkg:` header with no inline value introduces a nested map (SDK /
            // path / git / hosted) — `parse_entry` returns `None`, so it is skipped.
            if let Some((name, value_col, version)) = parse_entry(line)
                && is_version_value(version)
            {
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
            kind: ManifestKind::PubspecYaml,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// The top-level key of an indent-0 line (`dependencies:` → `dependencies`).
fn top_level_key(line: &str) -> &str {
    line.split(':').next().unwrap_or("").trim()
}

/// Parse a `key: value` entry, returning the key, the byte column where the
/// (unquoted) value starts within the line, and the value. Returns `None` for a
/// header line (`pkg:` with no inline value).
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

/// Whether a value looks like a single-clause version constraint, matching
/// `^[<>~=^]?=?\s*\d+(\.\d+)*([-+]?\w+)*$` (or the literal `any`). This filters out
/// non-version values such as `sdk: flutter` while keeping `^1.2.0`, `>=1.0.0`,
/// `1.8.3`, and pre-release/build suffixes.
fn is_version_value(v: &str) -> bool {
    if v == "any" {
        return true;
    }
    let bytes = v.as_bytes();
    let mut i = 0;
    if i < bytes.len() && matches!(bytes[i], b'<' | b'>' | b'~' | b'=' | b'^') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'=' {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    // Require at least one leading digit for the version core.
    if i >= bytes.len() || !bytes[i].is_ascii_digit() {
        return false;
    }
    bytes[i..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
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
        PubspecYamlParser.parse(content).unwrap()
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_dependencies_and_dev_dependencies() {
        let content = "name: my_app\nversion: 1.0.0\n\nenvironment:\n  sdk: \">=2.12.0 <3.0.0\"\n\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.1.0\n  provider: \"6.0.5\"\n\ndev_dependencies:\n  flutter_test:\n    sdk: flutter\n  test: ^1.24.0\n";
        let m = parse(content);

        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["http", "provider", "test"]); // sdk/env entries skipped

        let http = m.items.iter().find(|i| i.name == "http").unwrap();
        assert_eq!(http.version_constraint, "^1.1.0");
        assert_eq!(sliced(content, http), "^1.1.0");
        assert_eq!(http.source, PackageSource::Registry);

        let provider = m.items.iter().find(|i| i.name == "provider").unwrap();
        assert_eq!(provider.version_constraint, "6.0.5");
        assert_eq!(sliced(content, provider), "6.0.5"); // quotes excluded
    }

    #[test]
    fn skips_path_and_git_dependencies() {
        let content = "dependencies:\n  http: ^1.1.0\n  local_pkg:\n    path: ../local_pkg\n  git_pkg:\n    git:\n      url: https://example.com/pkg.git\n";
        let m = parse(content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["http"]);
    }

    #[test]
    fn accepts_any_and_ignores_comments() {
        let content = "dependencies:\n  meta: any  # provided transitively\n  http: ^1.1.0\n";
        let m = parse(content);
        let meta = m.items.iter().find(|i| i.name == "meta").unwrap();
        assert_eq!(meta.version_constraint, "any");
        assert_eq!(sliced(content, meta), "any");
    }

    #[test]
    fn ignores_non_dependency_sections() {
        let content = "name: my_app\ndescription: demo\nflutter:\n  uses-material-design: true\n";
        let m = parse(content);
        assert!(m.items.is_empty());
    }
}
