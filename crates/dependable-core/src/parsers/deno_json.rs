//! Parser for Deno `deno.json` / `deno.jsonc`.
//!
//! Reads the `imports` and `scopes` maps via the JSON(C) scanner (which skips
//! comments), keeping only `jsr:` and `npm:` specifiers. URL/relative/`node:`/
//! `file:` imports are not registry dependencies and are dropped.

use super::Parser;
use super::json_scan::{JsonStringValue, scan_strings};
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `deno.json` and `deno.jsonc`.
pub struct DenoJsonParser;

impl Parser for DenoJsonParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let starts = line_starts(content);
        let mut items = Vec::new();
        for entry in scan_strings(content) {
            if is_import_entry(&entry.path) {
                if let Some(item) = build_item(&entry, &starts) {
                    items.push(item);
                }
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::DenoJson,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// Whether `path` points at an `imports.<key>` or `scopes.<scope>.<key>` entry.
fn is_import_entry(path: &[String]) -> bool {
    matches!(path, [s, _] if s == "imports")
        || matches!(path, [s, ..] if s == "scopes" && path.len() == 3)
}

/// Build an [`Item`] from an import spec, or `None` for non-registry specifiers
/// (URLs, relative paths, `node:`, `file:`, `data:`, …).
fn build_item(entry: &JsonStringValue, starts: &[usize]) -> Option<Item> {
    let value = &entry.value;
    let (name, constraint, source, version_offset) = if let Some(rest) = value.strip_prefix("jsr:")
    {
        let (n, c, off) = split_alias(rest, "jsr:".len());
        (n, c, PackageSource::Jsr, off)
    } else if let Some(rest) = value.strip_prefix("npm:") {
        let (n, c, off) = split_alias(rest, "npm:".len());
        (n, c, PackageSource::Registry, off)
    } else {
        return None;
    };

    let global_start = entry.content_start + version_offset;
    let (line, col_start) = offset_to_line_col(starts, global_start);
    Some(Item {
        name,
        version_constraint: constraint,
        source,
        version_line: line,
        version_col_start: col_start,
        version_col_end: col_start + entry.content_end.saturating_sub(global_start),
        registry: None,
        locked_version: None,
    })
}

/// Split an aliased spec `name@version` (after the `jsr:`/`npm:` prefix), where
/// `name` may be scoped. Returns the name, version, and the version's byte offset
/// within the full value.
fn split_alias(rest: &str, prefix_len: usize) -> (String, String, usize) {
    match rest.rfind('@') {
        Some(at) if at > 0 => (
            rest[..at].to_string(),
            rest[at + 1..].to_string(),
            prefix_len + at + 1,
        ),
        _ => (rest.to_string(), String::new(), prefix_len + rest.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        DenoJsonParser.parse(content).unwrap()
    }

    fn find<'a>(m: &'a ParsedManifest, name: &str) -> &'a Item {
        m.items
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_imports_keeping_only_jsr_and_npm() {
        let content = r#"{
  // import map
  "imports": {
    "@std/path": "jsr:@std/path@^1.0.0",
    "chalk": "npm:chalk@5.3.0",
    "local": "./local.ts",
    "remote": "https://deno.land/x/foo@1.0.0/mod.ts"
  }
}"#;
        let m = parse(content);
        assert_eq!(m.items.len(), 2);
        let path = find(&m, "@std/path");
        assert_eq!(path.source, PackageSource::Jsr);
        assert_eq!(path.version_constraint, "^1.0.0");
        assert_eq!(sliced(content, path), "^1.0.0");
        let chalk = find(&m, "chalk");
        assert_eq!(chalk.source, PackageSource::Registry);
        assert_eq!(sliced(content, chalk), "5.3.0");
    }

    #[test]
    fn parses_scopes() {
        let content = r#"{
  "scopes": {
    "https://example.com/": {
      "@std/assert": "jsr:@std/assert@^1.0.0"
    }
  }
}"#;
        let m = parse(content);
        assert_eq!(find(&m, "@std/assert").source, PackageSource::Jsr);
        assert_eq!(find(&m, "@std/assert").version_constraint, "^1.0.0");
    }
}
