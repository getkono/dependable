//! Parser for Go `go.mod` files.
//!
//! A small hand-rolled line parser (no Go-specific crate). It reads the
//! `require (...)` block and single-line `require` directives, recording the byte
//! span of each version token for in-place `--fix`. `module`, `go`, `replace`,
//! `exclude`, and line comments are ignored.

use super::Parser;
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};
use crate::semver::normalize_version;

/// Parses `go.mod`.
pub struct GoModParser;

impl Parser for GoModParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let mut items = Vec::new();
        let mut in_block = false;
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if in_block {
                if trimmed.starts_with(')') {
                    in_block = false;
                } else if let Some(item) = parse_entry(line, 0, line_idx) {
                    items.push(item);
                }
                continue;
            }
            let Some(after) = trimmed.strip_prefix("require") else {
                continue;
            };
            // Confirm `require` is the directive keyword (not a longer token).
            if !(after.is_empty()
                || after.starts_with(char::is_whitespace)
                || after.starts_with('('))
            {
                continue;
            }
            if after.trim_start().starts_with('(') {
                in_block = true;
            } else {
                // Single-line `require <module> <version>`; skip the keyword.
                let kw_end = line.len() - trimmed.len() + "require".len();
                if let Some(item) = parse_entry(line, kw_end, line_idx) {
                    items.push(item);
                }
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::GoMod,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// A whitespace-delimited token and its byte span within the line.
struct Token<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

/// Parse a `<module> <version>` pair from `line` starting at byte offset `from`,
/// ignoring any trailing `// comment`.
///
/// A `go.mod` version is the *resolved* version (Go's minimum-version selection),
/// so it is recorded both as the constraint (for display/`--fix`, keeping the
/// `v` prefix) and as the locked version (for evaluation, normalized to semver) —
/// otherwise treating it as a range would hide same-major updates.
fn parse_entry(line: &str, from: usize, line_idx: usize) -> Option<Item> {
    let code_end = line.find("//").unwrap_or(line.len());
    let code = &line[..code_end];
    let module = next_token(code, from)?;
    let version = next_token(code, module.end)?;
    Some(Item {
        name: module.text.to_string(),
        version_constraint: version.text.to_string(),
        source: PackageSource::Registry,
        version_line: line_idx,
        version_col_start: version.start,
        version_col_end: version.end,
        registry: None,
        locked_version: Some(normalize_version(version.text)),
    })
}

/// The next whitespace-delimited token in `s` at or after byte offset `from`.
fn next_token(s: &str, from: usize) -> Option<Token<'_>> {
    let bytes = s.as_bytes();
    let mut i = from.min(bytes.len());
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    Some(Token {
        text: &s[start..i],
        start,
        end: i,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        GoModParser.parse(content).unwrap()
    }

    fn find<'a>(m: &'a ParsedManifest, name: &str) -> &'a Item {
        m.items.iter().find(|i| i.name == name).unwrap()
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_block_and_single_require() {
        let content = "module example.com/m\n\ngo 1.21\n\nrequire github.com/foo/bar v1.2.3\n\nrequire (\n\tgithub.com/baz/qux v0.4.5\n\tgolang.org/x/sync v0.7.0 // indirect\n)\n";
        let m = parse(content);
        assert_eq!(m.items.len(), 3);
        assert_eq!(find(&m, "github.com/foo/bar").version_constraint, "v1.2.3");
        assert_eq!(find(&m, "github.com/baz/qux").version_constraint, "v0.4.5");
        assert_eq!(find(&m, "golang.org/x/sync").version_constraint, "v0.7.0");
        assert_eq!(
            find(&m, "github.com/foo/bar").source,
            PackageSource::Registry
        );
    }

    #[test]
    fn records_version_positions() {
        let content = "require (\n\tgithub.com/foo/bar/v2 v2.3.4\n)\n";
        let m = parse(content);
        let it = find(&m, "github.com/foo/bar/v2");
        assert_eq!(it.version_constraint, "v2.3.4");
        assert_eq!(sliced(content, it), "v2.3.4");
    }

    #[test]
    fn records_resolved_version_as_locked() {
        let content = "require github.com/foo/bar v1.2.3\n";
        let m = parse(content);
        // Keeps the `v` for display/fix, but records normalized semver as locked.
        assert_eq!(find(&m, "github.com/foo/bar").version_constraint, "v1.2.3");
        assert_eq!(
            find(&m, "github.com/foo/bar").locked_version.as_deref(),
            Some("1.2.3")
        );
    }

    #[test]
    fn ignores_replace_exclude_and_comments() {
        let content = "require github.com/foo/bar v1.0.0\nreplace github.com/foo/bar => ../local\nexclude github.com/bad/pkg v1.0.0\n// a comment\n";
        let m = parse(content);
        assert_eq!(m.items.len(), 1);
        assert_eq!(find(&m, "github.com/foo/bar").version_constraint, "v1.0.0");
    }

    #[test]
    fn ignores_replace_block() {
        let content = "require (\n\tgithub.com/foo/bar v1.0.0\n)\n\nreplace (\n\tgithub.com/foo/bar => ../local\n)\n";
        let m = parse(content);
        assert_eq!(m.items.len(), 1);
        assert_eq!(find(&m, "github.com/foo/bar").version_constraint, "v1.0.0");
    }
}
