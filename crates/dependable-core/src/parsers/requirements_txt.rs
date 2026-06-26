//! Parser for Python `requirements.txt` (and `*.in`).
//!
//! A line parser: one requirement per line. Comment lines, option lines (`-r`,
//! `-e`, `--hash`), local paths (`./…`), and VCS/URL requirements are skipped, as
//! is any line whose comment contains `dependable: disable-check`. The shared
//! [`parse_pep508_spec`] (also used by `pyproject.toml`) extracts the name and the
//! version constraint's byte span.

use super::Parser;
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `requirements.txt`.
pub struct RequirementsTxtParser;

impl Parser for RequirementsTxtParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let mut items = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            if let Some(item) = parse_line(line, line_idx) {
                items.push(item);
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::RequirementsTxt,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

fn parse_line(line: &str, line_idx: usize) -> Option<Item> {
    // Split off a trailing comment; honor the disable-check directive.
    let hash = find_comment(line);
    let (code, comment) = match hash {
        Some(i) => (&line[..i], &line[i..]),
        None => (line, ""),
    };
    if comment.contains("dependable: disable-check") {
        return None;
    }
    let trimmed_start = code.len() - code.trim_start().len();
    let body = code[trimmed_start..].trim_end();
    if body.is_empty() {
        return None;
    }
    // Skip option lines (`-r`, `-e`, `--hash`) and local paths (`./`, `../`, `.`).
    let first = body.as_bytes()[0];
    if first == b'-' || first == b'.' {
        return None;
    }
    // Skip VCS/URL requirements.
    if body.starts_with("git+") || body.contains("://") {
        return None;
    }

    let (name, constraint, version_offset) = parse_pep508_spec(body)?;
    let abs_constraint_start = trimmed_start + version_offset;
    Some(Item {
        name,
        version_constraint: constraint.to_string(),
        source: PackageSource::Registry,
        version_line: line_idx,
        version_col_start: abs_constraint_start,
        version_col_end: abs_constraint_start + constraint.len(),
        registry: None,
        locked_version: None,
    })
}

/// Find the byte index of a line comment (`#` at start or after whitespace).
fn find_comment(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    bytes.iter().enumerate().find_map(|(i, &b)| {
        (b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace())).then_some(i)
    })
}

/// Parse a PEP 508 requirement spec (no comment, already trimmed of leading
/// whitespace): the distribution name, its version constraint, and the
/// constraint's byte offset within `spec`. Strips `[extras]` and `;` markers.
///
/// Shared with the `pyproject.toml` parser.
pub(crate) fn parse_pep508_spec(spec: &str) -> Option<(String, &str, usize)> {
    // Name: up to the first operator, `[`, `;`, `@`, or whitespace.
    let name_len = spec
        .find(|c: char| "<>=!~;[ \t@(".contains(c))
        .unwrap_or(spec.len());
    let name = &spec[..name_len];
    if name.is_empty() {
        return None;
    }

    let mut pos = name_len;
    let bytes = spec.as_bytes();
    // Skip whitespace and an optional `[extra1,extra2]`.
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if bytes.get(pos) == Some(&b'[') {
        if let Some(close) = spec[pos..].find(']') {
            pos += close + 1;
        }
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
    }
    // `name @ url` form is not a registry version.
    if bytes.get(pos) == Some(&b'@') {
        return None;
    }

    // Constraint runs to a `;` environment marker or the end.
    let rest = &spec[pos..];
    let region = rest.split(';').next().unwrap_or(rest);
    let constraint = region.trim_end();
    if constraint.is_empty() {
        // A bare requirement (`numpy`) — checkable, no recorded span for `--fix`.
        return Some((name.to_string(), "", spec.len()));
    }
    Some((name.to_string(), constraint, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        RequirementsTxtParser.parse(content).unwrap()
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
    fn parses_requirements_and_records_spans() {
        let content = "flask>=2.0\nrequests==2.28.1\ndjango>=3.2,<4.0\n";
        let m = parse(content);
        assert_eq!(find(&m, "flask").version_constraint, ">=2.0");
        assert_eq!(sliced(content, find(&m, "flask")), ">=2.0");
        assert_eq!(find(&m, "requests").version_constraint, "==2.28.1");
        assert_eq!(find(&m, "django").version_constraint, ">=3.2,<4.0");
        assert_eq!(sliced(content, find(&m, "django")), ">=3.2,<4.0");
    }

    #[test]
    fn strips_extras_and_markers() {
        let content = "celery[redis]>=5.0\nuvicorn==0.20 ; python_version >= \"3.8\"\n";
        let m = parse(content);
        assert_eq!(find(&m, "celery").version_constraint, ">=5.0");
        assert_eq!(sliced(content, find(&m, "celery")), ">=5.0");
        assert_eq!(find(&m, "uvicorn").version_constraint, "==0.20");
        assert_eq!(sliced(content, find(&m, "uvicorn")), "==0.20");
    }

    #[test]
    fn skips_comments_options_paths_and_directives() {
        let content = "# a comment\n-r other.txt\n-e .\n./local/pkg\ngit+https://example.com/x.git#egg=x\nflask>=2.0  # dependable: disable-check\nrequests==2.0\n";
        let m = parse(content);
        assert_eq!(m.items.len(), 1);
        assert_eq!(find(&m, "requests").version_constraint, "==2.0");
    }

    #[test]
    fn bare_requirement_has_empty_constraint() {
        let content = "numpy\n";
        let m = parse(content);
        assert_eq!(find(&m, "numpy").version_constraint, "");
        assert!(find(&m, "numpy").is_checkable());
    }
}
