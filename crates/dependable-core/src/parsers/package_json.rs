//! Parser for npm `package.json`.
//!
//! Uses the JSON scanner ([`super::json_scan`]) for structure *and* exact value
//! positions, then resolves npm version aliases. Only the version portion of an
//! alias is recorded for `--fix` (so `npm:left-pad@1.3.0` rewrites just `1.3.0`).

use super::Parser;
use super::json_scan::{JsonStringValue, scan_strings};
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Object keys whose entries are `name → version-spec` dependency maps.
const DEP_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

/// Parses `package.json`.
pub struct PackageJsonParser;

impl Parser for PackageJsonParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let starts = line_starts(content);
        let mut items = Vec::new();
        for entry in scan_strings(content) {
            if let Some(key) = dependency_key(&entry.path) {
                items.push(build_item(key, &entry, &starts));
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::PackageJson,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// Return the dependency name if `path` points at a dependency entry: a member of
/// a `*dependencies`/`catalog` map, or a `catalogs.<name>.<dep>` entry.
fn dependency_key(path: &[String]) -> Option<&str> {
    match path {
        [section, dep] if DEP_SECTIONS.contains(&section.as_str()) || section == "catalog" => {
            Some(dep)
        }
        [section, _catalog, dep] if section == "catalogs" => Some(dep),
        _ => None,
    }
}

/// Build an [`Item`] for one dependency entry, resolving aliases and recording the
/// version sub-span for `--fix`.
fn build_item(key: &str, entry: &JsonStringValue, starts: &[usize]) -> Item {
    let value = &entry.value;
    match resolve(key, value) {
        Resolved::Skip(source) => skip_item(key, source),
        Resolved::Dep {
            name,
            constraint,
            source,
            version_offset,
        } => {
            let global_start = entry.content_start + version_offset;
            let global_end = entry.content_end;
            let (line, col_start) = offset_to_line_col(starts, global_start);
            Item {
                name,
                version_constraint: constraint,
                source,
                version_line: line,
                version_col_start: col_start,
                version_col_end: col_start + global_end.saturating_sub(global_start),
                registry: None,
                locked_version: None,
            }
        }
    }
}

/// The outcome of resolving a `package.json` version spec.
enum Resolved {
    /// A checkable dependency. `version_offset` is the byte offset of the version
    /// within the *value* (non-zero for `npm:`/`jsr:` aliases).
    Dep {
        name: String,
        constraint: String,
        source: PackageSource,
        version_offset: usize,
    },
    /// A non-registry spec (path/link/workspace/catalog/git/url): skipped.
    Skip(PackageSource),
}

/// Local/workspace spec prefixes that are not version-checked.
const LOCAL_PREFIXES: &[&str] = &["file:", "link:", "workspace:", "catalog:", "portal:"];
/// Git/URL spec prefixes that are not version-checked.
const GIT_PREFIXES: &[&str] = &["git+", "git:", "github:", "http://", "https://"];

/// Resolve a `package.json` dependency `value` (`convertAliasToPackageName`).
fn resolve(key: &str, value: &str) -> Resolved {
    if let Some(rest) = value.strip_prefix("npm:") {
        let (name, constraint, offset) = split_alias(rest, "npm:".len());
        return Resolved::Dep {
            name,
            constraint,
            source: PackageSource::Registry,
            version_offset: offset,
        };
    }
    if let Some(rest) = value.strip_prefix("jsr:") {
        let (name, constraint, offset) = split_alias(rest, "jsr:".len());
        return Resolved::Dep {
            name,
            constraint,
            source: PackageSource::Jsr,
            version_offset: offset,
        };
    }
    if LOCAL_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Resolved::Skip(PackageSource::Local);
    }
    if GIT_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Resolved::Skip(PackageSource::Git);
    }
    Resolved::Dep {
        name: key.to_string(),
        constraint: value.to_string(),
        source: PackageSource::Registry,
        version_offset: 0,
    }
}

/// Split an aliased spec `name@version` (after the `npm:`/`jsr:` prefix), where
/// `name` may be scoped (`@scope/name`). Returns the name, the version, and the
/// version's byte offset within the *full* value (`prefix_len` accounts for the
/// stripped `npm:`/`jsr:`).
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

fn skip_item(name: &str, source: PackageSource) -> Item {
    Item {
        name: name.to_owned(),
        version_constraint: String::new(),
        source,
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        PackageJsonParser.parse(content).unwrap()
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
    fn parses_sections_and_records_positions() {
        let content = r#"{
  "dependencies": {
    "react": "^18.2.0",
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "typescript": "~5.4.0"
  }
}"#;
        let m = parse(content);
        let react = find(&m, "react");
        assert_eq!(react.version_constraint, "^18.2.0");
        assert_eq!(sliced(content, react), "^18.2.0");
        assert_eq!(react.source, PackageSource::Registry);
        assert_eq!(sliced(content, find(&m, "typescript")), "~5.4.0");
    }

    #[test]
    fn resolves_npm_and_jsr_aliases_with_version_span() {
        let content = r#"{
  "dependencies": {
    "my-left-pad": "npm:left-pad@1.3.0",
    "path": "jsr:@std/path@^1.0.0"
  }
}"#;
        let m = parse(content);
        let lp = find(&m, "left-pad");
        assert_eq!(lp.version_constraint, "1.3.0");
        assert_eq!(lp.source, PackageSource::Registry);
        assert_eq!(sliced(content, lp), "1.3.0"); // only the version, not the alias

        let p = find(&m, "@std/path");
        assert_eq!(p.version_constraint, "^1.0.0");
        assert_eq!(p.source, PackageSource::Jsr);
        assert_eq!(sliced(content, p), "^1.0.0");
    }

    #[test]
    fn classifies_local_and_git_specs() {
        let content = r#"{
  "dependencies": {
    "linked": "link:../linked",
    "wsdep": "workspace:*",
    "fromgit": "git+https://example.com/x.git",
    "catdep": "catalog:"
  }
}"#;
        let m = parse(content);
        assert_eq!(find(&m, "linked").source, PackageSource::Local);
        assert_eq!(find(&m, "wsdep").source, PackageSource::Local);
        assert_eq!(find(&m, "fromgit").source, PackageSource::Git);
        assert_eq!(find(&m, "catdep").source, PackageSource::Local);
        assert!(!find(&m, "linked").is_checkable());
    }

    #[test]
    fn parses_pnpm_catalogs_in_package_json() {
        let content = r#"{
  "catalog": { "react": "^18.0.0" },
  "catalogs": { "legacy": { "react": "^17.0.0" } }
}"#;
        let m = parse(content);
        // Both catalog and catalogs.legacy define `react`.
        let reacts: Vec<&str> = m
            .items
            .iter()
            .filter(|i| i.name == "react")
            .map(|i| i.version_constraint.as_str())
            .collect();
        assert!(reacts.contains(&"^18.0.0"));
        assert!(reacts.contains(&"^17.0.0"));
    }
}
