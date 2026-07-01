//! Parser for Elixir `mix.exs`.
//!
//! `mix.exs` is Elixir source, so a full parse is out of scope; instead a compiled
//! regex extracts the registry dependency tuples `{:name, "requirement"}` from the
//! `deps` list. A tuple whose second element is a keyword rather than a string
//! (`{:name, path: ...}` / `git:` / `github:` / `in_umbrella:`) has no version
//! string immediately after the comma and so is naturally skipped. The version
//! string's byte range (quotes excluded) is recorded for `--fix`.

use std::sync::OnceLock;

use regex::Regex;

use super::Parser;
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `mix.exs`.
pub struct MixExsParser;

/// Matches `{:dep, "requirement"` — capturing the atom name and the (unquoted)
/// version string. Keyword-form deps (`{:dep, git: ...}`) lack the quoted string
/// after the comma and don't match. The `regex` crate has no backreferences, so
/// only double-quoted requirements (the universal form for version reqs) match.
fn dep_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\{\s*:(\w+)\s*,\s*"([^"]+)""#).expect("valid dep regex"))
}

impl Parser for MixExsParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let starts = line_starts(content);
        let mut items = Vec::new();
        for caps in dep_re().captures_iter(content) {
            let name = caps.get(1).expect("group 1").as_str().to_string();
            let version = caps.get(2).expect("group 2");
            let (version_line, version_col_start) = offset_to_line_col(&starts, version.start());
            let text = version.as_str();
            items.push(Item {
                name,
                version_constraint: text.to_string(),
                source: PackageSource::Registry,
                version_line,
                version_col_start,
                version_col_end: version_col_start + text.len(),
                registry: None,
                locked_version: None,
            });
        }
        Ok(ParsedManifest {
            kind: ManifestKind::MixExs,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        MixExsParser.parse(content).unwrap()
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_registry_deps_and_positions() {
        let content = "  defp deps do\n    [\n      {:phoenix, \"~> 1.7.10\"},\n      {:ecto_sql, \"~> 3.10\", only: :test},\n      {:jason, \">= 1.0.0\"}\n    ]\n  end\n";
        let m = parse(content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["phoenix", "ecto_sql", "jason"]);

        let phoenix = m.items.iter().find(|i| i.name == "phoenix").unwrap();
        assert_eq!(phoenix.version_constraint, "~> 1.7.10");
        assert_eq!(sliced(content, phoenix), "~> 1.7.10"); // quotes excluded
        assert_eq!(phoenix.source, PackageSource::Registry);
    }

    #[test]
    fn skips_path_git_and_umbrella_deps() {
        let content = "[\n  {:phoenix, \"~> 1.7\"},\n  {:local, path: \"../local\"},\n  {:remote, git: \"https://example.com/r.git\"},\n  {:forked, github: \"org/repo\"},\n  {:sibling, in_umbrella: true}\n]\n";
        let m = parse(content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["phoenix"]);
    }
}
