//! Parser for Elixir `mix.lock` that preserves the resolved dependency graph.
//!
//! Unlike [`super::mix_lock`], which extracts only `name → version`, this parser
//! reads each entry's dependency list so the resolved transitive graph can be
//! reconstructed offline (see [`crate::graph`]).
//!
//! `mix.lock` is an Elixir map literal whose values are tuples:
//!
//! ```text
//! "phoenix": {:hex, :phoenix, "1.7.10", "sha", [:mix], [{:telemetry, "~> 1.0", […]}], "hexpm", "sha"},
//! ```
//!
//! Element 2 is the resolved version and element 5 is the dependency list. Because
//! those elements nest braces and brackets, they are found by splitting the tuple at
//! its top level rather than by a regex over the whole entry.

use std::sync::OnceLock;

use regex::Regex;

use crate::error::ParseError;
use crate::lockfiles::cargo_lock_graph::{LockedPackage, ResolvedLockfile};

/// Index of the resolved version within a `:hex` tuple.
const VERSION_ELEMENT: usize = 2;
/// Index of the dependency list within a `:hex` tuple.
const DEPS_ELEMENT: usize = 5;

/// The registry source recorded for Hex packages.
const HEX_SOURCE: &str = "registry+https://hex.pm";

/// Matches `"name": {` — the start of one lockfile entry.
fn entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""([^"]+)":\s*\{"#).expect("valid mix.lock entry regex"))
}

/// Matches a dependency atom at the head of a `{:name, "req", […]}` tuple.
fn dep_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\s*:(\w+)\s*,").expect("valid mix.lock dep regex"))
}

/// Parse `mix.lock` into a [`ResolvedLockfile`], preserving edges.
///
/// Only `:hex` entries become nodes: a `{:git, …}` entry has no resolved semver
/// version, matching [`super::mix_lock`]. Mix resolves one version per package, so
/// a bare name is an unambiguous edge reference.
///
/// # Errors
/// Never fails: a lockfile that does not parse yields no packages, which callers
/// treat as "no resolved graph" rather than an error that hides the project.
pub fn parse_mix_lock_graph(content: &str) -> Result<ResolvedLockfile, ParseError> {
    let mut packages = Vec::new();

    for caps in entry_re().captures_iter(content) {
        let name = caps.get(1).expect("group 1").as_str().to_owned();
        let open = caps.get(0).expect("group 0").end();
        let Some(body) = balanced(content, open, b'{', b'}') else {
            continue;
        };
        let elements = split_top_level(body);
        // A non-Hex entry (`{:git, …}`) resolves to no published version.
        if elements.first().map(|e| e.trim()) != Some(":hex") {
            continue;
        }
        let Some(version) = elements.get(VERSION_ELEMENT).and_then(|e| unquote(e)) else {
            continue;
        };
        let dependencies = elements
            .get(DEPS_ELEMENT)
            .map(|list| {
                dep_re()
                    .captures_iter(list)
                    .map(|c| c.get(1).expect("group 1").as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();

        packages.push(LockedPackage::new(
            name,
            Some(version),
            Some(HEX_SOURCE.to_owned()),
            dependencies,
        ));
    }

    Ok(ResolvedLockfile::from_packages(packages))
}

/// The slice enclosed by a bracket pair, given the offset just past the opener.
///
/// Quoted strings are skipped so a brace inside a string never closes the group.
fn balanced(src: &str, start: usize, open: u8, close: u8) -> Option<&str> {
    let bytes = src.as_bytes();
    let mut depth = 1usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    // A backslash escapes the next byte, including a quote.
                    i += usize::from(bytes[i] == b'\\') + 1;
                }
            }
            b if b == open => depth += 1,
            b if b == close => {
                depth -= 1;
                if depth == 0 {
                    return src.get(start..i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split a tuple body on the commas that sit at its top level, ignoring commas
/// nested inside brackets, braces, or strings.
fn split_top_level(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += usize::from(bytes[i] == b'\\') + 1;
                }
            }
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&body[start..]);
    parts
}

/// The content of a quoted element, or `None` when it is not a string.
fn unquote(element: &str) -> Option<String> {
    let trimmed = element.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = concat!(
        "%{\n",
        r#"  "ecto": {:hex, :ecto, "3.10.3", "aaa", [:mix], [{:telemetry, "~> 0.4 or ~> 1.0", [hex: :telemetry, repo: "hexpm", optional: false]}, {:decimal, "~> 2.0", [hex: :decimal, repo: "hexpm", optional: false]}], "hexpm", "bbb"},"#,
        "\n",
        r#"  "decimal": {:hex, :decimal, "2.1.1", "ccc", [:mix], [], "hexpm", "ddd"},"#,
        "\n",
        r#"  "telemetry": {:hex, :telemetry, "1.2.1", "iii", [:rebar3], [], "hexpm", "jjj"},"#,
        "\n",
        r#"  "forked": {:git, "https://example.com/forked.git", "a1b2", []},"#,
        "\n}\n",
    );

    fn deps_of<'a>(lock: &'a ResolvedLockfile, name: &str) -> Vec<&'a str> {
        let pkg = lock
            .packages
            .iter()
            .find(|p| p.name == name)
            .expect("package present");
        let mut deps: Vec<&str> = pkg
            .dependencies
            .iter()
            .filter_map(|d| lock.resolve(d))
            .map(|i| lock.packages[i].name.as_str())
            .collect();
        deps.sort_unstable();
        deps
    }

    #[test]
    fn reads_hex_packages_and_their_versions() {
        let resolved = parse_mix_lock_graph(LOCK).unwrap();
        let mut found: Vec<(&str, &str)> = resolved
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_deref().unwrap_or_default()))
            .collect();
        found.sort_unstable();
        assert_eq!(
            found,
            vec![
                ("decimal", "2.1.1"),
                ("ecto", "3.10.3"),
                ("telemetry", "1.2.1"),
            ],
            "the git-sourced entry has no resolved version"
        );
    }

    #[test]
    fn reads_edges_from_the_dependency_element() {
        let resolved = parse_mix_lock_graph(LOCK).unwrap();
        assert_eq!(deps_of(&resolved, "ecto"), vec!["decimal", "telemetry"]);
        assert!(deps_of(&resolved, "telemetry").is_empty(), "empty dep list");
    }

    #[test]
    fn does_not_mistake_the_build_tools_element_for_dependencies() {
        // Element 4 is `[:mix]` / `[:rebar3]`; only element 5 holds dependencies.
        let resolved = parse_mix_lock_graph(LOCK).unwrap();
        for pkg in &resolved.packages {
            assert!(
                !pkg.dependencies.iter().any(|d| d == "mix" || d == "rebar3"),
                "{} picked up a build tool as a dependency: {:?}",
                pkg.name,
                pkg.dependencies
            );
        }
    }

    #[test]
    fn splits_only_at_the_top_level() {
        let parts = split_top_level(r#":hex, :a, "1.0", [{:b, "~> 1, 2"}], "x""#);
        assert_eq!(parts.len(), 5, "the nested comma must not split: {parts:?}");
        assert_eq!(parts[3].trim(), r#"[{:b, "~> 1, 2"}]"#);
    }

    #[test]
    fn a_brace_inside_a_string_does_not_close_the_entry() {
        let lock = r#"%{
  "weird": {:hex, :weird, "1.0.0", "a}b", [:mix], [{:dep, "~> 1.0", []}], "hexpm", "c"},
  "dep": {:hex, :dep, "2.0.0", "x", [:mix], [], "hexpm", "y"},
}
"#;
        let resolved = parse_mix_lock_graph(lock).unwrap();
        assert_eq!(resolved.packages.len(), 2);
        assert_eq!(deps_of(&resolved, "weird"), vec!["dep"]);
    }

    #[test]
    fn survives_an_empty_lockfile() {
        let resolved = parse_mix_lock_graph("%{}\n").unwrap();
        assert!(resolved.packages.is_empty());
    }
}
