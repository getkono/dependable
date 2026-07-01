//! Parser for Elixir `mix.lock`.
//!
//! `mix.lock` is an Elixir map literal keyed by dependency name, each value a tuple
//! whose third element (the first quoted string after `{:hex, :name,`) is the
//! resolved version. A compiled regex extracts `"<name>": {:hex, :<atom>, "<version>"`;
//! non-Hex entries (`{:git, ...}`) have no resolved semver version and are skipped.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::error::ParseError;
use crate::lockfiles::LockfileData;

fn lock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""(\w+)":\s*\{:hex,\s*:\w+,\s*"([^"]+)""#).expect("valid mix.lock regex")
    })
}

/// Parse `mix.lock` into a name → resolved-version map.
pub fn parse_mix_lock(content: &str) -> Result<LockfileData, ParseError> {
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for caps in lock_re().captures_iter(content) {
        let name = caps.get(1).expect("group 1").as_str().to_string();
        let version = caps.get(2).expect("group 2").as_str().to_string();
        versions.entry(name).or_default().push(version);
    }
    Ok(LockfileData { versions })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Item, PackageSource};
    use crate::lockfiles::apply_lockfile;

    const LOCK: &str = "%{\n  \"phoenix\": {:hex, :phoenix, \"1.7.10\", \"abc\", [:mix], [{:telemetry, \"~> 1.0\", [hex: :telemetry]}], \"hexpm\", \"def\"},\n  \"telemetry\": {:hex, :telemetry, \"1.2.1\", \"aaa\", [:rebar3], [], \"hexpm\", \"bbb\"},\n  \"forked\": {:git, \"https://example.com/forked.git\", \"a1b2\", []},\n}\n";

    #[test]
    fn extracts_hex_versions_only() {
        let data = parse_mix_lock(LOCK).unwrap();
        assert_eq!(data.versions["phoenix"], vec!["1.7.10"]);
        assert_eq!(data.versions["telemetry"], vec!["1.2.1"]);
        // The git-sourced dep has no resolved semver version.
        assert!(!data.versions.contains_key("forked"));
    }

    #[test]
    fn applies_locked_version() {
        let data = parse_mix_lock(LOCK).unwrap();
        let mut items = vec![Item {
            name: "phoenix".into(),
            version_constraint: "~> 1.7".into(),
            source: PackageSource::Registry,
            version_line: 0,
            version_col_start: 0,
            version_col_end: 0,
            registry: None,
            locked_version: None,
        }];
        apply_lockfile(&mut items, &data);
        assert_eq!(items[0].locked_version.as_deref(), Some("1.7.10"));
    }
}
