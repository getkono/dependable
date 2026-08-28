//! Parser for Bun's text lockfile (`bun.lock`), collapsed to `name → versions`.
//!
//! `bun.lock` is JSONC, so it may carry comments and trailing commas; the shared
//! [`scan_strings`] scanner already tolerates both.
//!
//! Its `packages` map is nothing like npm's. Where `package-lock.json` gives
//! each entry an object with a `version` field, Bun gives an **array** whose
//! first element is a `name@version` descriptor:
//!
//! ```jsonc
//! "packages": {
//!   "react": ["react@19.0.0", "", { "dependencies": { … } }, "sha512-…"],
//!   "@acme/lib": ["@acme/lib@workspace:packages/lib"],
//! }
//! ```
//!
//! There is no `version` key to read and no `node_modules/` prefix to strip,
//! which is why the npm parser cannot be pointed at this file: it would find
//! nothing and report success, leaving every dependency unlocked with no
//! indication that a lockfile had been read at all.

use std::collections::HashMap;

use crate::error::ParseError;
use crate::lockfiles::cargo_lock::LockfileData;
use crate::parsers::json_scan::scan_strings;

/// Parse `bun.lock` into a `name → versions` map.
///
/// # Errors
/// Never fails: a lockfile that does not parse yields no versions, which callers
/// treat as "no locked versions" rather than an error that hides the project.
pub fn parse_bun_lock(content: &str) -> Result<LockfileData, ParseError> {
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();

    for entry in scan_strings(content) {
        // Only element 0 of each `packages` entry is the descriptor; the rest is
        // the registry, the dependency tables, and the integrity hash.
        let [section, _key, index] = entry.path.as_slice() else {
            continue;
        };
        if section != "packages" || index != "0" {
            continue;
        }
        let Some((name, version)) = split_descriptor(&entry.value) else {
            continue;
        };
        versions
            .entry(name.to_owned())
            .or_default()
            .push(version.to_owned());
    }

    Ok(LockfileData { versions })
}

/// Split a `name@version` descriptor, tolerating scoped names and aliases.
///
/// Returns `None` when the version is a location rather than a released version
/// — `workspace:packages/lib`, `file:../x`, `link:../x`, `github:owner/repo`.
/// Those packages are real, but they have no registry version to report, and
/// answering `workspace:packages/lib` to "what version is installed" would be
/// worse than answering nothing.
///
/// An alias (`a@npm:other@1.0.0`) does resolve to a version, and it is the
/// version installed *as* `a` — which is the name the manifest declares and the
/// name a locked version has to be recorded against.
pub(crate) fn split_descriptor(descriptor: &str) -> Option<(&str, &str)> {
    // A scoped name begins with `@`, so the separator is the last `@` rather
    // than the first: `@scope/name@1.0.0` splits after `name`.
    let at = descriptor.rfind('@').filter(|at| *at > 0)?;
    let (mut name, version) = (&descriptor[..at], &descriptor[at + 1..]);
    if version.is_empty() || version.contains(':') {
        return None;
    }
    // What remains of an alias is `a@npm:other`; the installed name is `a`.
    if name.contains(':') {
        let alias = name
            .char_indices()
            .find(|(i, c)| *c == '@' && *i > 0)
            .map(|(i, _)| i)?;
        name = &name[..alias];
    }
    if name.is_empty() {
        return None;
    }
    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{DependencyKind, Item, PackageSource};
    use crate::lockfiles::apply_lockfile;

    const LOCK: &str = r#"{
  // Bun writes JSONC, comments and all.
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "app", "dependencies": { "react": "^19.0.0" } },
  },
  "packages": {
    "react": ["react@19.0.0", "", { "dependencies": { "scheduler": "^0.25.0" } }, "sha512-aaa"],
    "scheduler": ["scheduler@0.25.0", "", {}, "sha512-bbb"],
    "@acme/ui": ["@acme/ui@2.1.0", "", {}, "sha512-ccc"],
    "@acme/lib": ["@acme/lib@workspace:packages/lib"],
  },
}"#;

    #[test]
    fn reads_versions_from_the_descriptor_array() {
        let data = parse_bun_lock(LOCK).unwrap();
        assert_eq!(data.versions["react"], ["19.0.0"]);
        assert_eq!(data.versions["scheduler"], ["0.25.0"]);
    }

    #[test]
    fn a_scoped_name_splits_at_its_last_at_sign() {
        let data = parse_bun_lock(LOCK).unwrap();
        assert_eq!(data.versions["@acme/ui"], ["2.1.0"]);
    }

    #[test]
    fn a_workspace_link_reports_no_version() {
        // `workspace:packages/lib` is a location, not a version, and reporting it
        // as one would be worse than reporting nothing.
        let data = parse_bun_lock(LOCK).unwrap();
        assert!(!data.versions.contains_key("@acme/lib"));
    }

    #[test]
    fn a_location_is_not_reported_as_a_version() {
        for descriptor in [
            "a@workspace:packages/a",
            "a@file:../a",
            "a@link:../a",
            "a@github:owner/repo",
        ] {
            assert_eq!(split_descriptor(descriptor), None, "{descriptor}");
        }
    }

    #[test]
    fn an_alias_is_recorded_against_the_name_it_is_installed_as() {
        // `"a": "npm:other@^1.0.0"` in the manifest declares `a`, so `a` is the
        // name a locked version has to be found under.
        assert_eq!(split_descriptor("a@npm:other@1.0.0"), Some(("a", "1.0.0")));
        assert_eq!(
            split_descriptor("@scope/a@npm:other@2.0.0"),
            Some(("@scope/a", "2.0.0"))
        );
    }

    #[test]
    fn a_descriptor_without_a_version_is_ignored() {
        assert_eq!(split_descriptor("react"), None);
        assert_eq!(split_descriptor("@scope/name"), None);
        assert_eq!(split_descriptor(""), None);
        assert_eq!(split_descriptor("@"), None);
    }

    #[test]
    fn applies_locked_versions_to_declared_items() {
        let mut items = vec![Item {
            name: "react".to_owned(),
            version_constraint: "^19.0.0".to_owned(),
            source: PackageSource::Registry,
            version_line: 1,
            version_col_start: 0,
            version_col_end: 0,
            registry: None,
            locked_version: None,
            kind: DependencyKind::Normal,
        }];
        let data = parse_bun_lock(LOCK).unwrap();
        apply_lockfile(&mut items, &data);
        assert_eq!(items[0].locked_version.as_deref(), Some("19.0.0"));
    }

    #[test]
    fn the_npm_shape_yields_nothing_rather_than_wrong_answers() {
        // A `package-lock.json` handed to this parser has no descriptor arrays,
        // so it reports no versions instead of inventing them.
        let npm = r#"{"packages":{"node_modules/react":{"version":"19.0.0"}}}"#;
        assert!(parse_bun_lock(npm).unwrap().versions.is_empty());
    }
}
