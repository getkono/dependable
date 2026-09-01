//! Parser for npm `package.json`.
//!
//! Uses the JSON scanner ([`super::json_scan`]) for structure *and* exact value
//! positions, then resolves npm version aliases. Only the version portion of an
//! alias is recorded for `--fix` (so `npm:left-pad@1.3.0` rewrites just `1.3.0`).

use std::collections::HashMap;

use super::Parser;
use super::json_scan::{JsonStringValue, scan_strings};
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{DependencyKind, Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Object keys whose entries are `name → version-spec` dependency maps, paired with
/// the kind an entry under each one gets.
const DEP_SECTIONS: &[(&str, DependencyKind)] = &[
    ("dependencies", DependencyKind::Normal),
    ("devDependencies", DependencyKind::Dev),
    ("peerDependencies", DependencyKind::Peer),
    ("optionalDependencies", DependencyKind::Optional),
];

/// Parses `package.json`.
pub struct PackageJsonParser;

impl Parser for PackageJsonParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let starts = line_starts(content);
        let entries = scan_strings(content);
        let declared = direct_dependencies(&entries);
        let mut items = Vec::new();
        for entry in &entries {
            if let Some((key, kind)) = dependency_key(&entry.path) {
                items.push(build_item(key, kind, entry, &starts, &declared));
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::PackageJson,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// The constraint each `*dependencies` section declares, by package name.
///
/// The lookup table an npm `"$name"` override value is resolved against; a later
/// section wins, which is the order npm itself reads them in.
fn direct_dependencies(entries: &[JsonStringValue]) -> HashMap<&str, &str> {
    entries
        .iter()
        .filter_map(|entry| match entry.path.as_slice() {
            [section, dep] if DEP_SECTIONS.iter().any(|(name, _)| name == section) => {
                Some((dep.as_str(), entry.value.as_str()))
            }
            _ => None,
        })
        .collect()
}

/// Return the dependency name and its kind if `path` points at a dependency entry: a
/// member of a `*dependencies`/`catalog` map, or a `catalogs.<name>.<dep>` entry.
///
/// A catalog entry is a version declaration workspace packages opt into by name, so it
/// is [`DependencyKind::Workspace`] rather than a dependency of this manifest.
fn dependency_key(path: &[String]) -> Option<(&str, DependencyKind)> {
    match path {
        [section, dep] => DEP_SECTIONS
            .iter()
            .find(|(name, _)| name == section)
            .map(|(_, kind)| (dep.as_str(), *kind))
            .or_else(|| (section == "catalog").then_some((dep.as_str(), DependencyKind::Workspace)))
            .or_else(|| {
                is_override_section(section)
                    .then(|| override_name(dep))
                    .flatten()
                    .map(|name| (name, DependencyKind::Override))
            }),
        [section, _catalog, dep] if section == "catalogs" => {
            Some((dep.as_str(), DependencyKind::Workspace))
        }
        // `pnpm.overrides`, and npm's nested form where an override is scoped to the
        // parent that pulls the package in: `overrides.parent.child`.
        [outer, inner, dep] if outer == "pnpm" && inner == "overrides" => {
            override_name(dep).map(|name| (name, DependencyKind::Override))
        }
        [section, _parent, dep] if is_override_section(section) => {
            override_name(dep).map(|name| (name, DependencyKind::Override))
        }
        _ => None,
    }
}

/// Whether `section` is one of the maps that force a version onto the resolved tree.
fn is_override_section(section: &str) -> bool {
    matches!(section, "overrides" | "resolutions")
}

/// The package an override key names.
///
/// Yarn `resolutions` keys carry a path (`parent/child`, `**/lodash`) and npm's nested
/// form uses `"."` to mean "the parent entry itself", which names no new package.
///
/// pnpm scopes an override to the parent that pulls the package in by joining the two
/// with `>`: `"foo@2>bar"` forces a version onto **bar**, not onto `foo`. The overridden
/// package is therefore the *last* `>`-separated segment; reading the first named an
/// unrelated package, which `--fix` then rewrote the pin to that package's latest
/// version.
fn override_name(key: &str) -> Option<&str> {
    if key == "." {
        return None;
    }
    // The parent selectors in front of the last `>` scope the override; only the segment
    // after it names the package being overridden.
    let key = key.rsplit('>').next().unwrap_or(key).trim();
    // Segment first, then strip the version. Doing it the other way round cut `**/@scope/pkg`
    // at the scope's own `@`, because that `@` is not at the start of the *key*.
    //
    // The package is the last segment — or the last *two* when the one before it is a
    // scope, because `@scope/pkg` is one name that happens to contain a slash.
    let mut start = key.rfind('/').map_or(0, |slash| slash + 1);
    if start > 0 {
        let head = &key[..start - 1];
        if let Some(prev) = head.rfind('/') {
            if key[prev + 1..].starts_with('@') {
                start = prev + 1;
            }
        } else if head.starts_with('@') {
            start = 0;
        }
    }
    let name = &key[start..];
    // A trailing `@version` selects a range, not part of the name. A *leading* `@` is the
    // scope, so the offset has to be past the start.
    let name = match name.rfind('@') {
        Some(at) if at > 0 => &name[..at],
        _ => name,
    };
    (!name.is_empty() && name != "*" && name != "**").then_some(name)
}

/// An npm override value that references one of this manifest's own direct
/// dependencies rather than stating a range.
///
/// `{"dependencies": {"semver": "^7.5.0"}, "overrides": {"semver": "$semver"}}` is
/// npm's documented way to say "force the version I already depend on". It is not a
/// constraint, and handing it to the version checker produced
/// `unparseable constraint: unexpected character '$'` on a perfectly valid manifest —
/// the same shape `csproj.rs` already declines to read as a version in `$(MSBuildProp)`.
///
/// Returns the referenced package name.
fn override_reference(value: &str) -> Option<&str> {
    let name = value.strip_prefix('$')?;
    (!name.is_empty() && !name.contains(char::is_whitespace)).then_some(name)
}

/// Build an [`Item`] for one dependency entry, resolving aliases and recording the
/// version sub-span for `--fix`.
fn build_item(
    key: &str,
    kind: DependencyKind,
    entry: &JsonStringValue,
    starts: &[usize],
    declared: &HashMap<&str, &str>,
) -> Item {
    if kind == DependencyKind::Override
        && let Some(referenced) = override_reference(&entry.value)
    {
        // Resolved, the reference *is* the referenced dependency's constraint, so the
        // entry is checked against exactly the version the manifest forces. Unresolved,
        // the manifest names a dependency it does not declare: real package, unreadable
        // version, and nothing to ask a registry for.
        return match declared.get(referenced) {
            Some(constraint) => {
                let (line, col) = offset_to_line_col(starts, entry.content_start);
                Item {
                    name: key.to_owned(),
                    version_constraint: (*constraint).to_owned(),
                    source: PackageSource::Registry,
                    // The span holds `$semver`, not the constraint being checked, so it
                    // reports its position and declines its width — the same way an
                    // escaped value does — and no rewriter can splice a version over
                    // the reference.
                    version_line: line,
                    version_col_start: col,
                    version_col_end: col,
                    registry: None,
                    locked_version: None,
                    kind,
                }
            }
            None => skip_item(key, PackageSource::Unresolved, kind),
        };
    }
    let value = &entry.value;
    match resolve(key, value) {
        Resolved::Skip(source) => skip_item(key, source, kind),
        Resolved::Dep {
            name,
            constraint,
            source,
            version_offset,
        } => {
            let global_start = entry.content_start + version_offset;
            let global_end = entry.content_end;
            let (line, col_start) = offset_to_line_col(starts, global_start);
            // `version_offset` indexes the *decoded* value. That only lands on the right
            // source byte while the two are identical, so an escaped string reports its
            // line and declines the span rather than handing `--fix` a drifted offset.
            let col_end = if entry.escaped {
                col_start
            } else {
                col_start + global_end.saturating_sub(global_start)
            };
            Item {
                name,
                version_constraint: constraint,
                source,
                version_line: line,
                version_col_start: col_start,
                version_col_end: col_end,
                registry: None,
                locked_version: None,
                kind,
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

fn skip_item(name: &str, source: PackageSource, kind: DependencyKind) -> Item {
    Item {
        name: name.to_owned(),
        version_constraint: String::new(),
        source,
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: None,
        kind,
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
    fn section_determines_dependency_kind() {
        let content = r#"{
  "dependencies": { "react": "^18.0.0" },
  "devDependencies": { "vitest": "^1.0.0" },
  "peerDependencies": { "react-dom": "^18.0.0" },
  "optionalDependencies": { "fsevents": "^2.3.0" },
  "catalog": { "lodash": "^4.17.21" }
}"#;
        let m = parse(content);
        assert_eq!(find(&m, "react").kind, DependencyKind::Normal);
        assert_eq!(find(&m, "vitest").kind, DependencyKind::Dev);
        assert_eq!(find(&m, "react-dom").kind, DependencyKind::Peer);
        assert_eq!(find(&m, "fsevents").kind, DependencyKind::Optional);
        assert_eq!(find(&m, "lodash").kind, DependencyKind::Workspace);
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

    /// `overrides` and `resolutions` are how a vulnerable transitive dependency is
    /// pinned to a patched version. Not reading them meant the pin was invisible, so a
    /// stale one could never be reported.
    #[test]
    fn overrides_and_resolutions_are_collected() {
        let content = r#"{
          "dependencies": { "express": "^4.0.0" },
          "overrides": { "minimist": "1.2.6" },
          "resolutions": { "lodash": "4.17.21", "parent/debug": "4.3.4" },
          "pnpm": { "overrides": { "glob-parent": ">=5.1.2" } }
        }"#;
        let m = PackageJsonParser.parse(content).expect("valid JSON");
        let by_name = |n: &str| m.items.iter().find(|i| i.name == n).cloned();

        for name in ["minimist", "lodash", "debug", "glob-parent"] {
            let it = by_name(name).unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(it.kind, DependencyKind::Override, "{name}");
        }
        assert_eq!(by_name("minimist").unwrap().version_constraint, "1.2.6");
        assert_eq!(by_name("express").unwrap().kind, DependencyKind::Normal);
    }

    /// npm's nested form scopes an override to the parent that pulls the package in, and
    /// spells "the parent itself" as `"."`, which names no new package.
    #[test]
    fn nested_override_keys_resolve_to_the_package_they_name() {
        let content = r#"{ "overrides": { "foo": { ".": "1.0.0", "bar": "2.0.0" } } }"#;
        let m = PackageJsonParser.parse(content).expect("valid JSON");
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"bar"), "got {names:?}");
        assert!(!names.contains(&"."), "got {names:?}");
    }

    #[test]
    fn resolution_key_paths_and_globs_name_the_last_segment() {
        assert_eq!(override_name("parent/child"), Some("child"));
        assert_eq!(override_name("**/lodash"), Some("lodash"));
        assert_eq!(override_name("@scope/pkg"), Some("@scope/pkg"));
        assert_eq!(override_name("lodash@^4"), Some("lodash"));
        assert_eq!(override_name("**/@scope/pkg"), Some("@scope/pkg"));
        assert_eq!(override_name("parent/@scope/pkg"), Some("@scope/pkg"));
        assert_eq!(override_name("@scope/pkg@^1"), Some("@scope/pkg"));
        assert_eq!(override_name("."), None);
    }

    /// npm's documented `$name` override value means "use the version of my own direct
    /// dependency", not a version range. It reached the version checker verbatim and
    /// came back `unparseable constraint: unexpected character '$'` — a hard error on a
    /// valid manifest.
    #[test]
    fn a_dollar_override_resolves_to_the_dependency_it_names() {
        let content = r#"{
  "dependencies": { "semver": "^7.5.0" },
  "overrides": { "semver": "$semver" }
}"#;
        let m = parse(content);
        let overridden = m
            .items
            .iter()
            .find(|i| i.kind == DependencyKind::Override)
            .expect("an override item");
        assert_eq!(overridden.name, "semver");
        assert_eq!(overridden.version_constraint, "^7.5.0");
        assert_eq!(overridden.source, PackageSource::Registry);
        // The recorded span holds `$semver`, not the constraint, so it must not be
        // offered to `--fix` as a place to write a version.
        assert!(!overridden.is_rewritable());
    }

    /// A reference to something the manifest never declares is unresolvable, not a
    /// parse error: the package is real, its intended version simply cannot be read.
    #[test]
    fn a_dollar_override_naming_nothing_declared_is_unresolvable() {
        let content = r#"{ "overrides": { "semver": "$semver" } }"#;
        let m = parse(content);
        let overridden = m.items.first().expect("an override item");
        assert_eq!(overridden.name, "semver");
        assert_eq!(overridden.source, PackageSource::Unresolved);
        assert!(!overridden.is_checkable());
    }

    /// The reference form is npm's, and only inside an override map. A `$` elsewhere is
    /// left exactly as it was read.
    #[test]
    fn a_dollar_is_only_a_reference_inside_an_override() {
        assert_eq!(override_reference("$semver"), Some("semver"));
        assert_eq!(override_reference("$@scope/pkg"), Some("@scope/pkg"));
        assert_eq!(override_reference("$"), None);
        assert_eq!(override_reference("^7.5.0"), None);

        let content = r#"{ "dependencies": { "weird": "$semver" } }"#;
        let m = parse(content);
        assert_eq!(find(&m, "weird").version_constraint, "$semver");
    }

    /// A pnpm override key scoped to a parent (`foo@2>bar`) pins **bar**. Reading the
    /// first segment named `foo`, so the entry was checked against an unrelated
    /// package's version list — and `fix --all` would then have rewritten a pin on `bar`
    /// to whatever `foo`'s newest release happened to be.
    #[test]
    fn a_scoped_override_key_names_the_package_after_the_last_arrow() {
        assert_eq!(override_name("foo@2>bar"), Some("bar"));
        assert_eq!(override_name("foo>bar"), Some("bar"));
        assert_eq!(override_name("a>b>c"), Some("c"));
        assert_eq!(
            override_name("@scope/pkg@1>@scope/other"),
            Some("@scope/other")
        );
        assert_eq!(override_name("foo"), Some("foo"));
    }

    /// The same key read end to end through the parser, so the defect is falsified where
    /// it was observed rather than only at the helper.
    #[test]
    fn a_scoped_pnpm_override_is_checked_as_the_package_it_pins() {
        let content = r#"{ "pnpm": { "overrides": { "foo@2>bar": "3.0.0" } } }"#;
        let m = parse(content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["bar"], "got {names:?}");
        assert_eq!(find(&m, "bar").kind, DependencyKind::Override);
    }
}
