//! Reader for SwiftPM's `Package.resolved`.
//!
//! Unlike every other lockfile here, this one is the **source** of the dependency
//! list rather than an annotation on one. `Package.swift` is executable Swift —
//! dependencies are routinely assembled in loops, behind conditionals, and from
//! variables — so reading it as text produces wrong answers rather than
//! incomplete ones, and it is deliberately not read at all.
//! `Package.resolved` is plain JSON carrying the full flattened pin set:
//! identity, location URL, revision, and version for every resolved package.
//!
//! Formats: v2 (Swift 5.6+) and v3 (Xcode 15+) both spell pins as a top-level
//! `pins` array of `{identity, kind, location, state}`; v3 only adds an
//! `originHash` field beside it. The v1 shape (`object.pins[]`, with
//! `repositoryURL` in place of `location`) costs one extra key to accept and is
//! read too, because the alternative — reporting a Swift 5.5 project as having no
//! dependencies at all — is the silent wrong answer this whole ecosystem is
//! shaped to avoid.

use std::collections::{BTreeMap, HashMap};

use crate::error::ParseError;
use crate::item::{DependencyKind, Item, PackageSource};
use crate::lockfiles::LockfileData;
use crate::parsers::json_scan::scan_strings;

/// URL schemes a Swift package location may carry, longest-prefix first so
/// `git+https://` is never mistaken for `https://` with a `git+` host.
const SCHEMES: &[&str] = &[
    "git+https://",
    "git+ssh://",
    "https://",
    "http://",
    "ssh://",
    "git://",
];

/// One pin exactly as `Package.resolved` records it, before interpretation.
#[derive(Debug, Default)]
struct Pin {
    /// SwiftPM's package identity (the repository's last path segment, lowercased).
    identity: Option<String>,
    /// `remoteSourceControl`, `localSourceControl`, `fileSystem`, or `registry`.
    kind: Option<String>,
    /// The package's location: a git URL, or a path for a local package.
    location: Option<String>,
    /// The resolved semantic version, when the pin resolved to a tag.
    version: Option<String>,
    /// The branch, when the pin follows one instead of a version.
    branch: Option<String>,
    /// The resolved git revision. Always present for a source-control pin.
    revision: Option<String>,
}

/// The dependencies `Package.resolved` pins, in the order it records them.
///
/// This is the whole flattened resolution — SwiftPM records transitive pins
/// beside direct ones and does not distinguish them, so neither does this.
///
/// Never fails: malformed JSON yields whatever pins were scanned before the
/// error, which is the same degradation every other reader here offers.
#[must_use]
pub fn swift_package_resolved_items(content: &str) -> Vec<Item> {
    pins(content).iter().filter_map(pin_item).collect()
}

/// Parse `Package.resolved` into a name → resolved-version map.
///
/// Keyed by the same name [`swift_package_resolved_items`] gives each pin, so the
/// two agree about what a package is called.
///
/// # Errors
/// Never fails today; the signature matches every other lockfile reader so the
/// dispatch in [`crate::lockfiles::parse_lockfile_kind`] stays uniform.
pub fn parse_swift_package_resolved(content: &str) -> Result<LockfileData, ParseError> {
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for item in swift_package_resolved_items(content) {
        if let Some(version) = item.locked_version {
            versions.entry(item.name).or_default().push(version);
        }
    }
    Ok(LockfileData { versions })
}

/// The OSV `SwiftURL` name for a package location.
///
/// SwiftPM identifies a package by its git URL; OSV keys its 60-odd Swift
/// advisories by the same URL with the scheme and the `.git` suffix removed
/// (`github.com/vapor/vapor`). Getting either wrong does not fail loudly — it
/// silently matches nothing — so both are stripped here rather than at the query.
#[must_use]
pub fn swift_package_name(location: &str) -> String {
    let trimmed = location.trim();
    let scheme = SCHEMES.iter().find(|s| trimmed.starts_with(**s)).copied();
    let mut name = scheme.map_or(trimmed, |s| &trimmed[s.len()..]).to_string();

    // A `user@` prefix addresses the host; it does not name the package.
    if let Some(at) = name.find('@')
        && !name[..at].contains('/')
    {
        name = name[at + 1..].to_string();
    }

    // git's SCP shorthand (`github.com:owner/repo`) writes a colon where a URL
    // writes a slash. A port number is digits and is never this.
    if scheme.is_none()
        && let Some(colon) = name.find(':')
        && !name[colon + 1..].starts_with(|c: char| c.is_ascii_digit())
    {
        name.replace_range(colon..=colon, "/");
    }

    let name = name.trim_end_matches('/');
    let name = name.strip_suffix(".git").unwrap_or(name);
    name.trim_end_matches('/').to_string()
}

/// Collect every pin in the document, keyed by its array index so the fields of
/// one pin — which the scanner reports one at a time — reassemble in order.
fn pins(content: &str) -> Vec<Pin> {
    let mut by_index: BTreeMap<usize, Pin> = BTreeMap::new();
    for entry in scan_strings(content) {
        let Some((index, field)) = pin_field(&entry.path) else {
            continue;
        };
        let pin = by_index.entry(index).or_default();
        match field.as_slice() {
            // `package` is v1's spelling of `identity`.
            ["identity"] | ["package"] => pin.identity = Some(entry.value),
            ["kind"] => pin.kind = Some(entry.value),
            // `repositoryURL` is v1's spelling of `location`.
            ["location"] | ["repositoryURL"] => pin.location = Some(entry.value),
            ["state", "version"] => pin.version = Some(entry.value),
            ["state", "branch"] => pin.branch = Some(entry.value),
            ["state", "revision"] => pin.revision = Some(entry.value),
            _ => {}
        }
    }
    by_index.into_values().collect()
}

/// Split a scanned path into the pin index and the field path within that pin,
/// or `None` when the path is not inside a pin list.
///
/// Only `pins` at the document root (v2/v3) or directly under `object` (v1) is a
/// pin list; a `pins` key nested anywhere else belongs to something we are not
/// reading.
fn pin_field(path: &[String]) -> Option<(usize, Vec<&str>)> {
    let at = path.iter().position(|segment| segment == "pins")?;
    let rooted = at == 0 || (at == 1 && path[0] == "object");
    if !rooted {
        return None;
    }
    let index: usize = path.get(at + 1)?.parse().ok()?;
    let field: Vec<&str> = path[at + 2..].iter().map(String::as_str).collect();
    (!field.is_empty()).then_some((index, field))
}

/// Interpret one pin as a dependency, or `None` when it names nothing.
fn pin_item(pin: &Pin) -> Option<Item> {
    let local = matches!(
        pin.kind.as_deref(),
        Some("fileSystem" | "localSourceControl")
    ) || pin.location.as_deref().is_some_and(is_local_path);

    // A local package's location is a path, which is not a name; its identity is.
    let name = if local {
        pin.identity.clone()
    } else {
        pin.location
            .as_deref()
            .map(swift_package_name)
            .filter(|name| !name.is_empty())
            .or_else(|| pin.identity.clone())
    }?;

    // What the pin resolved to, in descending order of usefulness to a reader.
    let state = pin
        .version
        .clone()
        .or_else(|| pin.branch.clone())
        .or_else(|| pin.revision.clone())
        .unwrap_or_default();

    // `Inherited`, not `Registry`: the version was written somewhere other than
    // this entry — in `Package.resolved`, never in the manifest — so there is no
    // span in `Package.swift` to report or to rewrite, which is exactly what
    // `Item::has_position` reads the source to decide. A branch pin has no
    // version at all and is the git dependency it looks like.
    let (source, constraint, locked) = if local {
        (PackageSource::Local, state, None)
    } else if let Some(version) = pin.version.clone() {
        (PackageSource::Inherited, version.clone(), Some(version))
    } else {
        (PackageSource::Git, state, None)
    };

    Some(Item {
        name,
        version_constraint: constraint,
        source,
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: locked,
        kind: DependencyKind::Normal,
    })
}

/// Whether a location addresses the filesystem rather than a remote repository.
fn is_local_path(location: &str) -> bool {
    let trimmed = location.trim();
    trimmed.starts_with("file://")
        || trimmed.starts_with('/')
        || trimmed.starts_with('.')
        || trimmed.starts_with('~')
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &str = r#"{
  "pins" : [
    {
      "identity" : "swift-nio",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/apple/swift-nio.git",
      "state" : {
        "revision" : "635b2589494c97e48c62514bc8b37ced762e0a62",
        "version" : "2.65.0"
      }
    },
    {
      "identity" : "vapor",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/vapor/vapor",
      "state" : {
        "revision" : "0f1b6d1e1d6c86b2a2c5b0a1f8a1c8d5e1f0a9b8",
        "version" : "4.92.1"
      }
    }
  ],
  "version" : 2
}
"#;

    fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
        items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("no pin {name}"))
    }

    #[test]
    fn reads_every_pin_as_a_dependency() {
        let items = swift_package_resolved_items(V2);
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            ["github.com/apple/swift-nio", "github.com/vapor/vapor"]
        );

        let nio = find(&items, "github.com/apple/swift-nio");
        assert_eq!(nio.locked_version.as_deref(), Some("2.65.0"));
        assert_eq!(nio.version_constraint, "2.65.0");
        assert_eq!(nio.source, PackageSource::Inherited);
    }

    /// The pin set is the only record of what the project depends on, so a pin has
    /// to be worth checking — and it can never be worth *rewriting*, because the
    /// version it states is not written in any manifest this tool parsed.
    #[test]
    fn a_pin_is_checkable_but_has_nowhere_to_be_rewritten() {
        let nio = find(
            &swift_package_resolved_items(V2),
            "github.com/apple/swift-nio",
        )
        .clone();
        assert!(nio.is_checkable());
        assert!(!nio.has_position());
        assert!(!nio.is_rewritable());
    }

    /// v3 adds `originHash` and nothing else that matters, so it must read
    /// identically. The fixtures under `crates/dependable/tests/fixtures` assert
    /// the same thing over two real files.
    #[test]
    fn v3_reads_the_same_pins_as_v2() {
        let v3 = V2.replace("\"version\" : 2", "\"version\" : 3").replace(
            "\"pins\" : [",
            "\"originHash\" : \"abc123\",\n  \"pins\" : [",
        );
        assert_eq!(
            swift_package_resolved_items(&v3),
            swift_package_resolved_items(V2)
        );
    }

    /// v1 spells the same facts differently. Reading it wrong would report a
    /// Swift 5.5 project as depending on nothing at all.
    #[test]
    fn v1_pins_are_read_from_their_own_spelling() {
        let v1 = r#"{
  "object": {
    "pins": [
      {
        "package": "SwiftNIO",
        "repositoryURL": "https://github.com/apple/swift-nio.git",
        "state": { "branch": null, "revision": "635b25", "version": "2.65.0" }
      }
    ]
  },
  "version": 1
}"#;
        let items = swift_package_resolved_items(v1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "github.com/apple/swift-nio");
        assert_eq!(items[0].locked_version.as_deref(), Some("2.65.0"));
    }

    /// A branch pin resolves to a revision, not a version: there is nothing to ask
    /// OSV about and nothing to compare, and calling it a git dependency is what
    /// every other ecosystem already says about the same situation.
    #[test]
    fn a_branch_pin_is_a_git_dependency() {
        let lock = r#"{
  "pins": [
    {
      "identity": "experimental",
      "kind": "remoteSourceControl",
      "location": "https://github.com/acme/experimental.git",
      "state": { "branch": "main", "revision": "deadbeef" }
    }
  ],
  "version": 2
}"#;
        let items = swift_package_resolved_items(lock);
        assert_eq!(items[0].source, PackageSource::Git);
        assert_eq!(items[0].version_constraint, "main");
        assert_eq!(items[0].locked_version, None);
        assert!(!items[0].is_checkable());
    }

    #[test]
    fn a_local_package_is_named_by_its_identity_and_never_fetched() {
        let lock = r#"{
  "pins": [
    { "identity": "helpers", "kind": "fileSystem", "location": "/Users/me/helpers", "state": {} }
  ],
  "version": 2
}"#;
        let items = swift_package_resolved_items(lock);
        assert_eq!(items[0].name, "helpers");
        assert_eq!(items[0].source, PackageSource::Local);
        assert!(!items[0].is_checkable());
    }

    /// OSV keys `SwiftURL` by the repository URL with no scheme and no `.git`;
    /// either left on matches nothing and reports a vulnerable package as clean.
    #[test]
    fn a_package_name_is_the_url_osv_keys_advisories_by() {
        let cases = [
            (
                "https://github.com/vapor/vapor.git",
                "github.com/vapor/vapor",
            ),
            ("https://github.com/vapor/vapor", "github.com/vapor/vapor"),
            (
                "https://github.com/vapor/vapor.git/",
                "github.com/vapor/vapor",
            ),
            ("http://example.com/a/b.git", "example.com/a/b"),
            ("git://github.com/vapor/vapor.git", "github.com/vapor/vapor"),
            (
                "ssh://git@github.com/vapor/vapor.git",
                "github.com/vapor/vapor",
            ),
            ("git@github.com:vapor/vapor.git", "github.com/vapor/vapor"),
            (
                "git+https://github.com/vapor/vapor.git",
                "github.com/vapor/vapor",
            ),
        ];
        for (location, expected) in cases {
            assert_eq!(swift_package_name(location), expected, "{location}");
        }
    }

    #[test]
    fn locked_versions_agree_with_the_items() {
        let data = parse_swift_package_resolved(V2).unwrap();
        assert_eq!(data.versions["github.com/apple/swift-nio"], ["2.65.0"]);
        assert_eq!(data.versions["github.com/vapor/vapor"], ["4.92.1"]);
        assert_eq!(data.versions.len(), 2);
    }

    /// A `pins` key that is not the pin list must not be read as one.
    #[test]
    fn an_unrelated_pins_key_is_not_a_pin_list() {
        let lock = r#"{ "meta": { "pins": [ { "location": "https://x/y.git" } ] } }"#;
        assert!(swift_package_resolved_items(lock).is_empty());
    }

    #[test]
    fn malformed_json_yields_no_pins_rather_than_an_error() {
        assert!(swift_package_resolved_items("not json at all {{{").is_empty());
        assert!(parse_swift_package_resolved("").is_ok());
    }
}
