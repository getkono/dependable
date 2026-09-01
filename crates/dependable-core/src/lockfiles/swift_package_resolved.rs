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
//!
//! Two consequences of the file being the list rather than an annotation on one:
//! a malformed file is reported as **unread** rather than degraded to the pins
//! scanned before the error, and every pin is [`DependencyKind::Indirect`],
//! because the resolution is flattened and marks no pin as direct.
//!
//! # Known limitation: repository path case
//! OSV keys `SwiftURL` advisories case-sensitively and real keys are mixed-case
//! (`github.com/weichsel/ZIPFoundation`, `github.com/marmelroy/Zip`). A
//! `Package.resolved` recording a lowercase spelling of such a repository —
//! which git clones happily, and which SwiftPM's own `identity` field uses —
//! produces a key OSV does not match, and the package is reported clean.
//! [`swift_package_name`] lowercases the host and queries a lowercase path
//! variant alongside the written one, which covers every direction but this: the
//! canonical casing is a fact only the forge holds.

use std::collections::{BTreeMap, HashMap};

use crate::error::ParseError;
use crate::item::{DependencyKind, Item, PackageSource};
use crate::lockfiles::LockfileData;
use crate::parsers::json_scan::scan_document;

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

/// The dependencies `Package.resolved` pins, in the order it records them, or
/// `None` when the file did not read.
///
/// This is the whole flattened resolution — SwiftPM records transitive pins
/// beside direct ones and does not distinguish them, so neither does this.
///
/// # Malformed input is unread, not partial
/// Every other reader here degrades to "whatever was scanned before the error",
/// because it annotates a list some manifest already produced: a pin it misses
/// costs a locked version, not a dependency. This file *is* the list — a
/// `Package.swift` is a program this crate declines to read — so a partial scan
/// would hand back a silently **short** dependency list presented as the whole
/// one, and a package dropped off the end is a package never scanned for
/// advisories. `None` says "this file told us nothing", which callers already
/// know how to report; a short list is the silent wrong answer.
#[must_use]
pub fn swift_package_resolved_items(content: &str) -> Option<Vec<Item>> {
    Some(pins(content)?.iter().filter_map(pin_item).collect())
}

/// Parse `Package.resolved` into a name → resolved-version map.
///
/// Keyed by the same name [`swift_package_resolved_items`] gives each pin, so the
/// two agree about what a package is called.
///
/// # Errors
/// Returns [`ParseError::Structural`] when the JSON does not read to its end, for
/// the reason [`swift_package_resolved_items`] documents: a partial pin set is a
/// short dependency list, not a partial annotation, and reporting the file as
/// unreadable is what puts a notice in front of the user.
pub fn parse_swift_package_resolved(content: &str) -> Result<LockfileData, ParseError> {
    let items = swift_package_resolved_items(content).ok_or_else(|| {
        ParseError::Structural(
            "Package.resolved is not well-formed JSON, so the pins it records could not be \
             read; this file is the whole dependency list of a Swift project, so a partial \
             read of it is not a shorter answer but a wrong one"
                .to_owned(),
        )
    })?;
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for item in items {
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
///
/// # Case
/// The **host** is lowercased unconditionally: hostnames are case-insensitive by
/// definition, and every OSV `SwiftURL` key spells one in lowercase, so
/// `GitHub.com/vapor/vapor` would otherwise match nothing.
///
/// The **path is left exactly as written**, because OSV's keys are case-sensitive
/// and mixed-case ones are real — `github.com/weichsel/ZIPFoundation`,
/// `github.com/marmelroy/Zip`, `github.com/migueldeicaza/SwiftTerm`. Lowercasing
/// the path would break precisely those.
///
/// That leaves one case nothing local can repair: a `Package.resolved` that
/// records a *lowercase* spelling of a repository whose OSV key is mixed-case
/// (`…/zipfoundation` for `…/ZIPFoundation`). Git clones either spelling happily
/// and SwiftPM lowercases `identity`, so both spellings circulate; recovering the
/// canonical one needs the forge, not this string. The other direction *is*
/// repaired — see [`swift_package_name_variants`], which the OSV scan queries
/// alongside the name — so only "written lower, keyed mixed" is missed.
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

    let name = name.trim_end_matches('/');
    let name = name.strip_suffix(".git").unwrap_or(name);
    normalize_host(name.trim_end_matches('/'), scheme.is_some())
}

/// Lowercase `name`'s host and join it to the path below it with a `/`, leaving
/// that path exactly as written.
///
/// The host is lowercased for the reason [`swift_package_name`] gives, and any port
/// is dropped: `ssh://git@github.com:22/apple/swift-nio.git` and
/// `https://github.com/apple/swift-nio.git` address the same repository, but only
/// the second spells the key OSV holds. A port is transport, not identity, and
/// leaving it on is the same silent false negative a mis-cased host is — the query
/// matches nothing and the package is reported clean.
fn normalize_host(name: &str, has_scheme: bool) -> String {
    match split_authority(name, has_scheme) {
        (host, Some(path)) => format!("{}/{path}", host.to_ascii_lowercase()),
        (host, None) => host.to_ascii_lowercase(),
    }
}

/// Split `name` into its host and the path beneath it, dropping the separator (and
/// a port, where there is one).
///
/// # A colon is a port or a path separator, and only the form of the location says which
/// `github.com:22/apple/swift-nio` and `github.com:42/pkg` are the same string
/// shape and mean opposite things, so no test applied to the colon's *neighbours*
/// can tell them apart. Guessing from whether the segment is numeric got both
/// wrong: an owner beginning with a digit (`1024jp/GzipSwift`, `0xOpenBytes`,
/// `4np`) kept a colon that OSV never matches, and an all-digit owner (`42/pkg`)
/// silently lost its segment, producing a well-formed key naming a *different*
/// package — the worse of the two, because nothing about it looks wrong.
///
/// What actually distinguishes them is the form: a port is URL syntax and only ever
/// follows a scheme, while git's SCP shorthand (`git@github.com:owner/repo`) has no
/// scheme by definition and writes a colon exactly where a URL writes a slash. So
/// `has_scheme` decides it, and the digits are never consulted.
///
/// An IPv6 literal is bracketed and full of colons that are neither, so the scan for
/// a separator begins after the closing `]`.
fn split_authority(name: &str, has_scheme: bool) -> (&str, Option<&str>) {
    let after_host = if name.starts_with('[') {
        name.find(']').map_or(0, |close| close + 1)
    } else {
        0
    };
    let find = |needle: char| name[after_host..].find(needle).map(|i| i + after_host);
    let slash = find('/');
    let colon = find(':');
    let split_at = |i: usize| (&name[..i], Some(&name[i + 1..]));

    if has_scheme {
        // URL syntax: the authority runs to the first `/`, and a `:` inside it is a
        // port.
        let (authority, path) = slash.map_or((name, None), split_at);
        let host = colon
            .filter(|i| *i < authority.len())
            .map_or(authority, |i| &authority[..i]);
        (host, path)
    } else {
        // No scheme, so no port: the first colon — if it comes before any slash — is
        // SCP shorthand's path separator.
        colon
            .filter(|colon| slash.is_none_or(|slash| *colon < slash))
            .or(slash)
            .map_or((name, None), split_at)
    }
}

/// Extra OSV `SwiftURL` keys worth asking about for a package named `name`.
///
/// OSV matches its Swift keys byte for byte while git forges treat a repository
/// path case-insensitively, so the same repository reaches us under whichever
/// spelling somebody pasted into `Package.swift`. Where a pin's path is not
/// already lowercase, the all-lowercase spelling is a second real key for the
/// same repository — `github.com/vapor/vapor` is keyed that way — and asking for
/// it too costs one batch entry and can only ever add a true match, since OSV
/// answers for the package it was asked about or not at all.
///
/// Empty when the name is already lowercase, which is the overwhelming majority.
///
/// The fold is **ASCII**, matching the host's: OSV's `SwiftURL` keys and the
/// hostnames in them are ASCII, and Unicode lowercasing can change a string's byte
/// length, which would hand OSV a key for a repository nobody wrote.
#[must_use]
pub fn swift_package_name_variants(name: &str) -> Vec<String> {
    let lowered = name.to_ascii_lowercase();
    if lowered == name {
        Vec::new()
    } else {
        vec![lowered]
    }
}

/// Collect every pin in the document, keyed by its array index so the fields of
/// one pin — which the scanner reports one at a time — reassemble in order.
///
/// `None` when the document is not well-formed JSON: see
/// [`swift_package_resolved_items`] for why a prefix of the pins is refused here
/// rather than returned.
fn pins(content: &str) -> Option<Vec<Pin>> {
    let scanned = scan_document(content);
    if !scanned.well_formed {
        return None;
    }
    let mut by_index: BTreeMap<usize, Pin> = BTreeMap::new();
    for entry in scanned.values {
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
    Some(by_index.into_values().collect())
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

    // `Locked`, not `Registry`: the version was written in `Package.resolved` and
    // never in a manifest, so there is no span in `Package.swift` to report or to
    // rewrite, which is exactly what `Item::has_position` reads the source to
    // decide. Not `Inherited` either — nothing was inherited, because nothing
    // declared it; a consumer told "inherited" would go looking for a central
    // declaration that does not exist. A branch pin has no version at all and is
    // the git dependency it looks like.
    let (source, constraint, locked) = if local {
        (PackageSource::Local, state, None)
    } else if let Some(version) = pin.version.clone() {
        (PackageSource::Locked, version.clone(), Some(version))
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
        // `Package.resolved` is the *flattened* resolution: a project depending
        // only on `swift-nio-ssl` gets pins for `swift-nio`, `swift-collections`,
        // and `swift-atomics` too, and the file marks none of them apart. So
        // nothing here can be called a direct dependency without inventing the
        // claim — and `direct: true` in `list --format json` is exactly that claim,
        // read by machines. `Indirect` is the kind that declines to make it.
        kind: DependencyKind::Indirect,
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

    /// The pins of a file that is expected to read.
    fn items(content: &str) -> Vec<Item> {
        swift_package_resolved_items(content).expect("well-formed Package.resolved")
    }

    fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
        items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("no pin {name}"))
    }

    #[test]
    fn reads_every_pin_as_a_dependency() {
        let items = items(V2);
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            ["github.com/apple/swift-nio", "github.com/vapor/vapor"]
        );

        let nio = find(&items, "github.com/apple/swift-nio");
        assert_eq!(nio.locked_version.as_deref(), Some("2.65.0"));
        assert_eq!(nio.version_constraint, "2.65.0");
        assert_eq!(
            nio.source,
            PackageSource::Locked,
            "the version came from this file, not from a declaration anywhere"
        );
    }

    /// The pin set is the only record of what the project depends on, so a pin has
    /// to be worth checking — and it can never be worth *rewriting*, because the
    /// version it states is not written in any manifest this tool parsed.
    #[test]
    fn a_pin_is_checkable_but_has_nowhere_to_be_rewritten() {
        let nio = find(&items(V2), "github.com/apple/swift-nio").clone();
        assert!(nio.is_checkable());
        assert!(!nio.has_position());
        assert!(!nio.is_rewritable());
    }

    /// `Package.resolved` is the flattened resolution: it lists a package the
    /// project depends on and a package that package depends on identically. So no
    /// pin may be reported as a direct dependency — `list --format json` publishes
    /// exactly that field, and a machine reading `"direct": true` off a transitive
    /// pin is being told something the file never said.
    #[test]
    fn a_pin_is_never_claimed_to_be_a_direct_dependency() {
        for item in items(V2) {
            assert_eq!(item.kind, DependencyKind::Indirect, "{}", item.name);
            assert!(!item.kind.is_direct(), "{}", item.name);
        }
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
        assert_eq!(items(&v3), items(V2));
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
        let items = items(v1);
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
        let items = items(lock);
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
        let items = items(lock);
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

    /// A port addresses the transport, not the package. OSV keys
    /// `github.com/apple/swift-nio`, so a pin written `ssh://git@github.com:22/…`
    /// would otherwise ask about `github.com:22/apple/swift-nio` — a key OSV has
    /// never heard of — and the same repository at the same version would come back
    /// clean through one URL and vulnerable through another.
    #[test]
    fn a_port_is_stripped_from_the_host() {
        let cases = [
            (
                "ssh://git@github.com:22/apple/swift-nio.git",
                "github.com/apple/swift-nio",
            ),
            (
                "https://github.com:443/apple/swift-nio.git",
                "github.com/apple/swift-nio",
            ),
            (
                "git://GitHub.com:9418/apple/swift-nio",
                "github.com/apple/swift-nio",
            ),
            // The port is transport only; a mixed-case path still survives it.
            (
                "ssh://git@github.com:22/weichsel/ZIPFoundation.git",
                "github.com/weichsel/ZIPFoundation",
            ),
        ];
        for (location, expected) in cases {
            assert_eq!(swift_package_name(location), expected, "{location}");
        }
    }

    /// The colon in git's SCP shorthand is a path separator, whatever the segment
    /// after it happens to look like. Reading it as a port when the segment was
    /// numeric produced two silent false negatives at once: `1024jp/GzipSwift` — a
    /// real, widely used package, as are `0xOpenBytes/*` and `4np/*` — kept a colon
    /// that OSV can never match, and `42/pkg` lost its owner entirely, yielding a
    /// well-formed key for a *different* repository, which no reader can spot as
    /// garbage and which could collide with a real advisory key.
    #[test]
    fn an_scp_shorthand_colon_is_a_path_separator_whatever_follows_it() {
        let cases = [
            // The owner begins with a digit. Nothing distinguishes this from a port
            // but the absence of a scheme.
            (
                "git@github.com:1024jp/GzipSwift.git",
                "github.com/1024jp/GzipSwift",
            ),
            // The owner is *all* digits — the case the old heuristic deleted.
            ("git@github.com:42/pkg.git", "github.com/42/pkg"),
            ("git@github.com:vapor/vapor.git", "github.com/vapor/vapor"),
            // A scheme is present, so here the same shape really is a port.
            (
                "ssh://git@github.com:22/apple/swift-nio.git",
                "github.com/apple/swift-nio",
            ),
            (
                "https://github.com:443/apple/swift-nio.git",
                "github.com/apple/swift-nio",
            ),
        ];
        for (location, expected) in cases {
            assert_eq!(swift_package_name(location), expected, "{location}");
        }
    }

    /// An IPv6 literal is bracketed and full of colons that separate nothing, so the
    /// search for a port or a path separator starts after the `]`.
    #[test]
    fn an_ipv6_literal_keeps_its_colons() {
        let cases = [
            ("https://[::1]/apple/swift-nio.git", "[::1]/apple/swift-nio"),
            // A scheme, so `:22` is a port.
            (
                "ssh://git@[::1]:22/apple/swift-nio",
                "[::1]/apple/swift-nio",
            ),
            // No scheme, so by the same rule as every other SCP location the colon
            // separates the host from the path — degenerate, but consistent, and it
            // does not mangle the address.
            ("[::1]:22", "[::1]/22"),
            // No separator at all: the whole literal is the host.
            ("[2001:db8::1]", "[2001:db8::1]"),
        ];
        for (location, expected) in cases {
            assert_eq!(swift_package_name(location), expected, "{location}");
        }
    }

    /// OSV's `SwiftURL` keys are matched byte for byte, and the real ones are
    /// mixed-case: `github.com/weichsel/ZIPFoundation`, `github.com/marmelroy/Zip`,
    /// `github.com/migueldeicaza/SwiftTerm`. Lowercasing the path would turn every
    /// one of those into a key OSV has never heard of — reporting a vulnerable
    /// package as clean, silently, which is the failure this ecosystem exists to
    /// avoid.
    #[test]
    fn a_mixed_case_repository_path_is_preserved_exactly() {
        let cases = [
            (
                "https://github.com/weichsel/ZIPFoundation.git",
                "github.com/weichsel/ZIPFoundation",
            ),
            (
                "https://github.com/marmelroy/Zip",
                "github.com/marmelroy/Zip",
            ),
            (
                "git@github.com:migueldeicaza/SwiftTerm.git",
                "github.com/migueldeicaza/SwiftTerm",
            ),
        ];
        for (location, expected) in cases {
            assert_eq!(swift_package_name(location), expected, "{location}");
        }
    }

    /// A hostname is case-insensitive by definition and every OSV `SwiftURL` key
    /// spells one in lowercase, so `GitHub.com/...` must not be carried through as
    /// written — and normalizing it must not touch the path beside it.
    #[test]
    fn the_host_is_lowercased_and_the_path_is_not() {
        assert_eq!(
            swift_package_name("https://GitHub.com/vapor/vapor.git"),
            "github.com/vapor/vapor"
        );
        assert_eq!(
            swift_package_name("https://GitHub.COM/weichsel/ZIPFoundation.git"),
            "github.com/weichsel/ZIPFoundation"
        );
        assert_eq!(
            swift_package_name("git@GitHub.com:marmelroy/Zip.git"),
            "github.com/marmelroy/Zip"
        );
    }

    /// A forge treats the repository path case-insensitively while OSV does not, so
    /// the all-lowercase spelling of a mixed-case name is a second real key for the
    /// same repository and is worth asking about too. A name that is already
    /// lowercase has no second spelling and must not cost a second query.
    #[test]
    fn a_mixed_case_name_offers_its_lowercase_spelling_as_a_second_key() {
        assert_eq!(
            swift_package_name_variants("github.com/Vapor/Vapor"),
            ["github.com/vapor/vapor"]
        );
        assert!(swift_package_name_variants("github.com/vapor/vapor").is_empty());
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
        assert!(items(lock).is_empty());
    }

    /// Malformed input is reported as unread rather than degraded to the pins that
    /// happened to scan first. Every other lockfile here annotates a list a manifest
    /// already produced, so a pin it misses costs a locked version; this file *is*
    /// the list, so a pin it misses is a dependency that is never scanned for
    /// advisories — presented, with no warning, as the complete set.
    #[test]
    fn a_malformed_file_reads_as_unread_not_as_a_short_list() {
        assert!(swift_package_resolved_items("not json at all {{{").is_none());
        assert!(swift_package_resolved_items("").is_none());
        assert!(parse_swift_package_resolved("not json at all {{{").is_err());
    }

    /// A file truncated mid-pin is the realistic malformed case (an interrupted
    /// write, a bad merge, a partial checkout) and the one that scans *most* of the
    /// pins before failing — which is exactly what makes a partial answer dangerous
    /// rather than obviously broken. It also used to panic outright.
    #[test]
    fn a_truncated_file_is_unread_rather_than_partially_read() {
        // Up to but not including the closing brace — a prefix that happens to end
        // there is the whole document, trailing newline aside.
        for cut in 1..V2.trim_end().len() {
            let truncated = &V2[..cut];
            assert!(
                swift_package_resolved_items(truncated).is_none(),
                "a prefix of {cut} bytes must not read as a dependency list"
            );
        }
        // The whole file still reads, so the check above is not vacuous.
        assert_eq!(items(V2).len(), 2);
    }
}
