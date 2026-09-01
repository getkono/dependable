//! Parser for a Maven POM (`pom.xml`).
//!
//! The declarative half of a Maven build. A read-only DOM walk (`roxmltree`) over
//! the `<dependencies>` element directly under `<project>`, taking the coordinate
//! from `<groupId>`/`<artifactId>` and the constraint from `<version>`. The exact
//! byte range of the version *text* is recorded for `--fix` — the one difference
//! from [`csproj`](super::csproj), where a version is an attribute and the span
//! comes from `Attribute::range_value`.
//!
//! # `${property}`
//!
//! A version may name a property instead of stating one:
//!
//! ```xml
//! <properties>
//!   <okhttp.version>4.12.0</okhttp.version>
//! </properties>
//! <dependencies>
//!   <dependency>
//!     <groupId>com.squareup.okhttp3</groupId>
//!     <artifactId>okhttp</artifactId>
//!     <version>${okhttp.version}</version>
//!   </dependency>
//! </dependencies>
//! ```
//!
//! That is the same shape as a Gradle catalog's `version.ref`, and it is resolved
//! the same way and for the same reason: the literal is in **this** file, so the
//! resolution needs no IO and the span of the `<properties>` line is a real place
//! to rewrite. A property used by exactly one dependency carries that span; a
//! property several dependencies share carries none, because one line cannot be
//! rewritten to two different versions. Such a dependency is
//! [`PackageSource::Inherited`]: checked and scanned for advisories, never written
//! to. Only a version that is *entirely* one `${…}` is resolved — a composed value
//! like `1.${minor}` has no span that could be replaced with a version.
//!
//! # What is deliberately not resolved
//!
//! `<parent>` inheritance, `<dependencyManagement>`, and BOM imports are out of
//! scope: resolving any of them correctly can require fetching the parent POM from
//! a registry, which makes this a resolution engine rather than a parser. Maven's
//! built-in properties (`${project.version}`, `${revision}`, …) are not
//! `<properties>` entries and are likewise not resolved.
//!
//! The same holds for a coordinate: `<groupId>${project.groupId}</groupId>` — the
//! standard idiom for a sibling module in a multi-module build — names a built-in
//! this file does not state, and the dependency is reported under that literal
//! rather than dropped.
//!
//! A dependency whose version or coordinate those rules leave unknown is
//! **reported anyway**, with no constraint and no span — the shape a Cargo member's unresolved
//! `dep.workspace = true` already has, which the CLI renders as `(unresolved)` and
//! never fetches, fixes, or claims a status for. Dropping it instead, as the
//! `csproj` parser drops an MSBuild `$(…)` version, would report a POM that
//! inherits half its versions as depending on only the other half. The
//! [`unreadable_manifests`](crate::manifest::ManifestKind::unreadable_manifests)
//! notice is the wrong surface for this: it is keyed on a file *name*, and a
//! `pom.xml` is perfectly readable — it is individual entries within one that are
//! not.

use std::collections::HashMap;
use std::ops::Range;

use super::Parser;
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{DependencyKind, Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// How many `${a}` → `${b}` **hops** a property chain may take before it is given
/// up on, which also bounds a property that (illegally) refers to itself.
///
/// A hop is a step from one property to the next, so the longest chain that still
/// resolves is `MAX_PROPERTY_HOPS + 1` properties long: eight hops from `${p0}`
/// reach `p8`, and `p8` is read. [`terminal`] loops one more time than this number
/// for exactly that reason — the first read is not a hop.
const MAX_PROPERTY_HOPS: usize = 8;

/// Parses `pom.xml`.
pub struct PomXmlParser;

/// A version literal and where it is written, before it is known whether the
/// dependency that uses it may rewrite it.
struct Located {
    value: String,
    span: Option<Range<usize>>,
}

/// Where one dependency's version comes from.
enum Source {
    /// Stated on the dependency itself.
    Literal(Located),
    /// Deferred to a `<properties>` entry, named here by the property the chain
    /// ends at — the one whose line a rewrite would have to touch.
    Property(String),
    /// Not knowable from this file alone: absent, a built-in property, a composed
    /// value, or a property this POM does not declare.
    Unknown,
}

/// One half of a `groupId:artifactId` coordinate: the text to report it under, and
/// whether that text is the resolved value or the literal this file could not
/// resolve.
struct Half {
    text: String,
    resolved: bool,
}

/// One `<dependency>`, read but not yet resolved.
struct Declared {
    name: String,
    version: Source,
    source: PackageSource,
    kind: DependencyKind,
}

impl Parser for PomXmlParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let doc = roxmltree::Document::parse(content)
            .map_err(|e| ParseError::Structural(e.to_string()))?;
        let starts = line_starts(content);
        let project = doc.root_element();

        let properties = read_properties(project);
        let declared = read_dependencies(project, &properties);

        // A property used by exactly one thing in this document is that
        // dependency's own line to fix; one anything else also reads belongs to
        // none of them — see `count_property_refs`.
        let mut uses: HashMap<String, usize> = HashMap::new();
        count_property_refs(project, &properties, &mut uses);

        let items = declared
            .iter()
            .map(|entry| match &entry.version {
                Source::Literal(version) => item(entry, version, &starts),
                Source::Property(name) => {
                    let located = &properties[name.as_str()];
                    if uses.get(name.as_str()).copied() == Some(1) {
                        item(entry, located, &starts)
                    } else {
                        inherited(entry, &located.value)
                    }
                }
                Source::Unknown => unresolved(entry),
            })
            .collect();

        Ok(ParsedManifest {
            kind: ManifestKind::PomXml,
            items,
            alternate_registries: Vec::new(),
            notices: profile_notice(project).into_iter().collect(),
        })
    }
}

/// Read `<properties>` into property name → stated value.
///
/// The value is kept exactly as written, `${…}` and all: whether it is a literal or
/// another reference is [`terminal`]'s question, not this one's.
fn read_properties<'a>(project: roxmltree::Node<'a, 'a>) -> HashMap<String, Located> {
    let mut out = HashMap::new();
    let Some(table) = child(project, "properties") else {
        return out;
    };
    for entry in table.children().filter(roxmltree::Node::is_element) {
        if let Some(located) = text_of(entry) {
            out.insert(entry.tag_name().name().to_owned(), located);
        }
    }
    out
}

/// Read the `<dependencies>` directly under `<project>`, in source order.
///
/// Only that one: `<dependencyManagement>` states versions for dependencies
/// declared elsewhere, `<build><plugins>` describes the build rather than the
/// artifact, and `<profiles>` applies conditionally. None of the three is a
/// dependency of this project as written.
fn read_dependencies<'a>(
    project: roxmltree::Node<'a, 'a>,
    properties: &HashMap<String, Located>,
) -> Vec<Declared> {
    let mut out = Vec::new();
    let Some(list) = child(project, "dependencies") else {
        return out;
    };
    for node in list.children().filter(roxmltree::Node::is_element) {
        if node.tag_name().name() != "dependency" {
            continue;
        }
        // A `${…}` half is interpolated, since `${project.groupId}` aside, a group is
        // often a property. A half this file cannot resolve is reported under the
        // literal it states rather than dropped — see [`coordinate`].
        let group = coordinate(node, "groupId", properties);
        let artifact = coordinate(node, "artifactId", properties);
        // A `<dependency>` naming neither half states nothing at all: there is no
        // text to report it under, so there is nothing to report.
        if group.is_none() && artifact.is_none() {
            continue;
        }
        let known = group.as_ref().is_some_and(|half| half.resolved)
            && artifact.as_ref().is_some_and(|half| half.resolved);
        let name = format!(
            "{}:{}",
            group.map(|half| half.text).unwrap_or_default(),
            artifact.map(|half| half.text).unwrap_or_default(),
        );
        let scope = child(node, "scope")
            .and_then(text_of)
            .map(|located| located.value)
            .unwrap_or_default();
        out.push(Declared {
            name,
            // A coordinate this file cannot state is a coordinate nothing can be
            // fetched for, whatever version sits beside it.
            version: if known {
                version_source(node, properties)
            } else {
                Source::Unknown
            },
            // A `system` dependency is a jar at a path on this machine, not
            // something a registry has ever heard of.
            source: match scope.as_str() {
                "system" => PackageSource::Local,
                _ => PackageSource::Registry,
            },
            kind: dependency_kind(node, &scope),
        });
    }
    out
}

/// Which section a `<dependency>` belongs to, read from `<scope>` and
/// `<optional>` rather than guessed.
///
/// `test` is the only scope that names a section [`DependencyKind`] has: `provided`
/// and `runtime` both describe a runtime dependency whose *provider* differs, which
/// is not the distinction this records.
fn dependency_kind(node: roxmltree::Node<'_, '_>, scope: &str) -> DependencyKind {
    if scope == "test" {
        return DependencyKind::Dev;
    }
    let optional = child(node, "optional")
        .and_then(text_of)
        .is_some_and(|located| located.value == "true");
    if optional {
        DependencyKind::Optional
    } else {
        DependencyKind::Normal
    }
}

/// Where a `<dependency>`'s version comes from, as far as this file can say.
fn version_source(node: roxmltree::Node<'_, '_>, properties: &HashMap<String, Located>) -> Source {
    // No `<version>` at all: supplied by `<dependencyManagement>` or a `<parent>`,
    // neither of which is read here.
    let Some(located) = child(node, "version").and_then(text_of) else {
        return Source::Unknown;
    };
    let Some(reference) = interpolation(&located.value) else {
        // A composed value (`1.${minor}`) states no version this file can rewrite.
        return if located.value.contains('$') {
            Source::Unknown
        } else {
            Source::Literal(located)
        };
    };
    match terminal(reference, properties) {
        Some(name) => Source::Property(name.to_owned()),
        None => Source::Unknown,
    }
}

/// The name of the property a `${…}` chain ends at — the one that states a literal.
///
/// `None` when the chain leaves this file, states nothing, or does not terminate.
fn terminal<'a>(start: &str, properties: &'a HashMap<String, Located>) -> Option<&'a str> {
    let mut name = start;
    // Inclusive: `MAX_PROPERTY_HOPS` hops means one more property read than hops
    // taken, since arriving at the first property costs no hop.
    for _ in 0..=MAX_PROPERTY_HOPS {
        let (key, located) = properties.get_key_value(name)?;
        match interpolation(&located.value) {
            Some(next) => name = next,
            None if located.value.contains('$') => return None,
            None => return Some(key.as_str()),
        }
    }
    None
}

/// The inner name of a value that is *entirely* one `${…}` reference.
fn interpolation(value: &str) -> Option<&str> {
    let inner = value.strip_prefix("${")?.strip_suffix('}')?;
    if inner.is_empty() || inner.contains(['$', '{', '}']) {
        return None;
    }
    Some(inner)
}

/// One half of a coordinate, with `${…}` resolved against `properties` where it can
/// be — and reported as written where it cannot.
///
/// `None` only when the element is absent or states nothing. An *unresolvable* half
/// (`${project.groupId}`, the standard idiom for a sibling module, or a property
/// declared in a `<parent>`) still yields the literal text, because dropping the
/// dependency would report a POM as depending on fewer things than it declares —
/// the silent omission this parser exists to avoid, and an asymmetry with
/// `<version>`, which is reported unresolved rather than deleted.
fn coordinate(
    node: roxmltree::Node<'_, '_>,
    tag: &str,
    properties: &HashMap<String, Located>,
) -> Option<Half> {
    let located = child(node, tag).and_then(text_of)?;
    let resolved = match interpolation(&located.value) {
        Some(reference) => terminal(reference, properties)
            .map(|name| properties[name].value.clone())
            .map(|text| Half {
                text,
                resolved: true,
            }),
        None if located.value.contains('$') => None,
        None => Some(Half {
            text: located.value.clone(),
            resolved: true,
        }),
    };
    Some(resolved.unwrap_or(Half {
        text: located.value,
        resolved: false,
    }))
}

/// Count every `${…}` reference in the document, by the property its chain ends at.
///
/// The whole document, because sole ownership of a `<properties>` line is a fact
/// about that line and not about `<dependencies>`. A POM that states
/// `<lib.version>32.1.3-jre</lib.version>` and reads it from both the top-level
/// `guava` and a `<profiles>`-only `guava-gwt` has one line and two readers;
/// counting only the top-level list makes `guava` the sole reader, so `--fix`
/// rewrites the `<properties>` line and silently moves `guava-gwt` with it — a
/// different artifact, never fetched, never validated, never named in the fix
/// record. `<dependencyManagement>` and a `<plugin>`'s `<version>` are the same
/// story. This is the `count_version_refs` rule of
/// [`gradle_catalog`](super::gradle_catalog), applied to the same defect.
///
/// A `<properties>` value that is *entirely* one `${…}` is a link in a chain
/// rather than a reader of it, and is skipped: the reference is counted against
/// the property the chain ends at when whoever started the chain is counted.
/// A composed value (`${core.version}-jre`) **is** a reader, and is counted.
fn count_property_refs(
    project: roxmltree::Node<'_, '_>,
    properties: &HashMap<String, Located>,
    uses: &mut HashMap<String, usize>,
) {
    let table = child(project, "properties");
    for node in project.descendants().filter(roxmltree::Node::is_text) {
        let Some(text) = node.text() else { continue };
        // A top-level `<properties>` entry's own value: a pure `${…}` is a chain
        // link, not a use of the property it names.
        let chain_link = table
            .is_some_and(|table| node.parent().and_then(|entry| entry.parent()) == Some(table))
            && interpolation(text.trim()).is_some();
        if chain_link {
            continue;
        }
        for reference in references(text) {
            if let Some(name) = terminal(reference, properties) {
                *uses.entry(name.to_owned()).or_default() += 1;
            }
        }
    }
}

/// Every `${…}` reference in a string, in order, by the name each names.
///
/// A version may compose one (`1.${minor}`) and a plugin configuration may hold
/// several, so this scans rather than matching the whole value the way
/// [`interpolation`] does.
fn references(value: &str) -> impl Iterator<Item = &str> {
    let mut rest = value;
    std::iter::from_fn(move || {
        loop {
            let start = rest.find("${")?;
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                rest = "";
                return None;
            };
            let inner = &after[..end];
            rest = &after[end + 1..];
            if !inner.is_empty() && !inner.contains(['$', '{']) {
                return Some(inner);
            }
        }
    })
}

/// Say that a `<profiles>` block was seen and its dependencies were not read.
///
/// A profile applies conditionally — on a JDK version, an activated property, an
/// operating system — so its dependencies are not this project's as written, and
/// parsing them would state as fact something that holds only under a condition
/// this file does not evaluate. Staying out is the decision; staying *silent*
/// about it is not, because a POM that declares every one of its dependencies
/// inside a profile then lists as `(0 dependencies)`, which reads as complete and
/// is not.
fn profile_notice(project: roxmltree::Node<'_, '_>) -> Option<String> {
    let profiles = child(project, "profiles")?;
    let count = profiles
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "dependency"
                && node
                    .parent()
                    .is_some_and(|list| list.tag_name().name() == "dependencies")
        })
        .count();
    if count == 0 {
        return None;
    }
    Some(format!(
        "{count} {} declared inside <profiles> {} not listed: a profile applies conditionally, so its dependencies are not this project's as written",
        if count == 1 {
            "dependency"
        } else {
            "dependencies"
        },
        if count == 1 { "is" } else { "are" },
    ))
}

/// The first direct child element named `tag`.
fn child<'a>(node: roxmltree::Node<'a, 'a>, tag: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == tag)
}

/// An element's text content and the byte span of the text itself, trimmed of the
/// whitespace a pretty-printed POM puts around it.
///
/// **Every** text node is concatenated, because that is the value Maven reads.
/// `<version>1.0<!--patched--\>.0</version>` is one version, `1.0.0`, split in two
/// by a comment; taking only the first node would report `1.0` — a version the file
/// never states, then dutifully fetched and evaluated against. The span is the
/// separate question, and it is dropped wherever the source bytes and the value
/// cannot be the same bytes: a character reference (`1.0&#46;0`), a `CDATA`
/// section, or text interrupted like this. An empty element yields nothing: it
/// states no value, which is not the same as stating one this parser resolved.
fn text_of(node: roxmltree::Node<'_, '_>) -> Option<Located> {
    let mut texts = node.children().filter(roxmltree::Node::is_text);
    let first = texts.next()?;
    let raw = first.text()?;
    let mut joined = raw.to_owned();
    let mut single = true;
    for rest in texts {
        single = false;
        joined.push_str(rest.text().unwrap_or_default());
    }
    let value = joined.trim();
    if value.is_empty() {
        return None;
    }
    let range = first.range();
    let faithful = single && range.len() == raw.len();
    let start = range.start + (raw.len() - raw.trim_start().len());
    let len = value.len();
    Some(Located {
        value: value.to_owned(),
        span: faithful.then(|| start..start + len),
    })
}

/// An item pointing at the version literal that governs it, wherever in this file
/// that literal is written.
fn item(entry: &Declared, version: &Located, starts: &[usize]) -> Item {
    let Some(span) = &version.span else {
        return inherited(entry, &version.value);
    };
    let (line, col_start) = offset_to_line_col(starts, span.start);
    Item {
        name: entry.name.clone(),
        version_constraint: version.value.clone(),
        source: entry.source,
        version_line: line,
        version_col_start: col_start,
        version_col_end: col_start + span.len(),
        registry: None,
        locked_version: None,
        kind: entry.kind,
    }
}

/// An item whose version is known but whose line is not this dependency's to
/// rewrite — a `<properties>` entry several dependencies share.
///
/// The entry's own source survives when it says something
/// [`Inherited`](PackageSource::Inherited) would contradict: a `<scope>system</scope>`
/// jar is [`Local`](PackageSource::Local) — there is no registry that has heard of
/// it — whether or not its version happened to need reconstructing. Only a registry
/// entry becomes `Inherited`, which is the case the variant describes.
fn inherited(entry: &Declared, version: &str) -> Item {
    Item {
        name: entry.name.clone(),
        version_constraint: version.to_owned(),
        source: match entry.source {
            PackageSource::Registry => PackageSource::Inherited,
            other => other,
        },
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: None,
        kind: entry.kind,
    }
}

/// An item this file states no version for: it is reported, and nothing is claimed
/// about it.
fn unresolved(entry: &Declared) -> Item {
    inherited(entry, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        PomXmlParser.parse(content).unwrap()
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    fn find<'a>(manifest: &'a ParsedManifest, name: &str) -> &'a Item {
        manifest
            .items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("no item {name}"))
    }

    fn pom(body: &str) -> String {
        format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             {body}</project>\n"
        )
    }

    #[test]
    fn parses_literal_versions_with_positions() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>com.google.guava</groupId>\n\
             \x20     <artifactId>guava</artifactId>\n\
             \x20     <version>32.1.3-jre</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        assert_eq!(m.kind, ManifestKind::PomXml);
        let guava = find(&m, "com.google.guava:guava");
        assert_eq!(guava.version_constraint, "32.1.3-jre");
        assert_eq!(sliced(&content, guava), "32.1.3-jre");
        assert_eq!(guava.source, PackageSource::Registry);
        assert!(guava.is_rewritable());
    }

    /// A property used once carries the `<properties>` line that governs it, so
    /// `--fix` rewrites where the version is actually written.
    #[test]
    fn a_property_used_once_carries_the_line_that_states_it() {
        let content = pom("  <properties>\n\
             \x20   <okhttp.version>4.12.0</okhttp.version>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>com.squareup.okhttp3</groupId>\n\
             \x20     <artifactId>okhttp</artifactId>\n\
             \x20     <version>${okhttp.version}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let okhttp = find(&m, "com.squareup.okhttp3:okhttp");
        assert_eq!(okhttp.version_constraint, "4.12.0");
        assert_eq!(sliced(&content, okhttp), "4.12.0");
        assert!(okhttp.is_rewritable());
    }

    /// One line cannot be rewritten to two different versions, so a shared property
    /// is resolved and checked but never written to.
    #[test]
    fn a_shared_property_is_resolved_but_never_rewritten() {
        let content = pom("  <properties>\n\
             \x20   <jackson.version>2.17.0</jackson.version>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>com.fasterxml.jackson.core</groupId>\n\
             \x20     <artifactId>jackson-core</artifactId>\n\
             \x20     <version>${jackson.version}</version>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>com.fasterxml.jackson.core</groupId>\n\
             \x20     <artifactId>jackson-databind</artifactId>\n\
             \x20     <version>${jackson.version}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        for artifact in ["jackson-core", "jackson-databind"] {
            let item = find(&m, &format!("com.fasterxml.jackson.core:{artifact}"));
            assert_eq!(item.version_constraint, "2.17.0", "{artifact}");
            assert_eq!(item.source, PackageSource::Inherited, "{artifact}");
            assert!(item.is_checkable(), "{artifact}");
            assert!(!item.is_rewritable(), "{artifact}");
        }
    }

    /// The required behaviour: a version this file cannot resolve is reported with
    /// no constraint rather than dropped, so the dependency list is never quietly
    /// short.
    #[test]
    fn an_unresolvable_version_is_reported_without_a_constraint() {
        let content = pom("  <parent>\n\
             \x20   <groupId>org.springframework.boot</groupId>\n\
             \x20   <artifactId>spring-boot-starter-parent</artifactId>\n\
             \x20   <version>3.2.5</version>\n\
             \x20 </parent>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.springframework.boot</groupId>\n\
             \x20     <artifactId>spring-boot-starter-web</artifactId>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.example</groupId>\n\
             \x20     <artifactId>sibling</artifactId>\n\
             \x20     <version>${project.version}</version>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.example</groupId>\n\
             \x20     <artifactId>composed</artifactId>\n\
             \x20     <version>1.${minor}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        // The `<parent>` is not a dependency, and its version is not read.
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "org.springframework.boot:spring-boot-starter-web",
                "org.example:sibling",
                "org.example:composed",
            ]
        );
        for item in &m.items {
            assert!(item.version_constraint.is_empty(), "{item:?}");
            assert_eq!(item.source, PackageSource::Inherited, "{item:?}");
            assert!(!item.is_checkable(), "{item:?}");
            assert!(!item.has_position(), "{item:?}");
        }
    }

    /// Versions stated for dependencies declared elsewhere, for the build, or under
    /// a condition are not this project's dependencies.
    #[test]
    fn only_the_projects_own_dependencies_are_read() {
        let content = pom("  <dependencyManagement>\n\
             \x20   <dependencies>\n\
             \x20     <dependency>\n\
             \x20       <groupId>managed</groupId>\n\
             \x20       <artifactId>managed</artifactId>\n\
             \x20       <version>1.0.0</version>\n\
             \x20     </dependency>\n\
             \x20   </dependencies>\n\
             \x20 </dependencyManagement>\n\
             \x20 <build>\n\
             \x20   <plugins>\n\
             \x20     <plugin>\n\
             \x20       <dependencies>\n\
             \x20         <dependency>\n\
             \x20           <groupId>plugin</groupId>\n\
             \x20           <artifactId>plugin</artifactId>\n\
             \x20           <version>2.0.0</version>\n\
             \x20         </dependency>\n\
             \x20       </dependencies>\n\
             \x20     </plugin>\n\
             \x20   </plugins>\n\
             \x20 </build>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>real</groupId>\n\
             \x20     <artifactId>real</artifactId>\n\
             \x20     <version>3.0.0</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["real:real"]);
    }

    /// `<scope>` and `<optional>` are stated in the manifest, so they are read
    /// rather than guessed at from a file name.
    #[test]
    fn scope_and_optional_name_the_section() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.junit.jupiter</groupId>\n\
             \x20     <artifactId>junit-jupiter</artifactId>\n\
             \x20     <version>5.10.2</version>\n\
             \x20     <scope>test</scope>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.example</groupId>\n\
             \x20     <artifactId>extra</artifactId>\n\
             \x20     <version>1.0.0</version>\n\
             \x20     <optional>true</optional>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.example</groupId>\n\
             \x20     <artifactId>vendored</artifactId>\n\
             \x20     <version>1.0.0</version>\n\
             \x20     <scope>system</scope>\n\
             \x20     <systemPath>/opt/vendored.jar</systemPath>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        assert_eq!(
            find(&m, "org.junit.jupiter:junit-jupiter").kind,
            DependencyKind::Dev
        );
        assert_eq!(find(&m, "org.example:extra").kind, DependencyKind::Optional);

        let vendored = find(&m, "org.example:vendored");
        assert_eq!(vendored.source, PackageSource::Local);
        assert!(!vendored.is_checkable(), "a system jar has no registry");
    }

    /// A property may name another; the span that governs is the one that finally
    /// states a literal.
    #[test]
    fn a_property_chain_resolves_to_the_line_that_states_a_literal() {
        let content = pom("  <properties>\n\
             \x20   <alias>real.version</alias>\n\
             \x20   <real.version>9.9.9</real.version>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>g</groupId>\n\
             \x20     <artifactId>a</artifactId>\n\
             \x20     <version>${alias}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        // `<alias>` states a literal of its own, so it is the terminal property.
        let m = parse(&content);
        assert_eq!(find(&m, "g:a").version_constraint, "real.version");

        let chained = content.replace(
            "<alias>real.version</alias>",
            "<alias>${real.version}</alias>",
        );
        let m = parse(&chained);
        let item = find(&m, "g:a");
        assert_eq!(item.version_constraint, "9.9.9");
        assert_eq!(sliced(&chained, item), "9.9.9");
    }

    /// A cycle must terminate rather than spin, and states no version.
    #[test]
    fn a_property_cycle_resolves_to_nothing() {
        let content = pom("  <properties>\n\
             \x20   <a>${b}</a>\n\
             \x20   <b>${a}</b>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>g</groupId>\n\
             \x20     <artifactId>a</artifactId>\n\
             \x20     <version>${a}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        assert_eq!(find(&m, "g:a").version_constraint, "");
    }

    /// A group stated as a property still names a package. One that is not
    /// resolvable names nothing that could be looked up — but the dependency is
    /// still declared, so it is reported under the literal it states rather than
    /// deleted from the manifest's own list.
    #[test]
    fn a_coordinate_may_be_stated_by_property() {
        let content = pom("  <properties>\n\
             \x20   <group>org.example</group>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>${group}</groupId>\n\
             \x20     <artifactId>named</artifactId>\n\
             \x20     <version>1.0.0</version>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>${project.groupId}</groupId>\n\
             \x20     <artifactId>unnameable</artifactId>\n\
             \x20     <version>1.0.0</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["org.example:named", "${project.groupId}:unnameable"]
        );
    }

    /// `${project.groupId}` is *the* idiom for a sibling module in a multi-module
    /// build, and a POM using it for two of its three dependencies must not list as
    /// depending on one. Reported under the literal, with no constraint — the shape
    /// a parent-deferred version already has, which the CLI renders `(unresolved)`
    /// and never fetches — rather than dropped in silence.
    #[test]
    fn a_group_this_file_cannot_resolve_is_reported_not_dropped() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>${project.groupId}</groupId>\n\
             \x20     <artifactId>app-core</artifactId>\n\
             \x20     <version>${project.version}</version>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.slf4j</groupId>\n\
             \x20     <artifactId>slf4j-api</artifactId>\n\
             \x20     <version>2.0.13</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        assert_eq!(m.items.len(), 2, "both dependencies are declared");
        let sibling = find(&m, "${project.groupId}:app-core");
        assert_eq!(sibling.version_constraint, "");
        assert_eq!(sibling.source, PackageSource::Inherited);
        assert!(
            !sibling.is_checkable(),
            "no coordinate, so nothing to fetch"
        );
        assert!(!sibling.is_rewritable());
        assert_eq!(find(&m, "org.slf4j:slf4j-api").version_constraint, "2.0.13");
    }

    /// A `<groupId>` this file never states is the same omission by a shorter
    /// route: the artifact is named, so the entry is reported under what there is.
    /// A `<dependency>` naming neither half states nothing at all and is skipped.
    #[test]
    fn a_missing_coordinate_half_is_still_reported_under_the_other() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <artifactId>orphan</artifactId>\n\
             \x20     <version>1.0.0</version>\n\
             \x20   </dependency>\n\
             \x20   <dependency>\n\
             \x20     <version>2.0.0</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec![":orphan"]);
        assert_eq!(m.items[0].version_constraint, "");
        assert!(!m.items[0].is_checkable());
    }

    /// A `system` jar is a file on this machine whatever shape its version takes.
    /// Reconstructing the version — here around a comment — must not relabel the
    /// entry as one a registry could answer for: `Inherited` is checkable, and the
    /// run would go and ask crates of a jar no registry has ever published.
    #[test]
    fn a_system_scoped_jar_stays_local_when_its_version_is_reconstructed() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>g</groupId>\n\
             \x20     <artifactId>cmtsys</artifactId>\n\
             \x20     <version>1.0<!--x-->.0</version>\n\
             \x20     <scope>system</scope>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let item = find(&m, "g:cmtsys");
        assert_eq!(item.version_constraint, "1.0.0");
        assert_eq!(item.source, PackageSource::Local);
        assert!(!item.is_checkable(), "a system jar has no registry to ask");
    }

    /// Whitespace around a version is formatting, not part of it, and the span has
    /// to exclude it or `--fix` would rewrite the indentation too.
    #[test]
    fn a_span_excludes_the_whitespace_around_the_text() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>g</groupId>\n\
             \x20     <artifactId>a</artifactId>\n\
             \x20     <version>\n\
             \x20       1.2.3\n\
             \x20     </version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let item = find(&m, "g:a");
        assert_eq!(item.version_constraint, "1.2.3");
        assert_eq!(sliced(&content, item), "1.2.3");
    }

    /// An `<exclusions>` block names packages that must **not** be pulled in. Its
    /// coordinates are nested, and reading only direct children is what keeps them
    /// from being mistaken for the dependency's own.
    #[test]
    fn an_exclusion_is_not_a_dependency() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.example</groupId>\n\
             \x20     <artifactId>app</artifactId>\n\
             \x20     <version>1.0.0</version>\n\
             \x20     <exclusions>\n\
             \x20       <exclusion>\n\
             \x20         <groupId>commons-logging</groupId>\n\
             \x20         <artifactId>commons-logging</artifactId>\n\
             \x20       </exclusion>\n\
             \x20     </exclusions>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let names: Vec<&str> = m.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["org.example:app"]);
        assert_eq!(sliced(&content, &m.items[0]), "1.0.0");
    }

    #[test]
    fn malformed_xml_is_a_structural_error() {
        assert!(PomXmlParser.parse("<project><dependencies>").is_err());
    }

    #[test]
    fn a_pom_without_dependencies_yields_none() {
        let m = parse(&pom("  <artifactId>solo</artifactId>\n"));
        assert!(m.items.is_empty());
        assert!(m.notices.is_empty());
    }

    /// A comment splits the version into two text nodes. Reading only the first
    /// states `1.0` — a version this file never declares, which would then be
    /// fetched and evaluated as if it were the real constraint.
    #[test]
    fn a_version_interrupted_by_a_comment_is_read_whole() {
        let content = pom("  <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>g</groupId>\n\
             \x20     <artifactId>a</artifactId>\n\
             \x20     <version>1.0<!--patched-->.0</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        let m = parse(&content);
        let item = find(&m, "g:a");
        assert_eq!(
            item.version_constraint, "1.0.0",
            "every text node is the value Maven reads"
        );
        assert!(
            !item.is_rewritable(),
            "the source bytes are not the value's bytes, so there is nothing to rewrite"
        );
    }

    /// The sibling cases: an escaped character and a `CDATA` section both state the
    /// whole version, and neither offers bytes a rewrite could replace.
    #[test]
    fn an_escaped_or_wrapped_version_is_read_whole_and_never_rewritten() {
        for spelling in ["1.0&#46;0", "<![CDATA[1.0.0]]>"] {
            let content = pom(&format!(
                "  <dependencies>\n\
                 \x20   <dependency>\n\
                 \x20     <groupId>g</groupId>\n\
                 \x20     <artifactId>a</artifactId>\n\
                 \x20     <version>{spelling}</version>\n\
                 \x20   </dependency>\n\
                 \x20 </dependencies>\n"
            ));
            let m = parse(&content);
            let item = find(&m, "g:a");
            assert_eq!(item.version_constraint, "1.0.0", "{spelling}");
            assert!(!item.is_rewritable(), "{spelling}");
        }
    }

    /// A property the top-level list reads once but a `<profiles>` block reads too
    /// has two readers, not one. Rewriting its line would move an artifact that was
    /// never fetched, never validated, and never named in the fix record.
    #[test]
    fn a_property_a_profile_also_reads_is_not_one_dependencys_to_rewrite() {
        let content = pom("  <properties>\n\
             \x20   <lib.version>32.1.3-jre</lib.version>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>com.google.guava</groupId>\n\
             \x20     <artifactId>guava</artifactId>\n\
             \x20     <version>${lib.version}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n\
             \x20 <profiles>\n\
             \x20   <profile>\n\
             \x20     <id>gwt</id>\n\
             \x20     <dependencies>\n\
             \x20       <dependency>\n\
             \x20         <groupId>com.google.guava</groupId>\n\
             \x20         <artifactId>guava-gwt</artifactId>\n\
             \x20         <version>${lib.version}</version>\n\
             \x20       </dependency>\n\
             \x20     </dependencies>\n\
             \x20   </profile>\n\
             \x20 </profiles>\n");
        let m = parse(&content);
        let guava = find(&m, "com.google.guava:guava");
        assert_eq!(guava.version_constraint, "32.1.3-jre");
        assert!(
            guava.is_checkable(),
            "the version is known and worth checking"
        );
        assert!(
            !guava.is_rewritable(),
            "the profile reads the same line, and would move with it"
        );
    }

    /// The same rule for the other two readers a POM has, so no single reader is
    /// privileged: `<dependencyManagement>` and a build plugin's own version.
    #[test]
    fn a_property_read_elsewhere_in_the_document_is_never_rewritable() {
        let elsewhere = [
            "  <dependencyManagement>\n\
             \x20   <dependencies>\n\
             \x20     <dependency>\n\
             \x20       <groupId>g</groupId>\n\
             \x20       <artifactId>managed</artifactId>\n\
             \x20       <version>${lib.version}</version>\n\
             \x20     </dependency>\n\
             \x20   </dependencies>\n\
             \x20 </dependencyManagement>\n",
            "  <build>\n\
             \x20   <plugins>\n\
             \x20     <plugin>\n\
             \x20       <groupId>g</groupId>\n\
             \x20       <artifactId>plug</artifactId>\n\
             \x20       <version>${lib.version}</version>\n\
             \x20     </plugin>\n\
             \x20   </plugins>\n\
             \x20 </build>\n",
        ];
        for other in elsewhere {
            let content = pom(&format!(
                "  <properties>\n\
                 \x20   <lib.version>1.2.3</lib.version>\n\
                 \x20 </properties>\n\
                 {other}\
                 \x20 <dependencies>\n\
                 \x20   <dependency>\n\
                 \x20     <groupId>g</groupId>\n\
                 \x20     <artifactId>a</artifactId>\n\
                 \x20     <version>${{lib.version}}</version>\n\
                 \x20   </dependency>\n\
                 \x20 </dependencies>\n"
            ));
            let m = parse(&content);
            let item = find(&m, "g:a");
            assert_eq!(item.version_constraint, "1.2.3", "{other}");
            assert!(!item.is_rewritable(), "{other}");
        }
    }

    /// A composed `<properties>` value reads the property it names, so the line it
    /// names is shared; a value that is *only* a reference is a link in a chain and
    /// is not itself a reader, or no chained property could ever be rewritten.
    #[test]
    fn a_chain_link_is_not_a_reader_but_a_composed_value_is() {
        let chained = pom("  <properties>\n\
             \x20   <alias>${real.version}</alias>\n\
             \x20   <real.version>9.9.9</real.version>\n\
             \x20 </properties>\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>g</groupId>\n\
             \x20     <artifactId>a</artifactId>\n\
             \x20     <version>${alias}</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n");
        assert!(
            find(&parse(&chained), "g:a").is_rewritable(),
            "one dependency, one chain, one line to rewrite"
        );

        // A second property composing the same line is a reader of it, so the line
        // is no longer any one dependency's to rewrite.
        let composed = chained
            .replace(
                "<version>${alias}</version>",
                "<version>${real.version}</version>",
            )
            .replace(
                "<alias>${real.version}</alias>",
                "<bundle.version>${real.version}-jre</bundle.version>",
            );
        let m = parse(&composed);
        let item = find(&m, "g:a");
        assert_eq!(item.version_constraint, "9.9.9");
        assert!(
            !item.is_rewritable(),
            "`<bundle.version>` composes the same line into a second value"
        );
    }

    /// Eight hops is what the constant says, so eight hops has to resolve.
    #[test]
    fn a_chain_resolves_up_to_the_documented_number_of_hops() {
        let chain = |hops: usize| {
            let mut properties = String::from("  <properties>\n");
            for hop in 0..hops {
                properties.push_str(&format!("    <p{hop}>${{p{}}}</p{hop}>\n", hop + 1));
            }
            properties.push_str(&format!("    <p{hops}>9.9.9</p{hops}>\n  </properties>\n"));
            let content = pom(&format!(
                "{properties}  <dependencies>\n\
                 \x20   <dependency>\n\
                 \x20     <groupId>g</groupId>\n\
                 \x20     <artifactId>a</artifactId>\n\
                 \x20     <version>${{p0}}</version>\n\
                 \x20   </dependency>\n\
                 \x20 </dependencies>\n"
            ));
            parse(&content).items[0].version_constraint.clone()
        };
        assert_eq!(chain(MAX_PROPERTY_HOPS), "9.9.9", "the documented limit");
        assert_eq!(
            chain(MAX_PROPERTY_HOPS + 1),
            "",
            "one hop past it states nothing, rather than spinning"
        );
    }

    /// Not parsing conditional dependencies is the decision; not *saying so* would
    /// leave a POM that declares all of them in a profile listing as empty.
    #[test]
    fn a_profiles_block_holding_dependencies_is_announced() {
        let content = pom("  <profiles>\n\
             \x20   <profile>\n\
             \x20     <id>native</id>\n\
             \x20     <dependencies>\n\
             \x20       <dependency>\n\
             \x20         <groupId>g</groupId>\n\
             \x20         <artifactId>a</artifactId>\n\
             \x20         <version>1.0.0</version>\n\
             \x20       </dependency>\n\
             \x20       <dependency>\n\
             \x20         <groupId>g</groupId>\n\
             \x20         <artifactId>b</artifactId>\n\
             \x20         <version>2.0.0</version>\n\
             \x20       </dependency>\n\
             \x20     </dependencies>\n\
             \x20   </profile>\n\
             \x20 </profiles>\n");
        let m = parse(&content);
        assert!(m.items.is_empty(), "a profile dependency is conditional");
        assert_eq!(m.notices.len(), 1, "{:?}", m.notices);
        assert!(
            m.notices[0].contains("2 dependencies declared inside <profiles>"),
            "{:?}",
            m.notices
        );
    }

    /// A profile that declares no dependency of its own has nothing to announce.
    #[test]
    fn a_profile_without_dependencies_says_nothing() {
        let content = pom("  <profiles>\n\
             \x20   <profile>\n\
             \x20     <id>release</id>\n\
             \x20     <properties>\n\
             \x20       <skip.tests>true</skip.tests>\n\
             \x20     </properties>\n\
             \x20   </profile>\n\
             \x20 </profiles>\n");
        assert!(parse(&content).notices.is_empty());
    }
}
