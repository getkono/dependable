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
//! A dependency whose version those rules leave unknown is **reported anyway**,
//! with no constraint and no span — the shape a Cargo member's unresolved
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

/// How far a `${a}` → `${b}` → literal chain is followed before giving up, which
/// also bounds a property that (illegally) refers to itself.
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

        // A property used by exactly one dependency is that dependency's own line
        // to fix; one shared by several belongs to none of them.
        let mut uses: HashMap<&str, usize> = HashMap::new();
        for entry in &declared {
            if let Source::Property(name) = &entry.version {
                *uses.entry(name.as_str()).or_default() += 1;
            }
        }

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
        })
    }
}

/// Read `<properties>` into property name → literal, skipping any entry that only
/// points at another unknown.
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
        // Without both halves there is no coordinate to look up, and nothing that
        // could be reported under a name. A `${…}` group is interpolated first,
        // since `${project.groupId}` aside, a group is often a property.
        let (Some(group), Some(artifact)) = (
            interpolated(node, "groupId", properties),
            interpolated(node, "artifactId", properties),
        ) else {
            continue;
        };
        let scope = child(node, "scope")
            .and_then(text_of)
            .map(|located| located.value)
            .unwrap_or_default();
        out.push(Declared {
            name: format!("{group}:{artifact}"),
            version: version_source(node, properties),
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
    for _ in 0..MAX_PROPERTY_HOPS {
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

/// A child element's text, with `${…}` resolved against `properties`.
fn interpolated(
    node: roxmltree::Node<'_, '_>,
    tag: &str,
    properties: &HashMap<String, Located>,
) -> Option<String> {
    let located = child(node, tag).and_then(text_of)?;
    match interpolation(&located.value) {
        Some(reference) => Some(properties[terminal(reference, properties)?].value.clone()),
        None if located.value.contains('$') => None,
        None => Some(located.value),
    }
}

/// The first direct child element named `tag`.
fn child<'a>(node: roxmltree::Node<'a, 'a>, tag: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == tag)
}

/// An element's text content and the byte span of the text itself, trimmed of the
/// whitespace a pretty-printed POM puts around it.
///
/// The span is dropped where the source text and the unescaped text cannot be the
/// same bytes — a character reference, or text split across several nodes — because
/// an offset into one is not an offset into the other. An empty element yields
/// nothing: it states no value, which is not the same as stating one this parser
/// resolved.
fn text_of(node: roxmltree::Node<'_, '_>) -> Option<Located> {
    let mut texts = node.children().filter(roxmltree::Node::is_text);
    let text = texts.next()?;
    let raw = text.text()?;
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    let range = text.range();
    let faithful = texts.next().is_none() && range.len() == raw.len();
    let start = range.start + (raw.len() - raw.trim_start().len());
    Some(Located {
        value: value.to_owned(),
        span: faithful.then(|| start..start + value.len()),
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
fn inherited(entry: &Declared, version: &str) -> Item {
    Item {
        name: entry.name.clone(),
        version_constraint: version.to_owned(),
        source: PackageSource::Inherited,
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

    /// A group stated as a property still names a package; one that is not
    /// resolvable names nothing that could be looked up.
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
        assert_eq!(names, vec!["org.example:named"]);
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

    #[test]
    fn malformed_xml_is_a_structural_error() {
        assert!(PomXmlParser.parse("<project><dependencies>").is_err());
    }

    #[test]
    fn a_pom_without_dependencies_yields_none() {
        let m = parse(&pom("  <artifactId>solo</artifactId>\n"));
        assert!(m.items.is_empty());
    }
}
