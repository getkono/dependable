//! Parser for a Gradle version catalog (`gradle/libs.versions.toml`).
//!
//! A catalog is the one part of a Gradle build that is data rather than program: it
//! is TOML with explicit version literals, so it parses without executing anything
//! and every version has a byte span to rewrite. The build scripts that consume it
//! are out of reach by construction — see [`ManifestKind::unreadable_manifests`],
//! which is how a project whose dependencies live in `build.gradle.kts` is told that
//! they were not read rather than reported as none.
//!
//! Only `[versions]` and `[libraries]` are read. `[bundles]` names groups of
//! libraries already declared here, and `[plugins]` resolves against the Gradle
//! Plugin Portal rather than a Maven repository.
//!
//! A `[libraries]` entry is reported as a [`DependencyKind::Normal`] dependency and
//! not as a central [`DependencyKind::Workspace`] declaration, which is what its
//! shape would otherwise suggest — a build script opts into it by alias, the way a
//! `csproj` opts into a `Directory.Packages.props` version. The difference is that
//! the opting-in half is readable there and unreadable here, so treating a catalog
//! entry as a declaration nothing has been shown to depend on would report every
//! Gradle project as depending on nothing at all.
//!
//! # `version.ref`
//!
//! A library may name a version instead of stating one:
//!
//! ```toml
//! [versions]
//! kotlin = "1.9.24"
//!
//! [libraries]
//! kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
//! ```
//!
//! That is structurally a Cargo member's `serde.workspace = true`, but it resolves
//! **within this file**, so it is resolved here rather than by
//! [`resolve_workspace_inheritance`](crate::resolve_workspace_inheritance) — which
//! matches a member to a root declaration *by name*, and an alias (`kotlin`) is not
//! the name of a package (`org.jetbrains.kotlin:kotlin-stdlib`).
//!
//! Because the `[versions]` literal is in this same file, a library that is the
//! **only** user of its alias also carries that literal's span, so `--fix` rewrites
//! the `[versions]` line — the line that governs it. An alias shared by several
//! libraries carries no span on any of them: one line cannot be rewritten to two
//! different versions, and the same reasoning is why a Cargo member is never
//! rewritten in place either. Such a library is [`PackageSource::Inherited`]:
//! checked and scanned for advisories, never written to.

use std::collections::HashMap;
use std::ops::Range;

use toml_edit::{ImDocument, Item as TomlItem, TableLike};

use super::Parser;
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{DependencyKind, Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `gradle/libs.versions.toml`.
pub struct GradleCatalogParser;

/// A version literal and where it is written, before it is known whether the
/// library that uses it may rewrite it.
struct Located {
    value: String,
    span: Range<usize>,
}

/// One library entry, read but not yet resolved.
struct Declared {
    /// The Maven coordinate, `groupId:artifactId`.
    name: String,
    /// The version stated here, with its own span.
    version: Option<Located>,
    /// The `[versions]` alias this entry defers to.
    reference: Option<String>,
}

impl Parser for GradleCatalogParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let doc = ImDocument::parse(content.to_owned())?;
        let root = doc.as_table();
        let starts = line_starts(content);

        let versions = read_versions(root);
        let declared = read_libraries(root);

        // An alias used by exactly one library is that library's own line to fix.
        let mut uses: HashMap<&str, usize> = HashMap::new();
        for entry in &declared {
            if let Some(alias) = &entry.reference {
                *uses.entry(alias.as_str()).or_default() += 1;
            }
        }

        let mut items = Vec::new();
        for entry in &declared {
            let item = match (&entry.version, &entry.reference) {
                (Some(version), _) => positioned(&entry.name, version, &starts),
                (None, Some(alias)) => {
                    let Some(target) = versions.get(alias.as_str()) else {
                        // The alias names nothing: the catalog states no version, so
                        // there is nothing to ask a registry for.
                        continue;
                    };
                    if uses.get(alias.as_str()).copied() == Some(1) {
                        positioned(&entry.name, target, &starts)
                    } else {
                        inherited(&entry.name, &target.value)
                    }
                }
                // A version supplied by a platform/BOM rather than by the catalog.
                (None, None) => continue,
            };
            items.push(item);
        }

        Ok(ParsedManifest {
            kind: ManifestKind::GradleVersionCatalog,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// Read `[versions]` into alias → literal.
fn read_versions(root: &dyn TableLike) -> HashMap<String, Located> {
    let mut out = HashMap::new();
    let Some(table) = root.get("versions").and_then(TomlItem::as_table_like) else {
        return out;
    };
    for (alias, item) in table.iter() {
        if let Some(located) = version_literal(item) {
            out.insert(alias.to_owned(), located);
        }
    }
    out
}

/// Read `[libraries]` into one record per entry, in source order.
fn read_libraries(root: &dyn TableLike) -> Vec<Declared> {
    let mut out = Vec::new();
    let Some(table) = root.get("libraries").and_then(TomlItem::as_table_like) else {
        return out;
    };
    for (_alias, item) in table.iter() {
        // The shorthand: `commons = "org.apache.commons:commons-lang3:3.14.0"`.
        if let Some(value) = item.as_value()
            && let Some(text) = value.as_str()
        {
            if let Some(declared) = shorthand(text, value.span()) {
                out.push(declared);
            }
            continue;
        }
        let Some(entry) = item.as_table_like() else {
            continue;
        };
        let Some(name) = coordinate(entry) else {
            continue;
        };
        let version = entry.get("version");
        out.push(Declared {
            name,
            version: version.and_then(version_literal),
            reference: version
                .and_then(TomlItem::as_table_like)
                .and_then(|v| v.get("ref"))
                .and_then(TomlItem::as_str)
                .map(str::to_owned),
        });
    }
    out
}

/// `groupId:artifactId` from `module`, else from the `group`/`name` pair.
///
/// One string either way, because that is what a registry lookup takes.
fn coordinate(entry: &dyn TableLike) -> Option<String> {
    if let Some(module) = entry.get("module").and_then(TomlItem::as_str) {
        return (!module.is_empty()).then(|| module.to_owned());
    }
    let group = entry.get("group").and_then(TomlItem::as_str)?;
    let name = entry.get("name").and_then(TomlItem::as_str)?;
    Some(format!("{group}:{name}"))
}

/// The version string an entry states, whether written plainly or as one of
/// Gradle's rich-version keys.
///
/// `prefer` is read last: where a rich version carries both, `strictly`/`require`
/// is the bound that actually holds and `prefer` only picks within it.
fn version_literal(item: &TomlItem) -> Option<Located> {
    if let Some(value) = item.as_value()
        && let Some(text) = value.as_str()
    {
        return Some(Located {
            value: text.to_owned(),
            span: unquoted(value.span()?),
        });
    }
    let table = item.as_table_like()?;
    for key in ["strictly", "require", "prefer"] {
        if let Some(inner) = table.get(key)
            && let Some(value) = inner.as_value()
            && let Some(text) = value.as_str()
        {
            return Some(Located {
                value: text.to_owned(),
                span: unquoted(value.span()?),
            });
        }
    }
    None
}

/// Narrow a quoted string's span to the text inside the quotes, which is what a
/// rewrite has to replace.
fn unquoted(span: Range<usize>) -> Range<usize> {
    (span.start + 1)..span.end.saturating_sub(1)
}

/// The `"group:artifact:version"` shorthand, whose version span is an offset into
/// the quoted string.
fn shorthand(text: &str, span: Option<Range<usize>>) -> Option<Declared> {
    let span = span?;
    let (coordinate, version) = text.rsplit_once(':')?;
    if coordinate.is_empty() || !coordinate.contains(':') || version.is_empty() {
        return None;
    }
    // `span` covers the quoted string; +1 skips the opening quote.
    let start = span.start + 1 + coordinate.len() + 1;
    Some(Declared {
        name: coordinate.to_owned(),
        version: Some(Located {
            value: version.to_owned(),
            span: start..start + version.len(),
        }),
        reference: None,
    })
}

/// An item pointing at the version literal that governs it, wherever in this file
/// that literal is written.
fn positioned(name: &str, version: &Located, starts: &[usize]) -> Item {
    let (line, col_start) = offset_to_line_col(starts, version.span.start);
    Item {
        name: name.to_owned(),
        version_constraint: version.value.clone(),
        source: PackageSource::Registry,
        version_line: line,
        version_col_start: col_start,
        version_col_end: col_start + version.span.len(),
        registry: None,
        locked_version: None,
        kind: DependencyKind::Normal,
    }
}

/// An item whose version is resolved but whose line belongs to other libraries too.
fn inherited(name: &str, version: &str) -> Item {
    Item {
        name: name.to_owned(),
        version_constraint: version.to_owned(),
        source: PackageSource::Inherited,
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: None,
        kind: DependencyKind::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = r#"
[versions]
kotlin = "1.9.24"
junit = { require = "5.10.0" }
guava = "33.0.0-jre"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlin" }
junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version.ref = "junit" }
okhttp = { module = "com.squareup.okhttp3:okhttp", version = "4.12.0" }
guava = { group = "com.google.guava", name = "guava", version = "32.1.3-jre" }
commons = "org.apache.commons:commons-lang3:3.14.0"

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }

[bundles]
testing = ["junit-jupiter"]
"#;

    fn items(content: &str) -> Vec<Item> {
        GradleCatalogParser.parse(content).expect("parses").items
    }

    fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
        items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("no item {name}"))
    }

    /// The span has to point at the version text and nothing else, or `--fix`
    /// splices a version into the middle of a coordinate.
    fn slice<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).expect("line");
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn a_coordinate_is_one_name_however_it_is_spelled() {
        let parsed = items(CATALOG);
        let names: Vec<&str> = parsed.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "org.jetbrains.kotlin:kotlin-stdlib",
                "org.jetbrains.kotlin:kotlin-reflect",
                "org.junit.jupiter:junit-jupiter",
                "com.squareup.okhttp3:okhttp",
                "com.google.guava:guava",
                "org.apache.commons:commons-lang3",
            ],
            "`module`, `group`+`name`, and the shorthand all name one package; \
             `[plugins]` and `[bundles]` name none, and source order is kept"
        );
    }

    #[test]
    fn a_stated_version_is_rewritable_where_it_is_written() {
        let parsed = items(CATALOG);
        let okhttp = find(&parsed, "com.squareup.okhttp3:okhttp");
        assert_eq!(okhttp.version_constraint, "4.12.0");
        assert_eq!(slice(CATALOG, okhttp), "4.12.0");
        assert!(okhttp.is_rewritable());

        let guava = find(&parsed, "com.google.guava:guava");
        assert_eq!(guava.version_constraint, "32.1.3-jre");
        assert_eq!(slice(CATALOG, guava), "32.1.3-jre");

        let commons = find(&parsed, "org.apache.commons:commons-lang3");
        assert_eq!(commons.version_constraint, "3.14.0");
        assert_eq!(
            slice(CATALOG, commons),
            "3.14.0",
            "the shorthand's span is the version, not the whole coordinate"
        );
    }

    /// The sole user of an alias may rewrite the `[versions]` line, because that
    /// line governs it and nothing else.
    #[test]
    fn a_reference_used_once_points_at_the_versions_line() {
        let parsed = items(CATALOG);
        let junit = find(&parsed, "org.junit.jupiter:junit-jupiter");
        assert_eq!(junit.version_constraint, "5.10.0");
        assert_eq!(slice(CATALOG, junit), "5.10.0");
        assert_eq!(
            CATALOG.lines().nth(junit.version_line),
            Some("junit = { require = \"5.10.0\" }"),
            "the rich-version form states the literal too"
        );
        assert!(junit.is_rewritable());
    }

    /// A shared alias is one line that two libraries would rewrite to two
    /// different versions, so neither writes it — the rule a Cargo member follows.
    #[test]
    fn a_shared_reference_is_resolved_but_never_rewritten() {
        let parsed = items(CATALOG);
        for name in [
            "org.jetbrains.kotlin:kotlin-stdlib",
            "org.jetbrains.kotlin:kotlin-reflect",
        ] {
            let item = find(&parsed, name);
            assert_eq!(item.source, PackageSource::Inherited);
            assert_eq!(item.version_constraint, "1.9.24", "still checked");
            assert!(item.is_checkable(), "{name}");
            assert!(!item.is_rewritable(), "{name}");
            assert!(!item.has_position(), "{name}");
        }
    }

    #[test]
    fn an_entry_stating_no_version_states_nothing_to_check() {
        // A BOM supplies the version at build time; a dangling ref supplies none.
        let parsed = items(
            "[libraries]\n\
             bom = { module = \"org.example:managed\" }\n\
             dangling = { module = \"org.example:other\", version.ref = \"absent\" }\n",
        );
        assert!(parsed.is_empty());
    }

    #[test]
    fn a_catalog_that_is_not_toml_is_an_error_not_an_empty_project() {
        assert!(GradleCatalogParser.parse("[versions").is_err());
    }
}
