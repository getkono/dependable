//! Parser for `Cargo.toml`.
//!
//! Uses `toml_edit`'s span-preserving immutable document so we can record the
//! exact byte range of every version value for in-place `--fix` editing.

use std::collections::BTreeMap;
use std::ops::Range;

use toml_edit::{ImDocument, Item as TomlItem, TableLike};

use super::Parser;
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{AlternateRegistryDecl, ManifestKind, ParsedManifest};

/// Parses `Cargo.toml`, recording version positions for in-place fixes.
pub struct CargoTomlParser;

const DEP_SECTIONS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

impl Parser for CargoTomlParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let doc = ImDocument::parse(content.to_owned())?;
        let root = doc.as_table();
        let starts = line_starts(content);
        let mut items = Vec::new();

        // [dependencies], [dev-dependencies], [build-dependencies]
        for &section in DEP_SECTIONS {
            if let Some(table) = root.get(section).and_then(|i| i.as_table_like()) {
                collect(table, &starts, &mut items);
            }
        }

        // [workspace.dependencies]
        if let Some(deps) = root
            .get("workspace")
            .and_then(|i| i.as_table_like())
            .and_then(|ws| ws.get("dependencies"))
            .and_then(|i| i.as_table_like())
        {
            collect(deps, &starts, &mut items);
        }

        // [registries.*] — alternate registry index URLs
        let mut alternate_registries = Vec::new();
        if let Some(regs) = root.get("registries").and_then(|i| i.as_table_like()) {
            for (name, item) in regs.iter() {
                let index_url = item
                    .as_table_like()
                    .and_then(|t| t.get("index"))
                    .and_then(TomlItem::as_str)
                    .map(str::to_owned);
                alternate_registries.push(AlternateRegistryDecl {
                    name: name.to_owned(),
                    index_url,
                    auth_token: None,
                });
            }
        }

        Ok(ParsedManifest {
            kind: ManifestKind::CargoToml,
            items,
            alternate_registries,
        })
    }
}

/// Parse Cargo's `$CARGO_HOME/config.toml` and optional `credentials.toml` into
/// alternate-registry declarations, keyed by alias (the name used by a
/// dependency's `registry = "..."`).
///
/// `[registries.<name>]` tables contribute the sparse `index` URL (normally from
/// `config`) and the auth `token` (normally from `credentials`, which wins over
/// any token declared inline in `config`). IO-free: the caller reads the two
/// files and passes their contents; a missing `credentials` file is `None`.
///
/// Malformed input yields no declarations rather than an error, and registries
/// without an `index` are still returned (with `index_url: None`) so the caller
/// can skip them gracefully.
#[must_use]
pub fn parse_cargo_config(config: &str, credentials: Option<&str>) -> Vec<AlternateRegistryDecl> {
    let mut decls: BTreeMap<String, AlternateRegistryDecl> = BTreeMap::new();

    // `config.toml` supplies index URLs (and, rarely, inline tokens).
    for (name, index, token) in registries_in(config) {
        let decl = decls
            .entry(name.clone())
            .or_insert_with(|| empty_registry(name));
        if index.is_some() {
            decl.index_url = index;
        }
        if token.is_some() {
            decl.auth_token = token;
        }
    }

    // `credentials.toml` supplies tokens, taking precedence over inline ones.
    if let Some(credentials) = credentials {
        for (name, _index, token) in registries_in(credentials) {
            if token.is_none() {
                continue;
            }
            decls
                .entry(name.clone())
                .or_insert_with(|| empty_registry(name))
                .auth_token = token;
        }
    }

    decls.into_values().collect()
}

/// An [`AlternateRegistryDecl`] with only its alias set.
fn empty_registry(name: String) -> AlternateRegistryDecl {
    AlternateRegistryDecl {
        name,
        index_url: None,
        auth_token: None,
    }
}

/// Extract `(name, index, token)` from every `[registries.<name>]` table in a
/// Cargo `config`/`credentials` TOML document. Unparseable input yields nothing.
fn registries_in(content: &str) -> Vec<(String, Option<String>, Option<String>)> {
    let Ok(doc) = ImDocument::parse(content.to_owned()) else {
        return Vec::new();
    };
    let Some(regs) = doc
        .as_table()
        .get("registries")
        .and_then(TomlItem::as_table_like)
    else {
        return Vec::new();
    };
    regs.iter()
        .filter_map(|(name, item)| {
            let table = item.as_table_like()?;
            let str_field = |key| table.get(key).and_then(TomlItem::as_str).map(str::to_owned);
            Some((name.to_owned(), str_field("index"), str_field("token")))
        })
        .collect()
}

fn collect(table: &dyn TableLike, starts: &[usize], items: &mut Vec<Item>) {
    for (name, item) in table.iter() {
        if let Some(parsed) = parse_dependency(name, item, starts) {
            items.push(parsed);
        }
    }
}

fn parse_dependency(name: &str, item: &TomlItem, starts: &[usize]) -> Option<Item> {
    // String form: `serde = "1.0"`
    if let Some(value) = item.as_value()
        && let Some(version) = value.as_str()
    {
        let span = value.span()?;
        return Some(make_item(
            name,
            version,
            span,
            PackageSource::Registry,
            None,
            starts,
        ));
    }

    // Table-like form: inline `{ version = "1.0", ... }` or `[dependencies.serde]`
    if let Some(table) = item.as_table_like() {
        if table.get("workspace").and_then(TomlItem::as_bool) == Some(true) {
            return Some(skip_item(name, PackageSource::Local));
        }
        if table.contains_key("path") {
            return Some(skip_item(name, PackageSource::Local));
        }
        if table.contains_key("git") {
            return Some(skip_item(name, PackageSource::Git));
        }
        let registry = table
            .get("registry")
            .and_then(TomlItem::as_str)
            .map(str::to_owned);
        if let Some(version_item) = table.get("version")
            && let Some(version) = version_item.as_str()
        {
            let span = version_item.span()?;
            return Some(make_item(
                name,
                version,
                span,
                PackageSource::Registry,
                registry,
                starts,
            ));
        }
    }
    None
}

fn make_item(
    name: &str,
    version: &str,
    span: Range<usize>,
    source: PackageSource,
    registry: Option<String>,
    starts: &[usize],
) -> Item {
    // `span` covers the quoted string; strip the surrounding quotes.
    let inner_start = span.start + 1;
    let inner_end = span.end.saturating_sub(1);
    let (line, col_start) = offset_to_line_col(starts, inner_start);
    let col_end = col_start + inner_end.saturating_sub(inner_start);
    Item {
        name: name.to_owned(),
        version_constraint: version.to_owned(),
        source,
        version_line: line,
        version_col_start: col_start,
        version_col_end: col_end,
        registry,
        locked_version: None,
    }
}

fn skip_item(name: &str, source: PackageSource) -> Item {
    Item {
        name: name.to_owned(),
        version_constraint: String::new(),
        source,
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        CargoTomlParser.parse(content).unwrap()
    }

    /// The recorded position should slice back to exactly the version value.
    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    fn find<'a>(m: &'a ParsedManifest, name: &str) -> &'a Item {
        m.items.iter().find(|i| i.name == name).unwrap()
    }

    #[test]
    fn string_dependency_records_position() {
        let content = "[dependencies]\nserde = \"1.0\"\n";
        let m = parse(content);
        let it = find(&m, "serde");
        assert_eq!(it.version_constraint, "1.0");
        assert_eq!(it.source, PackageSource::Registry);
        assert_eq!(sliced(content, it), "1.0");
    }

    #[test]
    fn inline_table_with_features() {
        let content = "[dependencies]\ntokio = { version = \"1.35\", features = [\"full\"] }\n";
        let m = parse(content);
        let it = find(&m, "tokio");
        assert_eq!(it.version_constraint, "1.35");
        assert_eq!(sliced(content, it), "1.35");
    }

    #[test]
    fn expanded_table_form() {
        let content = "[dependencies.reqwest]\nversion = \"0.12\"\nfeatures = [\"json\"]\n";
        let m = parse(content);
        let it = find(&m, "reqwest");
        assert_eq!(it.version_constraint, "0.12");
        assert_eq!(sliced(content, it), "0.12");
    }

    #[test]
    fn path_and_git_and_workspace_are_classified() {
        let content = "[dependencies]\nlocal = { path = \"../local\" }\nfromgit = { git = \"https://example.com/x\" }\nshared = { workspace = true }\n";
        let m = parse(content);
        assert_eq!(find(&m, "local").source, PackageSource::Local);
        assert_eq!(find(&m, "fromgit").source, PackageSource::Git);
        assert_eq!(find(&m, "shared").source, PackageSource::Local);
    }

    #[test]
    fn dev_and_build_sections_and_registry() {
        let content = "[dev-dependencies]\ncriterion = \"0.5\"\n\n[build-dependencies]\ncc = \"1\"\n\n[dependencies]\nprivate = { version = \"2.0\", registry = \"my-registry\" }\n";
        let m = parse(content);
        assert_eq!(find(&m, "criterion").version_constraint, "0.5");
        assert_eq!(find(&m, "cc").version_constraint, "1");
        assert_eq!(find(&m, "private").registry.as_deref(), Some("my-registry"));
    }

    #[test]
    fn parses_alternate_registry_decl() {
        let content = "[registries.my-registry]\nindex = \"https://example.com/index\"\n";
        let m = parse(content);
        assert_eq!(m.alternate_registries.len(), 1);
        assert_eq!(m.alternate_registries[0].name, "my-registry");
        assert_eq!(
            m.alternate_registries[0].index_url.as_deref(),
            Some("https://example.com/index")
        );
    }

    #[test]
    fn cargo_config_merges_index_from_config_and_token_from_credentials() {
        let config = "[registries.corp]\nindex = \"sparse+https://corp.example/index/\"\n";
        let credentials = "[registries.corp]\ntoken = \"Bearer sekret\"\n";
        let decls = parse_cargo_config(config, Some(credentials));
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "corp");
        assert_eq!(
            decls[0].index_url.as_deref(),
            Some("sparse+https://corp.example/index/")
        );
        assert_eq!(decls[0].auth_token.as_deref(), Some("Bearer sekret"));
    }

    #[test]
    fn cargo_config_credentials_token_overrides_inline_config_token() {
        let config = "[registries.corp]\nindex = \"https://corp.example/i\"\ntoken = \"inline\"\n";
        let credentials = "[registries.corp]\ntoken = \"from-credentials\"\n";
        let decls = parse_cargo_config(config, Some(credentials));
        assert_eq!(decls[0].auth_token.as_deref(), Some("from-credentials"));
    }

    #[test]
    fn cargo_config_without_credentials_has_index_but_no_token() {
        let config = "[registries.corp]\nindex = \"https://corp.example/i\"\n";
        let decls = parse_cargo_config(config, None);
        assert_eq!(decls.len(), 1);
        assert_eq!(
            decls[0].index_url.as_deref(),
            Some("https://corp.example/i")
        );
        assert_eq!(decls[0].auth_token, None);
    }

    #[test]
    fn cargo_config_ignores_malformed_and_unrelated_input() {
        // Missing closing bracket -> unparseable -> no declarations, not a panic.
        assert!(parse_cargo_config("[registries.corp\nindex = \"x\"", None).is_empty());
        // No `[registries]` table at all.
        assert!(parse_cargo_config("[net]\nretry = 2\n", None).is_empty());
    }
}
