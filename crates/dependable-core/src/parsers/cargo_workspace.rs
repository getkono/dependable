//! Pure readers for Cargo workspace topology: the `[workspace]` table and a
//! manifest's own `[package] name`.
//!
//! Member globs are returned **raw** — glob expansion needs the filesystem and
//! is done in the IO layer ([`dependable_fetch`]). These readers only turn
//! `&str` manifest content into plain data.

use std::collections::BTreeMap;

use toml_edit::{ImDocument, Item as TomlItem};

use crate::item::{DependencyKind, Item, PackageSource};

/// The `[workspace]` table of a Cargo manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceDecl {
    /// `members` globs/paths, exactly as written.
    pub members: Vec<String>,
    /// `default-members` globs/paths, exactly as written.
    pub default_members: Vec<String>,
    /// `exclude` globs/paths, exactly as written.
    pub exclude: Vec<String>,
    /// The scalar string values of `[workspace.package]`, the inheritance source for a
    /// member's `field.workspace = true`.
    ///
    /// Only string-valued keys are captured — `version`, `edition`, `rust-version`,
    /// `license`, and the like. Array-valued keys (`authors`, `keywords`, `categories`)
    /// are omitted, since no consumer of this reader resolves them today.
    pub package_defaults: BTreeMap<String, String>,
}

/// Parse the `[workspace]` table from a `Cargo.toml`, or `None` if the manifest
/// declares no workspace.
#[must_use]
pub fn parse_workspace(content: &str) -> Option<WorkspaceDecl> {
    let doc = ImDocument::parse(content.to_owned()).ok()?;
    let ws = doc
        .as_table()
        .get("workspace")
        .and_then(TomlItem::as_table_like)?;
    Some(WorkspaceDecl {
        members: string_array(ws.get("members")),
        default_members: string_array(ws.get("default-members")),
        exclude: string_array(ws.get("exclude")),
        package_defaults: string_table(ws.get("package")),
    })
}

/// Collect a TOML table's string-valued entries, ignoring every other value type.
fn string_table(item: Option<&TomlItem>) -> BTreeMap<String, String> {
    item.and_then(TomlItem::as_table_like)
        .map(|table| {
            table
                .iter()
                .filter_map(|(key, value)| Some((key.to_owned(), value.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse `[package] name` from a `Cargo.toml`, or `None` for a virtual manifest
/// (a workspace root with no `[package]`).
#[must_use]
pub fn parse_package_name(content: &str) -> Option<String> {
    let doc = ImDocument::parse(content.to_owned()).ok()?;
    doc.as_table()
        .get("package")
        .and_then(TomlItem::as_table_like)?
        .get("name")
        .and_then(TomlItem::as_str)
        .map(str::to_owned)
}

/// Fill in the constraints `items` inherit from a workspace root's
/// `[workspace.dependencies]`, returning the names resolved that way in item order.
///
/// Pure: `declarations` is simply the root manifest's own parsed items — locating and
/// reading that manifest is the IO layer's job (`dependable_fetch::workspace_source`).
/// Only entries with [`DependencyKind::Workspace`] are consulted, so a root that also
/// declares its own `[dependencies]` cannot lend them to its members.
///
/// # Positions are deliberately untouched
/// The version string being adopted lives in a *different file*, so no
/// [`version_line`](Item::version_line) or column in the member manifest is truthful and
/// none is invented. The resolved item keeps [`PackageSource::Inherited`], which is what
/// [`Item::is_rewritable`] reads to keep `--fix` and the location-emitting reporters off
/// a span that means nothing.
///
/// A root declaration that is itself a `path` or `git` entry hands the member
/// [`PackageSource::Local`] / [`PackageSource::Git`]: the member does inherit, but what it
/// inherits has no registry version to check. It is still reported as inherited, because
/// that is where its definition came from.
#[must_use]
pub fn resolve_workspace_inheritance(items: &mut [Item], declarations: &[Item]) -> Vec<String> {
    let mut resolved = Vec::new();
    for item in items {
        // Only an entry that says it inherits, and has nothing of its own to say, can be
        // resolved. A `path` dependency sharing a name with a root declaration is not
        // inheriting — Cargo uses the path — and must not be rewritten here.
        if item.source != PackageSource::Inherited || !item.version_constraint.is_empty() {
            continue;
        }
        let Some(declaration) = declarations
            .iter()
            .find(|d| d.kind == DependencyKind::Workspace && d.name == item.name)
        else {
            continue;
        };
        // A declaration with neither a version nor a path/git source of its own — a root
        // writing `serde = { workspace = true }` into its own table — supplies nothing.
        // Reporting the name as resolved would be a lie, and would leave the item in the
        // exact state this loop re-resolves, so a second pass would report it again.
        if declaration.version_constraint.is_empty()
            && !matches!(
                declaration.source,
                PackageSource::Local | PackageSource::Git
            )
        {
            continue;
        }
        item.version_constraint
            .clone_from(&declaration.version_constraint);
        item.registry.clone_from(&declaration.registry);
        if matches!(
            declaration.source,
            PackageSource::Local | PackageSource::Git
        ) {
            item.source = declaration.source;
        }
        resolved.push(item.name.clone());
    }
    resolved
}

/// Collect a TOML array of strings, ignoring non-string and missing values.
fn string_array(item: Option<&TomlItem>) -> Vec<String> {
    item.and_then(TomlItem::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestKind;
    use crate::parsers::parse;

    /// The `[workspace.dependencies]` entries of a root manifest, as the IO layer
    /// would hand them over.
    fn declarations(root: &str) -> Vec<Item> {
        parse(ManifestKind::CargoToml, root)
            .expect("root parses")
            .items
            .into_iter()
            .filter(|item| item.kind == DependencyKind::Workspace)
            .collect()
    }

    fn member(content: &str) -> Vec<Item> {
        parse(ManifestKind::CargoToml, content)
            .expect("member parses")
            .items
    }

    fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
        items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("no item {name}"))
    }

    #[test]
    fn parses_virtual_workspace_root() {
        let toml = r#"
[workspace]
resolver = "2"
members = ["crates/*", "tools/gen"]
default-members = ["crates/app"]
exclude = ["crates/legacy"]
"#;
        let ws = parse_workspace(toml).unwrap();
        assert_eq!(ws.members, ["crates/*", "tools/gen"]);
        assert_eq!(ws.default_members, ["crates/app"]);
        assert_eq!(ws.exclude, ["crates/legacy"]);
        // Virtual root: no package of its own.
        assert_eq!(parse_package_name(toml), None);
    }

    #[test]
    fn parses_package_name() {
        let toml = r#"
[package]
name = "dependable-core"
version = "0.1.0"
"#;
        assert_eq!(parse_package_name(toml).as_deref(), Some("dependable-core"));
        assert_eq!(parse_workspace(toml), None);
    }

    #[test]
    fn handles_root_that_is_both_package_and_workspace() {
        let toml = r#"
[package]
name = "root-crate"

[workspace]
members = ["sub"]
"#;
        assert_eq!(parse_package_name(toml).as_deref(), Some("root-crate"));
        assert_eq!(parse_workspace(toml).unwrap().members, ["sub"]);
    }

    #[test]
    fn missing_tables_default_empty() {
        let toml = "[workspace]\n";
        let ws = parse_workspace(toml).unwrap();
        assert!(ws.members.is_empty());
        assert!(ws.default_members.is_empty());
        assert!(ws.exclude.is_empty());
        assert!(ws.package_defaults.is_empty());
    }

    #[test]
    fn collects_string_valued_workspace_package_defaults() {
        let toml = r#"
[workspace]
members = ["crates/*"]

[workspace.package]
version = "0.5.0"
edition = "2024"
rust-version = "1.92"
license = "MIT OR Apache-2.0"
authors = ["Someone"]
keywords = ["tui", "editor"]
"#;
        let ws = parse_workspace(toml).unwrap();
        assert_eq!(
            ws.package_defaults.get("version").map(String::as_str),
            Some("0.5.0")
        );
        assert_eq!(
            ws.package_defaults.get("edition").map(String::as_str),
            Some("2024")
        );
        assert_eq!(
            ws.package_defaults.get("rust-version").map(String::as_str),
            Some("1.92")
        );
        assert_eq!(
            ws.package_defaults.get("license").map(String::as_str),
            Some("MIT OR Apache-2.0")
        );
        // Array-valued keys are deliberately omitted.
        assert!(!ws.package_defaults.contains_key("authors"));
        assert!(!ws.package_defaults.contains_key("keywords"));
    }
    #[test]
    fn a_member_inherits_the_roots_constraint_and_registry() {
        let decls = declarations(
            "[workspace.dependencies]\nserde = { version = \"1.0.200\", registry = \"internal\" }\n",
        );
        let mut items =
            member("[dependencies]\nserde = { workspace = true, features = [\"derive\"] }\n");

        let resolved = resolve_workspace_inheritance(&mut items, &decls);

        assert_eq!(resolved, ["serde"]);
        let serde = find(&items, "serde");
        assert_eq!(serde.version_constraint, "1.0.200");
        assert_eq!(serde.registry.as_deref(), Some("internal"));
        assert_eq!(serde.source, PackageSource::Inherited);
        assert!(
            serde.is_checkable(),
            "a resolved constraint is worth asking about"
        );
    }

    /// The version string lives in the root, so the member manifest has no truthful
    /// position for it — and an invented one would be spliced into byte 0 of line 0 by
    /// anything rewriting spans.
    #[test]
    fn inheriting_a_constraint_invents_no_position() {
        let decls = declarations("[workspace.dependencies]\nserde = \"1.0.200\"\n");
        let mut items =
            member("[package]\nname = \"member\"\n\n[dependencies]\nserde.workspace = true\n");

        let _ = resolve_workspace_inheritance(&mut items, &decls);

        let serde = find(&items, "serde");
        assert_eq!(
            (
                serde.version_line,
                serde.version_col_start,
                serde.version_col_end
            ),
            (0, 0, 0)
        );
        assert!(
            !serde.is_rewritable(),
            "nothing in this file may be rewritten"
        );
    }

    /// Cargo resolves a member's `path` entry to the path, whatever the root says about
    /// a crate of the same name. Telling the two apart is why `workspace = true` gets
    /// its own source at parse time.
    #[test]
    fn a_path_dependency_sharing_a_name_is_never_promoted() {
        let decls = declarations("[workspace.dependencies]\nutil = \"1.0.0\"\n");
        let mut items = member("[dependencies]\nutil = { path = \"../util\" }\n");

        let resolved = resolve_workspace_inheritance(&mut items, &decls);

        assert!(resolved.is_empty(), "{resolved:?}");
        let util = find(&items, "util");
        assert_eq!(util.source, PackageSource::Local);
        assert!(util.version_constraint.is_empty());
    }

    #[test]
    fn a_path_or_git_root_declaration_is_inherited_as_such() {
        let decls = declarations(
            "[workspace.dependencies]\nutil = { path = \"crates/util\" }\ngitdep = { git = \"https://example.com/g\" }\n",
        );
        let mut items = member("[dependencies]\nutil.workspace = true\ngitdep.workspace = true\n");

        let resolved = resolve_workspace_inheritance(&mut items, &decls);

        assert_eq!(resolved, ["util", "gitdep"]);
        assert_eq!(find(&items, "util").source, PackageSource::Local);
        assert_eq!(find(&items, "gitdep").source, PackageSource::Git);
        assert!(!find(&items, "util").is_checkable());
        assert!(!find(&items, "gitdep").is_checkable());
    }

    /// A root's own `[dependencies]` are its own business — only the central
    /// declarations are on offer.
    #[test]
    fn only_workspace_kind_declarations_are_consulted() {
        let decls = parse(
            ManifestKind::CargoToml,
            "[dependencies]\nserde = \"1.0.200\"\n",
        )
        .expect("parses")
        .items;
        let mut items = member("[dependencies]\nserde.workspace = true\n");

        assert!(resolve_workspace_inheritance(&mut items, &decls).is_empty());
        assert!(find(&items, "serde").version_constraint.is_empty());
    }

    /// A member can name a crate the root never declared. That is a broken manifest, and
    /// guessing a version for it would be worse than reporting nothing.
    #[test]
    fn an_undeclared_name_stays_unresolved_and_unchecked() {
        let decls = declarations("[workspace.dependencies]\nserde = \"1\"\n");
        let mut items = member("[dependencies]\ntokio.workspace = true\n");

        assert!(resolve_workspace_inheritance(&mut items, &decls).is_empty());
        let tokio = find(&items, "tokio");
        assert_eq!(tokio.source, PackageSource::Inherited);
        assert!(
            !tokio.is_checkable(),
            "no constraint means nothing to ask for"
        );
        assert!(!tokio.is_rewritable());
    }

    /// A root declaring an entry that supplies nothing — `serde = { workspace = true }`
    /// in its own `[workspace.dependencies]` — leaves the member exactly as it was. It
    /// must not be reported as resolved, or the returned names lie and a second pass
    /// reports them again.
    #[test]
    fn a_declaration_that_supplies_nothing_resolves_nothing() {
        let decls = declarations("[workspace.dependencies]\nserde = { workspace = true }\n");
        let mut items = member("[dependencies]\nserde.workspace = true\n");

        assert!(resolve_workspace_inheritance(&mut items, &decls).is_empty());
        assert!(resolve_workspace_inheritance(&mut items, &decls).is_empty());
        assert!(find(&items, "serde").version_constraint.is_empty());
    }

    /// Resolution runs once per manifest, but a second pass must not re-report or
    /// re-copy — the item already states a version of its own.
    #[test]
    fn resolution_is_idempotent() {
        let decls = declarations("[workspace.dependencies]\nserde = \"1.0.200\"\n");
        let mut items = member("[dependencies]\nserde.workspace = true\n");

        assert_eq!(resolve_workspace_inheritance(&mut items, &decls), ["serde"]);
        assert!(resolve_workspace_inheritance(&mut items, &decls).is_empty());
        assert_eq!(find(&items, "serde").version_constraint, "1.0.200");
    }
}
