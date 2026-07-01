//! Pure readers for Cargo workspace topology: the `[workspace]` table and a
//! manifest's own `[package] name`.
//!
//! Member globs are returned **raw** — glob expansion needs the filesystem and
//! is done in the IO layer ([`dependable_fetch`]). These readers only turn
//! `&str` manifest content into plain data.

use toml_edit::{ImDocument, Item as TomlItem};

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
    })
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
    }
}
