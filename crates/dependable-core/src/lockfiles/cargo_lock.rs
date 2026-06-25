//! Parser for `Cargo.lock`, used to show the actually-resolved version.

use std::collections::HashMap;

use toml_edit::{ImDocument, Item as TomlItem};

use crate::error::ParseError;
use crate::item::Item;

/// Locked versions keyed by package name. A package may appear at several
/// versions because of transitive resolution.
#[derive(Debug, Clone, Default)]
pub struct LockfileData {
    pub versions: HashMap<String, Vec<String>>,
}

/// Parse `Cargo.lock` into a name → versions map.
pub fn parse_cargo_lock(content: &str) -> Result<LockfileData, ParseError> {
    let doc = ImDocument::parse(content.to_owned())?;
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(packages) = doc
        .as_table()
        .get("package")
        .and_then(TomlItem::as_array_of_tables)
    {
        for pkg in packages.iter() {
            let name = pkg.get("name").and_then(TomlItem::as_str);
            let version = pkg.get("version").and_then(TomlItem::as_str);
            if let (Some(name), Some(version)) = (name, version) {
                versions
                    .entry(name.to_owned())
                    .or_default()
                    .push(version.to_owned());
            }
        }
    }
    Ok(LockfileData { versions })
}

/// Populate [`Item::locked_version`] from a parsed lockfile.
pub fn apply_lockfile(items: &mut [Item], lock: &LockfileData) {
    for item in items.iter_mut() {
        if let Some(found) = lock.versions.get(&item.name) {
            item.locked_version = pick_locked(found, &item.version_constraint);
        }
    }
}

/// Choose the locked version that best represents a direct dependency: the
/// highest locked version satisfying its declared constraint.
fn pick_locked(versions: &[String], constraint: &str) -> Option<String> {
    if let [only] = versions {
        return Some(only.clone());
    }
    let req = crate::semver::to_version_req(constraint).ok();
    let mut best: Option<::semver::Version> = None;
    for v in versions {
        let Ok(parsed) = ::semver::Version::parse(v) else {
            continue;
        };
        let satisfies = req.as_ref().is_none_or(|r| r.matches(&parsed));
        if satisfies && best.as_ref().is_none_or(|b| parsed > *b) {
            best = Some(parsed);
        }
    }
    best.map(|v| v.to_string())
        .or_else(|| versions.iter().max().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::PackageSource;

    fn item(name: &str, constraint: &str) -> Item {
        Item {
            name: name.to_owned(),
            version_constraint: constraint.to_owned(),
            source: PackageSource::Registry,
            version_line: 0,
            version_col_start: 0,
            version_col_end: 0,
            registry: None,
            locked_version: None,
        }
    }

    #[test]
    fn parses_and_applies_locked_versions() {
        let lock = r#"
[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "serde"
version = "0.9.15"

[[package]]
name = "tokio"
version = "1.38.0"
"#;
        let data = parse_cargo_lock(lock).unwrap();
        let mut items = vec![item("serde", "^1.0"), item("tokio", "1")];
        apply_lockfile(&mut items, &data);
        // serde resolves to the 1.x lock, not the stray 0.9.
        assert_eq!(items[0].locked_version.as_deref(), Some("1.0.200"));
        assert_eq!(items[1].locked_version.as_deref(), Some("1.38.0"));
    }
}
