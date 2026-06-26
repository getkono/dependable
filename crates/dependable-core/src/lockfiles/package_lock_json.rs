//! Parser for npm `package-lock.json` (lockfile v2/v3 `packages` map).

use std::collections::HashMap;

use crate::error::ParseError;
use crate::lockfiles::LockfileData;
use crate::parsers::json_scan::scan_strings;

/// Parse `package-lock.json` into a name → resolved-versions map.
///
/// Reads the v2/v3 `packages` object, whose keys are install paths
/// (`node_modules/react`, `node_modules/a/node_modules/b`); the package name is
/// the segment after the last `node_modules/`.
pub fn parse_package_lock(content: &str) -> Result<LockfileData, ParseError> {
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for entry in scan_strings(content) {
        if let [section, key, field] = entry.path.as_slice()
            && section == "packages"
            && field == "version"
            && let Some(name) = package_name(key)
        {
            versions.entry(name).or_default().push(entry.value);
        }
    }
    Ok(LockfileData { versions })
}

/// The package name for a `packages` key, or `None` for the root (`""`) entry.
fn package_name(key: &str) -> Option<String> {
    if !key.contains("node_modules/") {
        return None;
    }
    let name = key.rsplit("node_modules/").next()?;
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Item, PackageSource};
    use crate::lockfiles::apply_lockfile;

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
    fn extracts_versions_and_strips_node_modules() {
        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "root", "version": "1.0.0" },
    "node_modules/react": { "version": "18.2.0" },
    "node_modules/@scope/pkg": { "version": "2.1.0" },
    "node_modules/a/node_modules/b": { "version": "3.0.0" }
  }
}"#;
        let data = parse_package_lock(lock).unwrap();
        assert_eq!(data.versions["react"], vec!["18.2.0"]);
        assert_eq!(data.versions["@scope/pkg"], vec!["2.1.0"]);
        assert_eq!(data.versions["b"], vec!["3.0.0"]);
        // The root entry ("") is not a dependency.
        assert!(!data.versions.contains_key("root"));
    }

    #[test]
    fn applies_locked_version_to_items() {
        let lock = r#"{ "packages": { "node_modules/react": { "version": "18.2.0" } } }"#;
        let data = parse_package_lock(lock).unwrap();
        let mut items = vec![item("react", "^18.0.0")];
        apply_lockfile(&mut items, &data);
        assert_eq!(items[0].locked_version.as_deref(), Some("18.2.0"));
    }
}
