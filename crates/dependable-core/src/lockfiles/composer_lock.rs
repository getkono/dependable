//! Parser for PHP `composer.lock`.

use std::collections::HashMap;

use crate::error::ParseError;
use crate::lockfiles::LockfileData;
use crate::parsers::json_scan::scan_strings;

const SECTIONS: &[&str] = &["packages", "packages-dev"];

/// Parse `composer.lock` into a name → resolved-versions map.
///
/// Reads the `packages` and `packages-dev` arrays, each element of which is an
/// object with `name` and `version` fields; the leading `v` of a version tag is
/// stripped so it parses as semver.
pub fn parse_composer_lock(content: &str) -> Result<LockfileData, ParseError> {
    // Collect name/version per array element, keyed by (section, index).
    let mut elements: HashMap<(String, String), (Option<String>, Option<String>)> = HashMap::new();
    for entry in scan_strings(content) {
        if let [section, index, field] = entry.path.as_slice()
            && SECTIONS.contains(&section.as_str())
        {
            let slot = elements
                .entry((section.clone(), index.clone()))
                .or_default();
            match field.as_str() {
                "name" => slot.0 = Some(entry.value),
                "version" => slot.1 = Some(entry.value),
                _ => {}
            }
        }
    }

    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for (name, version) in elements.into_values() {
        if let (Some(name), Some(version)) = (name, version) {
            versions.entry(name).or_default().push(strip_v(&version));
        }
    }
    Ok(LockfileData { versions })
}

/// Strip a single leading `v` from a composer version tag (`v2.1.0` → `2.1.0`).
fn strip_v(version: &str) -> String {
    version.strip_prefix('v').unwrap_or(version).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Item, PackageSource};
    use crate::lockfiles::apply_lockfile;

    #[test]
    fn extracts_versions_from_both_sections() {
        let lock = r#"{
  "packages": [
    { "name": "monolog/monolog", "version": "2.1.0" },
    { "name": "psr/log", "version": "v1.1.4" }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "9.5.0" }
  ]
}"#;
        let data = parse_composer_lock(lock).unwrap();
        assert_eq!(data.versions["monolog/monolog"], vec!["2.1.0"]);
        assert_eq!(data.versions["psr/log"], vec!["1.1.4"]); // leading v stripped
        assert_eq!(data.versions["phpunit/phpunit"], vec!["9.5.0"]);
    }

    #[test]
    fn applies_locked_version() {
        let lock = r#"{ "packages": [ { "name": "monolog/monolog", "version": "2.1.0" } ] }"#;
        let data = parse_composer_lock(lock).unwrap();
        let mut items = vec![Item {
            name: "monolog/monolog".into(),
            version_constraint: "^2.0".into(),
            source: PackageSource::Registry,
            version_line: 0,
            version_col_start: 0,
            version_col_end: 0,
            registry: None,
            locked_version: None,
        }];
        apply_lockfile(&mut items, &data);
        assert_eq!(items[0].locked_version.as_deref(), Some("2.1.0"));
    }
}
