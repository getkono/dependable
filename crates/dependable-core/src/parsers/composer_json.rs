//! Parser for PHP `composer.json`.
//!
//! Reads `require` and `require-dev` via the JSON scanner. Platform packages
//! (`php`, `ext-*`, `lib-*`, `composer-*`) have no `vendor/name` form and are
//! skipped — only real Packagist packages are version-checked.

use super::Parser;
use super::json_scan::scan_strings;
use super::position::{line_starts, offset_to_line_col};
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

const DEP_SECTIONS: &[&str] = &["require", "require-dev"];

/// Parses `composer.json`.
pub struct ComposerJsonParser;

impl Parser for ComposerJsonParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let starts = line_starts(content);
        let mut items = Vec::new();
        for entry in scan_strings(content) {
            if let [section, name] = entry.path.as_slice()
                && DEP_SECTIONS.contains(&section.as_str())
                && is_packagist_package(name)
            {
                let (line, col_start) = offset_to_line_col(&starts, entry.content_start);
                items.push(Item {
                    name: name.clone(),
                    version_constraint: entry.value.clone(),
                    source: PackageSource::Registry,
                    version_line: line,
                    version_col_start: col_start,
                    version_col_end: col_start
                        + entry.content_end.saturating_sub(entry.content_start),
                    registry: None,
                    locked_version: None,
                });
            }
        }
        Ok(ParsedManifest {
            kind: ManifestKind::ComposerJson,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// Whether `name` is a real Packagist package (`vendor/name`) rather than a
/// platform requirement (`php`, `ext-mbstring`, `composer-runtime-api`, …).
fn is_packagist_package(name: &str) -> bool {
    name.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        ComposerJsonParser.parse(content).unwrap()
    }

    fn find<'a>(m: &'a ParsedManifest, name: &str) -> &'a Item {
        m.items
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_require_and_skips_platform_packages() {
        let content = r#"{
  "require": {
    "php": ">=8.1",
    "monolog/monolog": "^2.0",
    "ext-mbstring": "*"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.5"
  }
}"#;
        let m = parse(content);
        assert_eq!(m.items.len(), 2);
        let monolog = find(&m, "monolog/monolog");
        assert_eq!(monolog.version_constraint, "^2.0");
        assert_eq!(sliced(content, monolog), "^2.0");
        assert_eq!(find(&m, "phpunit/phpunit").version_constraint, "^9.5");
    }
}
