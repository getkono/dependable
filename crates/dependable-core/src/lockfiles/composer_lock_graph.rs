//! Parser for PHP `composer.lock` that preserves the resolved dependency graph.
//!
//! Unlike [`super::composer_lock`], which collapses the lockfile to a
//! `name → versions` map, this parser keeps each package's `require` table so the
//! resolved transitive graph can be reconstructed offline (see [`crate::graph`]).
//!
//! Composer resolves one version per package, so a bare name is an unambiguous
//! edge reference. Platform requirements (`php`, `ext-*`, …) are constraints on the
//! runtime rather than packages, and are not part of the graph.

use std::collections::HashMap;

use crate::error::ParseError;
use crate::lockfiles::cargo_lock_graph::{LockedPackage, ResolvedLockfile};
use crate::parsers::json_scan::scan_strings;

/// The lockfile arrays holding resolved packages.
const SECTIONS: &[&str] = &["packages", "packages-dev"];

/// The registry source recorded for resolved packages.
const COMPOSER_SOURCE: &str = "registry+https://repo.packagist.org";

/// One array element, accumulated across the scan.
#[derive(Default)]
struct Entry {
    name: Option<String>,
    version: Option<String>,
    requires: Vec<String>,
}

/// Parse `composer.lock` into a [`ResolvedLockfile`], preserving edges.
///
/// Reads the `packages` and `packages-dev` arrays. The leading `v` of a version tag
/// is stripped so it parses as semver, matching [`super::composer_lock`].
///
/// # Errors
/// Never fails: a lockfile that does not parse yields no packages, which callers
/// treat as "no resolved graph" rather than an error that hides the project.
pub fn parse_composer_lock_graph(content: &str) -> Result<ResolvedLockfile, ParseError> {
    let mut entries: HashMap<(String, String), Entry> = HashMap::new();
    let mut order: Vec<(String, String)> = Vec::new();

    for entry in scan_strings(content) {
        let [section, index, rest @ ..] = entry.path.as_slice() else {
            continue;
        };
        if !SECTIONS.contains(&section.as_str()) || rest.is_empty() {
            continue;
        }
        let key = (section.clone(), index.clone());
        let slot = entries.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            Entry::default()
        });
        match rest {
            [field] if field == "name" => slot.name = Some(entry.value),
            [field] if field == "version" => slot.version = Some(entry.value),
            [table, dep] if table == "require" && !is_platform_requirement(dep) => {
                slot.requires.push(dep.clone());
            }
            _ => {}
        }
    }

    let packages: Vec<LockedPackage> = order
        .iter()
        .filter_map(|key| {
            let entry = &entries[key];
            let name = entry.name.clone()?;
            let version = strip_v(entry.version.as_deref().unwrap_or_default());
            Some(LockedPackage::new(
                name,
                version,
                Some(COMPOSER_SOURCE.to_owned()),
                entry.requires.clone(),
            ))
        })
        .collect();

    Ok(ResolvedLockfile::from_packages(packages))
}

/// Whether a `require` key names the runtime rather than a package.
///
/// Composer treats `php`, `hhvm`, `composer*`, and the `ext-`/`lib-` families as
/// **platform** requirements: they are satisfied by the environment and never
/// appear as resolved packages, so they are not graph nodes.
fn is_platform_requirement(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "php"
        || lower == "hhvm"
        || lower.starts_with("php-")
        || lower.starts_with("ext-")
        || lower.starts_with("lib-")
        || lower.starts_with("composer")
}

/// Strip a single leading `v` from a composer version tag (`v2.1.0` → `2.1.0`).
fn strip_v(version: &str) -> String {
    version.strip_prefix('v').unwrap_or(version).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
  "packages": [
    { "name": "monolog/monolog", "version": "2.1.0",
      "require": { "php": ">=7.2", "psr/log": "^1.0", "ext-json": "*" } },
    { "name": "psr/log", "version": "v1.1.4", "require": { "php": ">=5.3.0" } }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "9.5.0",
      "require": { "monolog/monolog": "^2.0" } }
  ]
}"#;

    fn deps_of<'a>(lock: &'a ResolvedLockfile, name: &str) -> Vec<&'a str> {
        let pkg = lock
            .packages
            .iter()
            .find(|p| p.name == name)
            .expect("package present");
        pkg.dependencies
            .iter()
            .filter_map(|d| lock.resolve(d))
            .map(|i| lock.packages[i].name.as_str())
            .collect()
    }

    #[test]
    fn reads_packages_from_both_sections() {
        let resolved = parse_composer_lock_graph(LOCK).unwrap();
        let mut names: Vec<&str> = resolved.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["monolog/monolog", "phpunit/phpunit", "psr/log"]);
    }

    #[test]
    fn keeps_real_edges_and_drops_platform_requirements() {
        let resolved = parse_composer_lock_graph(LOCK).unwrap();
        assert_eq!(
            deps_of(&resolved, "monolog/monolog"),
            vec!["psr/log"],
            "php and ext-json are runtime constraints, not packages"
        );
        assert!(deps_of(&resolved, "psr/log").is_empty());
    }

    #[test]
    fn edges_a_dev_package_to_the_package_it_requires() {
        let resolved = parse_composer_lock_graph(LOCK).unwrap();
        assert_eq!(
            deps_of(&resolved, "phpunit/phpunit"),
            vec!["monolog/monolog"]
        );
    }

    #[test]
    fn strips_a_leading_v_from_the_version_tag() {
        let resolved = parse_composer_lock_graph(LOCK).unwrap();
        let psr = resolved
            .packages
            .iter()
            .find(|p| p.name == "psr/log")
            .expect("psr/log");
        assert_eq!(psr.version, "1.1.4");
    }

    #[test]
    fn treats_every_platform_family_as_a_non_package() {
        for name in [
            "php",
            "PHP",
            "php-64bit",
            "ext-mbstring",
            "lib-curl",
            "composer-plugin-api",
            "composer-runtime-api",
            "hhvm",
        ] {
            assert!(is_platform_requirement(name), "{name} should be platform");
        }
        for name in ["psr/log", "phpunit/phpunit", "league/flysystem"] {
            assert!(!is_platform_requirement(name), "{name} is a real package");
        }
    }

    #[test]
    fn survives_a_lockfile_with_no_packages() {
        let resolved = parse_composer_lock_graph(r#"{"packages": []}"#).unwrap();
        assert!(resolved.packages.is_empty());
    }
}
