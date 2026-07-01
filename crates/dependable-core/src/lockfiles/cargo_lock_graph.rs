//! Parser for `Cargo.lock` that preserves the full resolved dependency graph.
//!
//! Unlike [`super::cargo_lock`], which collapses the lockfile to a
//! `name → versions` map for annotating direct dependencies, this parser keeps
//! each package's `source` and `dependencies` edges so the resolved transitive
//! graph can be reconstructed offline (see [`crate::graph`]).

use std::collections::HashMap;

use toml_edit::{ImDocument, Item as TomlItem};

use crate::error::ParseError;

/// A single `[[package]]` entry from `Cargo.lock`, preserving the fields needed
/// to rebuild the resolved dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockedPackage {
    /// Package name.
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Package source (`registry+https://…`, `git+…`, `sparse+…`). `None` for
    /// path/workspace packages — that absence is how local crates are told apart
    /// from external ones.
    pub source: Option<String>,
    /// Resolved dependency references, each a `"name"`, `"name version"`, or
    /// `"name version (source)"` string exactly as Cargo writes them. Resolve
    /// them to package indices with [`ResolvedLockfile::resolve`].
    pub dependencies: Vec<String>,
}

/// A fully parsed `Cargo.lock`: every resolved package plus its edges.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ResolvedLockfile {
    /// All packages, in lockfile order.
    pub packages: Vec<LockedPackage>,
    /// `name → indices into packages`, built once for O(1) edge resolution.
    by_name: HashMap<String, Vec<usize>>,
}

impl ResolvedLockfile {
    /// Resolve a `dependencies` entry to an index into [`Self::packages`].
    ///
    /// Cargo writes the shortest unambiguous form: `"name"` when the name is
    /// unique in the lock, `"name version"` when several versions coexist, and
    /// `"name version (source)"` in the rare multi-source case. Matching on
    /// `(name, version)` disambiguates every realistic lockfile.
    #[must_use]
    pub fn resolve(&self, dep: &str) -> Option<usize> {
        let mut parts = dep.splitn(3, ' ');
        let name = parts.next()?;
        let version = parts.next();
        let candidates = self.by_name.get(name)?;
        match version {
            // Bare name: Cargo only omits the version when the name is unique.
            None => candidates.first().copied(),
            Some(version) => candidates
                .iter()
                .copied()
                .find(|&i| self.packages[i].version == version),
        }
    }
}

/// Parse `Cargo.lock` into a [`ResolvedLockfile`], preserving sources and edges.
pub fn parse_cargo_lock_graph(content: &str) -> Result<ResolvedLockfile, ParseError> {
    let doc = ImDocument::parse(content.to_owned())?;
    let mut packages: Vec<LockedPackage> = Vec::new();
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    if let Some(pkgs) = doc
        .as_table()
        .get("package")
        .and_then(TomlItem::as_array_of_tables)
    {
        for pkg in pkgs.iter() {
            let (Some(name), Some(version)) = (
                pkg.get("name").and_then(TomlItem::as_str),
                pkg.get("version").and_then(TomlItem::as_str),
            ) else {
                continue;
            };
            let source = pkg
                .get("source")
                .and_then(TomlItem::as_str)
                .map(str::to_owned);
            let dependencies = pkg
                .get("dependencies")
                .and_then(TomlItem::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            by_name
                .entry(name.to_owned())
                .or_default()
                .push(packages.len());
            packages.push(LockedPackage {
                name: name.to_owned(),
                version: version.to_owned(),
                source,
                dependencies,
            });
        }
    }
    Ok(ResolvedLockfile { packages, by_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "getrandom 0.2.17",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "getrandom"
version = "0.2.17"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "getrandom"
version = "0.3.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    #[test]
    fn captures_source_and_edges() {
        let lock = parse_cargo_lock_graph(LOCK).unwrap();
        assert_eq!(lock.packages.len(), 4);

        let app = &lock.packages[0];
        assert_eq!(app.name, "app");
        assert_eq!(app.source, None); // local/workspace package: no source
        assert_eq!(app.dependencies, vec!["serde", "getrandom 0.2.17"]);

        let serde = &lock.packages[1];
        assert_eq!(
            serde.source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert!(serde.dependencies.is_empty());
    }

    #[test]
    fn resolves_bare_name_to_unique_package() {
        let lock = parse_cargo_lock_graph(LOCK).unwrap();
        let idx = lock.resolve("serde").unwrap();
        assert_eq!(lock.packages[idx].name, "serde");
    }

    #[test]
    fn resolves_disambiguated_name_and_version() {
        let lock = parse_cargo_lock_graph(LOCK).unwrap();
        let idx = lock.resolve("getrandom 0.2.17").unwrap();
        assert_eq!(lock.packages[idx].version, "0.2.17");
        // The other version is a distinct package, resolvable on its own.
        let other = lock.resolve("getrandom 0.3.4").unwrap();
        assert_eq!(lock.packages[other].version, "0.3.4");
    }

    #[test]
    fn resolves_three_token_source_form() {
        let lock = parse_cargo_lock_graph(LOCK).unwrap();
        let idx = lock
            .resolve("getrandom 0.2.17 (registry+https://github.com/rust-lang/crates.io-index)")
            .unwrap();
        assert_eq!(lock.packages[idx].version, "0.2.17");
    }

    #[test]
    fn unknown_dependency_resolves_to_none() {
        let lock = parse_cargo_lock_graph(LOCK).unwrap();
        assert_eq!(lock.resolve("nonexistent"), None);
        assert_eq!(lock.resolve("getrandom 9.9.9"), None);
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let lock = parse_cargo_lock_graph("version = 4\n").unwrap();
        assert!(lock.packages.is_empty());
    }
}
