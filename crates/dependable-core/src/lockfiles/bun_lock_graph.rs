//! Parser for `bun.lock` that preserves the resolved dependency graph.
//!
//! Where [`super::bun_lock`] collapses the lockfile to `name → versions` for
//! annotating direct dependencies, this keeps each entry's edges so the resolved
//! transitive graph can be rebuilt offline (see [`crate::graph`]).
//!
//! Bun keys its `packages` map the way npm keys install paths, but without the
//! `node_modules/` segments: a package installed at the top level is keyed by
//! its bare name, and one installed under another to satisfy a conflicting
//! version is keyed `parent/name`. Edges resolve the same way Node resolves
//! them — look under the dependent first, then under each enclosing scope,
//! ending at the top level.
//!
//! The root project and any workspace members live in a separate `workspaces`
//! object rather than in `packages`, so the root has to be assembled from there.

use std::collections::HashMap;

use crate::error::ParseError;
use crate::lockfiles::bun_lock::split_descriptor;
use crate::lockfiles::cargo_lock_graph::{LockedPackage, ResolvedLockfile};
use crate::parsers::json_scan::scan_strings;

/// The dependency tables whose union forms the graph's edges.
///
/// `peerDependencies` is excluded for the same reason as in the npm parser: a
/// peer is a requirement on the consumer, not something this package installs.
const DEP_TABLES: &[&str] = &["dependencies", "devDependencies", "optionalDependencies"];

/// The registry source recorded for installed packages, so
/// [`crate::graph::DependencyGraph::from_resolved`] classifies them as external.
const NPM_SOURCE: &str = "registry+https://registry.npmjs.org/";

/// One `packages` entry, accumulated across the scan.
#[derive(Default)]
struct Entry {
    /// The `name@version` descriptor at index 0.
    descriptor: Option<String>,
    /// Names declared in this entry's dependency tables.
    deps: Vec<String>,
}

/// One `workspaces` entry: the root project, or a workspace member.
#[derive(Default)]
struct Workspace {
    name: Option<String>,
    version: Option<String>,
    deps: Vec<String>,
}

/// Parse `bun.lock` into a [`ResolvedLockfile`], preserving edges.
///
/// # Errors
/// Never fails: a lockfile that does not parse yields no packages, which callers
/// treat as "no resolved graph" rather than an error that hides the project.
pub fn parse_bun_lock_graph(content: &str) -> Result<ResolvedLockfile, ParseError> {
    let mut entries: HashMap<String, Entry> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut workspaces: HashMap<String, Workspace> = HashMap::new();
    let mut workspace_order: Vec<String> = Vec::new();

    for entry in scan_strings(content) {
        match entry.path.as_slice() {
            [section, key, rest @ ..] if section == "packages" => {
                let slot = entries.entry(key.clone()).or_insert_with(|| {
                    order.push(key.clone());
                    Entry::default()
                });
                match rest {
                    // Index 0 is the descriptor; 1 is the registry, 3 the hash.
                    [index] if index == "0" => slot.descriptor = Some(entry.value),
                    // Index 2 holds the dependency tables.
                    [index, table, dep] if index == "2" && DEP_TABLES.contains(&table.as_str()) => {
                        slot.deps.push(dep.clone());
                    }
                    _ => {}
                }
            }
            [section, key, rest @ ..] if section == "workspaces" => {
                let slot = workspaces.entry(key.clone()).or_insert_with(|| {
                    workspace_order.push(key.clone());
                    Workspace::default()
                });
                match rest {
                    [field] if field == "name" => slot.name = Some(entry.value),
                    [field] if field == "version" => slot.version = Some(entry.value),
                    [table, dep] if DEP_TABLES.contains(&table.as_str()) => {
                        slot.deps.push(dep.clone());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Identity per install key, so an edge can name what it actually resolves to.
    let identity: Vec<(String, String)> = order
        .iter()
        .map(|key| {
            let descriptor = entries[key].descriptor.as_deref().unwrap_or_default();
            match split_descriptor(descriptor) {
                Some((name, version)) => (name.to_owned(), version.to_owned()),
                // A workspace link has no version; its name is still the key's
                // last segment, which is how a dependent refers to it.
                None => (leaf(key).to_owned(), String::new()),
            }
        })
        .collect();

    let index: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, key)| (key.as_str(), i))
        .collect();

    let mut packages: Vec<LockedPackage> = Vec::new();

    // The root first, so the graph has something to render from.
    for key in &workspace_order {
        let workspace = &workspaces[key];
        let name = workspace
            .name
            .clone()
            .unwrap_or_else(|| leaf(key).to_owned());
        let dependencies = workspace
            .deps
            .iter()
            .filter_map(|dep| edge("", dep, &index, &identity))
            .collect();
        packages.push(LockedPackage::new(
            name,
            workspace.version.clone().unwrap_or_default(),
            // A workspace member is local, never fetched from a registry.
            None,
            dependencies,
        ));
    }

    for (i, key) in order.iter().enumerate() {
        let (name, version) = identity[i].clone();
        // Workspace members appear in both objects; the `workspaces` entry is
        // the one carrying the real dependency list, so this one is a duplicate.
        if version.is_empty()
            && workspaces
                .values()
                .any(|w| w.name.as_deref() == Some(&name))
        {
            continue;
        }
        let dependencies = entries[key]
            .deps
            .iter()
            .filter_map(|dep| edge(key, dep, &index, &identity))
            .collect();
        let source = (!version.is_empty()).then(|| NPM_SOURCE.to_owned());
        packages.push(LockedPackage::new(name, version, source, dependencies));
    }

    Ok(ResolvedLockfile::from_packages(packages))
}

/// Resolve one dependency name to a reference the graph can follow.
fn edge(
    from: &str,
    dep: &str,
    index: &HashMap<&str, usize>,
    identity: &[(String, String)],
) -> Option<String> {
    let target = resolve_key(from, dep, index)?;
    let (name, version) = &identity[target];
    Some(match version.is_empty() {
        true => name.clone(),
        false => format!("{name} {version}"),
    })
}

/// Find the `packages` key a dependency resolves to, the way Node resolves it.
///
/// Innermost first: a package installed under the dependent shadows one of the
/// same name higher up, which is the whole reason Bun nests keys at all.
fn resolve_key(from: &str, dep: &str, index: &HashMap<&str, usize>) -> Option<usize> {
    let mut scope = from;
    loop {
        let candidate = if scope.is_empty() {
            dep.to_owned()
        } else {
            format!("{scope}/{dep}")
        };
        if let Some(found) = index.get(candidate.as_str()) {
            return Some(*found);
        }
        if scope.is_empty() {
            return None;
        }
        // Step out one enclosing scope; an unnested key steps straight to the top.
        scope = scope.rsplit_once('/').map_or("", |(head, _)| head);
    }
}

/// The last path segment of an install key.
///
/// A scoped package nests as `parent/@scope/name`, so the name is the last two
/// segments when the second-to-last begins with `@`.
fn leaf(key: &str) -> &str {
    let Some((head, last)) = key.rsplit_once('/') else {
        return key;
    };
    match head.rsplit_once('/') {
        Some((_, scope)) if scope.starts_with('@') => {
            &key[key.len() - scope.len() - last.len() - 1..]
        }
        None if head.starts_with('@') => key,
        _ => last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "version": "1.0.0",
      "dependencies": { "react": "^19.0.0" },
      "devDependencies": { "typescript": "^5.0.0" },
    },
  },
  "packages": {
    "react": ["react@19.0.0", "", { "dependencies": { "scheduler": "^0.25.0" } }, "sha512-a"],
    "scheduler": ["scheduler@0.25.0", "", {}, "sha512-b"],
    "typescript": ["typescript@5.4.0", "", {}, "sha512-c"],
  },
}"#;

    /// `name@version -> [dependency names]`, for readable assertions.
    fn flatten(resolved: &ResolvedLockfile) -> Vec<(String, Vec<String>)> {
        resolved
            .packages
            .iter()
            .map(|p| {
                (
                    format!("{} {}", p.name, p.version).trim().to_owned(),
                    p.dependencies.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn the_root_comes_from_the_workspaces_object() {
        // Bun keeps the project itself out of `packages`, so a parser that only
        // read `packages` would produce a forest with no root to render from.
        let resolved = parse_bun_lock_graph(LOCK).unwrap();
        let root = &resolved.packages[0];
        assert_eq!(root.name, "app");
        assert_eq!(root.version, "1.0.0");
        assert_eq!(root.source, None, "the project is local");
        assert_eq!(
            root.dependencies,
            ["react 19.0.0", "typescript 5.4.0"],
            "dev dependencies are edges too"
        );
    }

    #[test]
    fn the_graph_is_transitive() {
        let resolved = parse_bun_lock_graph(LOCK).unwrap();
        let react = flatten(&resolved)
            .into_iter()
            .find(|(id, _)| id == "react 19.0.0")
            .expect("react");
        assert_eq!(react.1, ["scheduler 0.25.0"]);
    }

    #[test]
    fn an_installed_package_is_marked_as_external() {
        let resolved = parse_bun_lock_graph(LOCK).unwrap();
        let react = resolved
            .packages
            .iter()
            .find(|p| p.name == "react")
            .expect("react");
        assert!(
            react
                .source
                .as_deref()
                .is_some_and(|s| s.contains("registry")),
            "an installed package came from a registry"
        );
    }

    #[test]
    fn a_nested_version_shadows_the_one_above_it() {
        // Bun nests a conflicting version under its dependent, exactly so that
        // dependent resolves to it rather than to the top-level copy.
        const NESTED: &str = r#"{
  "workspaces": { "": { "name": "app", "dependencies": { "a": "^1", "b": "^1" } } },
  "packages": {
    "a": ["a@1.0.0", "", { "dependencies": { "shared": "^2.0.0" } }, "h"],
    "a/shared": ["shared@2.0.0", "", {}, "h"],
    "b": ["b@1.0.0", "", { "dependencies": { "shared": "^1.0.0" } }, "h"],
    "shared": ["shared@1.0.0", "", {}, "h"],
  },
}"#;
        let resolved = parse_bun_lock_graph(NESTED).unwrap();
        let by = |name: &str| {
            resolved
                .packages
                .iter()
                .find(|p| p.name == name && !p.version.is_empty())
                .cloned()
                .unwrap_or_else(|| panic!("missing {name}"))
        };
        assert_eq!(
            by("a").dependencies,
            ["shared 2.0.0"],
            "a resolves to the copy nested under it"
        );
        assert_eq!(
            by("b").dependencies,
            ["shared 1.0.0"],
            "b falls through to the top-level copy"
        );
    }

    #[test]
    fn a_dependency_with_no_entry_is_dropped_rather_than_invented() {
        const MISSING: &str = r#"{
  "workspaces": { "": { "name": "app", "dependencies": { "ghost": "^1" } } },
  "packages": {},
}"#;
        let resolved = parse_bun_lock_graph(MISSING).unwrap();
        assert_eq!(resolved.packages[0].dependencies, [] as [String; 0]);
    }

    #[test]
    fn an_empty_lockfile_is_not_an_error() {
        let resolved = parse_bun_lock_graph("{}").unwrap();
        assert!(resolved.packages.is_empty());
    }

    #[test]
    fn a_scoped_package_keeps_its_scope() {
        const SCOPED: &str = r#"{
  "workspaces": { "": { "name": "app", "dependencies": { "@acme/ui": "^2" } } },
  "packages": { "@acme/ui": ["@acme/ui@2.1.0", "", {}, "h"] },
}"#;
        let resolved = parse_bun_lock_graph(SCOPED).unwrap();
        assert_eq!(resolved.packages[0].dependencies, ["@acme/ui 2.1.0"]);
    }
}
