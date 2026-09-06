//! Parser for npm `package-lock.json` that preserves the resolved dependency graph.
//!
//! Unlike [`super::package_lock_json`], which collapses the lockfile to a
//! `name → versions` map for annotating direct dependencies, this parser keeps each
//! entry's install path and declared dependencies so the resolved transitive graph
//! can be reconstructed offline (see [`crate::graph`]).
//!
//! npm's `packages` map is keyed by **install path**, not by package name, because
//! the same package may be installed at several versions under different
//! `node_modules` directories. Edges are therefore resolved the way Node resolves
//! them: look for the dependency in the dependent's own `node_modules`, then in each
//! enclosing one, ending at the top level.

use std::collections::HashMap;

use crate::error::ParseError;
use crate::lockfiles::cargo_lock_graph::{LockedPackage, ResolvedLockfile};
use crate::parsers::json_scan::scan_strings;

/// The dependency tables whose union forms the graph's edges.
///
/// `peerDependencies` is deliberately excluded: a peer is a requirement on the
/// *consumer*, not something this package causes to be installed.
const DEP_TABLES: &[&str] = &["dependencies", "devDependencies", "optionalDependencies"];

/// The registry source recorded for installed packages, so
/// [`crate::graph::DependencyGraph::from_resolved`] classifies them as external.
const NPM_SOURCE: &str = "registry+https://registry.npmjs.org/";

/// One `packages` entry, accumulated across the scan.
#[derive(Default)]
struct Entry {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    deps: Vec<String>,
}

/// Parse `package-lock.json` into a [`ResolvedLockfile`], preserving edges.
///
/// Reads the lockfile v2/v3 `packages` object. The root project is the `""` entry;
/// entries whose key contains `node_modules/` are installed packages, and any other
/// key is a local workspace package.
///
/// # Errors
/// Returns [`ParseError::Structural`] for a lockfile v1 (npm 6) document, whose graph
/// lives under a top-level `dependencies` tree this parser does not read. Returning an
/// empty graph for one made "this format is not supported" indistinguishable from "this
/// project has no dependencies"; the caller reports the former and falls back.
pub fn parse_package_lock_graph(content: &str) -> Result<ResolvedLockfile, ParseError> {
    let mut entries: HashMap<String, Entry> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    // A v1 lockfile records resolved versions under `dependencies.<name>.version`; v2/v3
    // keep that tree too, but always alongside a `packages` object.
    let mut legacy_versions = false;

    for entry in scan_strings(content) {
        let Some((section, _key, rest)) = split_path(&entry.path) else {
            continue;
        };
        if section == "dependencies" && matches!(rest, [field] if field == "version") {
            legacy_versions = true;
        }
        let Some(("packages", key, rest)) = split_path(&entry.path) else {
            continue;
        };
        let slot = entries.entry(key.to_owned()).or_insert_with(|| {
            order.push(key.to_owned());
            Entry::default()
        });
        match rest {
            [field] => match field.as_str() {
                "name" => slot.name = Some(entry.value),
                "version" => slot.version = Some(entry.value),
                "resolved" => slot.resolved = Some(entry.value),
                _ => {}
            },
            [table, dep] if DEP_TABLES.contains(&table.as_str()) => slot.deps.push(dep.clone()),
            _ => {}
        }
    }

    if order.is_empty() && legacy_versions {
        return Err(ParseError::Structural(
            "package-lock.json lockfileVersion 1 has no `packages` map;              run `npm install` with npm 7 or newer to upgrade it"
                .to_owned(),
        ));
    }

    // Index install paths before resolving, so edges can be looked up in one pass.
    let index: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, key)| (key.as_str(), i))
        .collect();

    // Resolve identity first: an aliased install (`"node_modules/alias": {"name":
    // "real"}`) is edged by the name it actually resolves to, not the alias.
    let identity: Vec<(String, String)> = order
        .iter()
        .map(|key| {
            let entry = &entries[key];
            (
                entry
                    .name
                    .clone()
                    .or_else(|| package_name(key))
                    .unwrap_or_default(),
                entry.version.clone().unwrap_or_default(),
            )
        })
        .collect();

    let packages: Vec<LockedPackage> = order
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let entry = &entries[key];
            let (name, version) = identity[i].clone();
            let dependencies = entry
                .deps
                .iter()
                .filter_map(|dep| {
                    let target = resolve_install_path(key, dep, &index)?;
                    let target = follow_link(target, &order, &entries, &index);
                    let (target_name, target_version) = &identity[target];
                    Some(reference(target_name, Some(target_version.as_str())))
                })
                .collect();
            LockedPackage::new(name, version, source_of(key, entry), dependencies)
        })
        .collect();

    Ok(ResolvedLockfile::from_packages(packages))
}

/// Split a scanned path into `(section, key, remainder)`.
fn split_path(path: &[String]) -> Option<(&str, &str, &[String])> {
    match path {
        [section, key, rest @ ..] if !rest.is_empty() => Some((section.as_str(), key, rest)),
        _ => None,
    }
}

/// A dependency reference in the form [`ResolvedLockfile::resolve`] understands:
/// `"name version"` when the version is known, and a bare `"name"` when it is not
/// (a workspace link records no version of its own).
fn reference(name: &str, version: Option<&str>) -> String {
    match version.filter(|v| !v.is_empty()) {
        Some(version) => format!("{name} {version}"),
        None => name.to_owned(),
    }
}

/// The package source for an install path, mirroring how npm records it.
fn source_of(key: &str, entry: &Entry) -> Option<String> {
    if let Some(resolved) = entry.resolved.as_deref()
        && (resolved.starts_with("git+") || resolved.starts_with("git:"))
    {
        return Some(resolved.to_owned());
    }
    // A workspace link stub lives under `node_modules/` but is the member, not an
    // install from the registry; calling it one puts a versionless npm package in the
    // graph beside the real member.
    if is_link_stub(key, entry) {
        return None;
    }
    // The root ("") and workspace packages ("packages/app") are local.
    key.contains("node_modules/").then(|| NPM_SOURCE.to_owned())
}

/// Whether this entry is npm's `node_modules/<name>` stub for a workspace member.
///
/// npm records a member twice: the stub, whose `resolved` is the member's path in the
/// repository and which carries no version of its own, and the member itself under that
/// path. `link: true` marks it, but the scan yields only string values and that is a
/// boolean — a relative `resolved` with no version identifies the same thing.
fn is_link_stub(key: &str, entry: &Entry) -> bool {
    if !key.contains("node_modules/") || entry.version.is_some() {
        return false;
    }
    entry.resolved.as_deref().is_some_and(|resolved| {
        !resolved.contains("://") && !resolved.starts_with("git+") && !resolved.is_empty()
    })
}

/// Resolve a link stub to the workspace member it points at.
///
/// The stub declares no dependencies, so an edge that stops there severs the member's
/// entire subtree from the graph — and because the stub has no version, the edge was
/// emitted as a bare name, which resolves to whichever candidate came first in document
/// order. That is the stub, every time: npm writes `node_modules/*` before `packages/*`.
fn follow_link(
    i: usize,
    order: &[String],
    entries: &HashMap<String, Entry>,
    index: &HashMap<&str, usize>,
) -> usize {
    let key = &order[i];
    let Some(entry) = entries.get(key) else {
        return i;
    };
    if !is_link_stub(key, entry) {
        return i;
    }
    let Some(resolved) = entry.resolved.as_deref() else {
        return i;
    };
    let path = resolved.trim_start_matches("./");
    index.get(path).copied().unwrap_or(i)
}

/// The package name implied by a `packages` key, for entries that declare none.
fn package_name(key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let name = match key.rsplit_once("node_modules/") {
        Some((_, name)) => name,
        None => key.rsplit('/').next()?,
    };
    (!name.is_empty()).then(|| name.to_owned())
}

/// Resolve `dep`, required by the package installed at `from`, to an install path.
///
/// Node looks in the dependent's own `node_modules` first, then in each enclosing
/// one, ending at the top level — so a nested copy shadows the hoisted one, exactly
/// as it does at runtime.
fn resolve_install_path(from: &str, dep: &str, index: &HashMap<&str, usize>) -> Option<usize> {
    let mut scope = from.to_owned();
    loop {
        let candidate = if scope.is_empty() {
            format!("node_modules/{dep}")
        } else {
            format!("{scope}/node_modules/{dep}")
        };
        if let Some(&i) = index.get(candidate.as_str()) {
            return Some(i);
        }
        if scope.is_empty() {
            return None;
        }
        // Step out of the innermost `node_modules` and look again. A workspace
        // package (no `node_modules` in its path) falls straight back to the root.
        match scope.rfind("node_modules/") {
            Some(pos) => {
                scope.truncate(pos);
                while scope.ends_with('/') {
                    scope.pop();
                }
            }
            None => scope.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `name -> the names it depends on`, resolved through the lockfile.
    fn edges(lock: &ResolvedLockfile) -> HashMap<&str, Vec<&str>> {
        lock.packages
            .iter()
            .map(|p| {
                let mut deps: Vec<&str> = p
                    .dependencies
                    .iter()
                    .filter_map(|d| lock.resolve(d))
                    .map(|i| lock.packages[i].name.as_str())
                    .collect();
                deps.sort_unstable();
                (p.name.as_str(), deps)
            })
            .collect()
    }

    #[test]
    fn reads_the_root_project_and_its_direct_dependencies() {
        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "react": "^18.0.0" },
          "devDependencies": { "typescript": "^5.0.0" } },
    "node_modules/react": { "version": "18.2.0" },
    "node_modules/typescript": { "version": "5.4.2" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        let edges = edges(&resolved);
        assert_eq!(
            edges["app"],
            vec!["react", "typescript"],
            "dev deps included"
        );
    }

    #[test]
    fn a_nested_copy_shadows_the_hoisted_one() {
        // `b` exists at two versions: hoisted 2.0.0, and 1.0.0 nested under `a`.
        // `a` must edge to its own nested copy, the root to the hoisted one.
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0",
          "dependencies": { "a": "^1.0.0", "b": "^2.0.0" } },
    "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "^1.0.0" } },
    "node_modules/a/node_modules/b": { "version": "1.0.0" },
    "node_modules/b": { "version": "2.0.0" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();

        let a = resolved
            .packages
            .iter()
            .find(|p| p.name == "a")
            .expect("a is present");
        assert_eq!(
            a.dependencies,
            vec!["b 1.0.0"],
            "a resolves to its nested b"
        );

        let root = &resolved.packages[0];
        assert!(
            root.dependencies.contains(&"b 2.0.0".to_owned()),
            "the root resolves to the hoisted b: {:?}",
            root.dependencies
        );
    }

    #[test]
    fn walks_out_to_an_enclosing_node_modules() {
        // `b` is nested under `a` and depends on `c`, which exists only at top level.
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "a": "^1.0.0" } },
    "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "^1.0.0" } },
    "node_modules/a/node_modules/b": { "version": "1.0.0",
                                       "dependencies": { "c": "^1.0.0" } },
    "node_modules/c": { "version": "3.0.0" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        assert_eq!(edges(&resolved)["b"], vec!["c"]);
    }

    #[test]
    fn keeps_scoped_names_intact() {
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0",
          "dependencies": { "@scope/pkg": "^2.0.0" } },
    "node_modules/@scope/pkg": { "version": "2.1.0" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        assert_eq!(edges(&resolved)["app"], vec!["@scope/pkg"]);
    }

    #[test]
    fn edges_an_alias_to_the_package_it_resolves_to() {
        // `npm:` aliases install a differently-named package under the alias path.
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "alias": "npm:real@^1" } },
    "node_modules/alias": { "name": "real", "version": "1.2.3" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        assert_eq!(edges(&resolved)["app"], vec!["real"]);
    }

    #[test]
    fn classifies_installed_packages_as_external_and_the_root_as_local() {
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/react": { "version": "18.2.0" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        assert_eq!(resolved.packages[0].source, None, "root is local");
        assert_eq!(
            resolved.packages[1].source.as_deref(),
            Some(NPM_SOURCE),
            "installed packages carry a registry source"
        );
    }

    #[test]
    fn records_a_git_install_as_a_git_source() {
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "forked": "*" } },
    "node_modules/forked": { "version": "1.0.0",
                             "resolved": "git+https://example.com/forked.git#abc" }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        assert!(
            resolved.packages[1]
                .source
                .as_deref()
                .is_some_and(|s| s.starts_with("git+")),
            "a git install must not look like a registry package"
        );
    }

    #[test]
    fn drops_a_dependency_that_was_never_installed() {
        // An unmet optional dependency has no entry; it must not become a dangling edge.
        let lock = r#"{
  "packages": {
    "": { "name": "app", "version": "1.0.0",
          "optionalDependencies": { "fsevents": "^2.0.0" } }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).unwrap();
        assert!(resolved.packages[0].dependencies.is_empty());
    }

    #[test]
    fn survives_a_lockfile_with_no_packages_map() {
        let resolved = parse_package_lock_graph(r#"{"lockfileVersion": 1}"#).unwrap();
        assert!(resolved.packages.is_empty());
    }

    /// A v1 lockfile keeps its graph somewhere this parser does not read. Reporting an
    /// empty graph made "unsupported format" look exactly like "no dependencies", so the
    /// caller had nothing to tell the user and nothing to fall back from.
    #[test]
    fn a_v1_lockfile_is_reported_as_unsupported() {
        let lock = r#"{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": { "version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" }
  }
}"#;
        assert!(parse_package_lock_graph(lock).is_err());
    }

    /// npm writes a workspace member twice: a versionless stub under `node_modules/` and
    /// the member itself. Edges used to stop at the stub — which has no dependencies —
    /// so the member's whole subtree vanished from the graph.
    #[test]
    fn a_workspace_link_stub_resolves_to_the_member() {
        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "root", "version": "1.0.0", "dependencies": { "app": "*" } },
    "node_modules/app": { "resolved": "packages/app", "link": true },
    "node_modules/lodash": { "version": "4.17.21" },
    "packages/app": { "name": "app", "version": "2.0.0", "dependencies": { "lodash": "^4.0.0" } }
  }
}"#;
        let resolved = parse_package_lock_graph(lock).expect("v3 lockfile");
        let root = resolved
            .packages
            .iter()
            .find(|p| p.name == "root")
            .expect("root");
        // The root's edge must reach the member at its real version, not the stub.
        assert_eq!(root.dependencies, vec!["app 2.0.0".to_string()]);

        let app = resolved
            .packages
            .iter()
            .find(|p| p.name == "app" && p.version == "2.0.0")
            .expect("member");
        assert_eq!(app.dependencies, vec!["lodash 4.17.21".to_string()]);
    }
}
