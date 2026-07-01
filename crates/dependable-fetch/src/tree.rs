//! Build a workspace dependency graph from files on disk.
//!
//! This is the thin, **synchronous** filesystem glue between the pure core
//! ([`dependable_core::graph`]) and the CLI: it locates the workspace root,
//! collects member crate names, reads `Cargo.lock`, and hands the content to the
//! pure graph assembler. No network and no async are involved — the resolved
//! graph already lives in `Cargo.lock`.
//!
//! When no `Cargo.lock` is present it degrades to a **shallow** graph built from
//! the manifests alone (members plus their direct declared dependencies, with
//! versions left unresolved), flagged via [`GraphSource::Manifests`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use dependable_core::{
    CargoTomlParser, DependencyGraph, LockedPackage, ManifestKind, PackageSource, ParseError,
    Parser, ResolvedLockfile, parse_cargo_lock_graph, parse_package_name, parse_workspace,
};
use thiserror::Error;

/// Directories never descended into while collecting member manifests.
const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "vendor"];

/// Where a workspace graph's edges came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphSource {
    /// The full resolved transitive graph, read from `Cargo.lock`.
    Lockfile,
    /// A shallow graph from manifests only — no `Cargo.lock` was found, so this
    /// is members plus their *direct* declared dependencies, versions
    /// unresolved.
    Manifests,
}

/// The result of [`build_workspace_graph`]: the graph plus how it was built.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WorkspaceGraph {
    /// The assembled dependency graph.
    pub graph: DependencyGraph,
    /// Whether the graph is the full resolved one or the shallow fallback.
    pub source: GraphSource,
}

/// Options for [`build_workspace_graph`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WorkspaceGraphOptions {
    /// Restrict the roots to a single crate (`-p`). `None` = all members.
    pub package: Option<String>,
}

/// An error while building a workspace graph.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TreeError {
    /// No `Cargo.toml` was found at or above the given path.
    #[error("no Cargo.toml found at or above {0}")]
    NoManifest(PathBuf),
    /// A file could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// A manifest or lockfile failed to parse.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// Build a dependency graph for the workspace containing `root`.
///
/// Walks up from `root` to the workspace root (the nearest ancestor `Cargo.toml`
/// with a `[workspace]` table, else the nearest package), collects member crate
/// names, and assembles the graph from `Cargo.lock` when present or from the
/// manifests otherwise.
///
/// # Errors
/// Returns [`TreeError::NoManifest`] if no `Cargo.toml` is found, [`TreeError::Io`]
/// on a read failure, or [`TreeError::Parse`] on a malformed lockfile.
pub fn build_workspace_graph(
    root: &Path,
    opts: &WorkspaceGraphOptions,
) -> Result<WorkspaceGraph, TreeError> {
    let start = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let root_dir = locate_root(&start)?;
    let root_content = read(&root_dir.join("Cargo.toml"))?;

    let excluded = excluded_dirs(&root_dir, &root_content);
    let members = collect_members(&root_dir, &excluded);
    let workspace_names: HashSet<String> = members.iter().map(|(name, _)| name.clone()).collect();

    let roots: Vec<String> = match &opts.package {
        Some(pkg) => vec![pkg.clone()],
        None => {
            let mut names: Vec<String> = workspace_names.iter().cloned().collect();
            names.sort();
            names
        }
    };

    // Prefer the resolved lockfile; fall back to a shallow manifest-only graph.
    let lock_name = ManifestKind::CargoToml
        .lockfile_name()
        .unwrap_or("Cargo.lock");
    if let Ok(lock_content) = std::fs::read_to_string(root_dir.join(lock_name)) {
        let resolved = parse_cargo_lock_graph(&lock_content)?;
        let graph = DependencyGraph::from_resolved(&resolved, &workspace_names, &roots);
        return Ok(WorkspaceGraph {
            graph,
            source: GraphSource::Lockfile,
        });
    }

    let graph = shallow_graph(&members, &workspace_names, &roots);
    Ok(WorkspaceGraph {
        graph,
        source: GraphSource::Manifests,
    })
}

/// Walk up from `start` to the workspace root directory: the nearest ancestor
/// with a `[workspace]` `Cargo.toml`, else the nearest ancestor with any
/// `Cargo.toml` (a standalone crate).
fn locate_root(start: &Path) -> Result<PathBuf, TreeError> {
    let mut nearest: Option<PathBuf> = None;
    for dir in start.ancestors() {
        let Ok(content) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        if parse_workspace(&content).is_some() {
            return Ok(dir.to_path_buf());
        }
        if nearest.is_none() {
            nearest = Some(dir.to_path_buf());
        }
    }
    nearest.ok_or_else(|| TreeError::NoManifest(start.to_path_buf()))
}

/// The absolute directories named in the root's `[workspace] exclude`.
fn excluded_dirs(root_dir: &Path, root_content: &str) -> HashSet<PathBuf> {
    parse_workspace(root_content)
        .map(|ws| ws.exclude.iter().map(|rel| root_dir.join(rel)).collect())
        .unwrap_or_default()
}

/// Collect `(package name, manifest content)` for every crate under `root_dir`,
/// deduplicated by name. A crate is treated as in-workspace iff its
/// `[package] name` appears here — this sidesteps needing a glob engine.
fn collect_members(root_dir: &Path, excluded: &HashSet<PathBuf>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk_members(root_dir, excluded, &mut seen, &mut out, 64);
    out
}

fn walk_members(
    dir: &Path,
    excluded: &HashSet<PathBuf>,
    seen: &mut HashSet<String>,
    out: &mut Vec<(String, String)>,
    depth_left: usize,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth_left == 0 || excluded.contains(&path) {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (SKIP_DIRS.contains(&name) || name.starts_with('.'))
            {
                continue;
            }
            walk_members(&path, excluded, seen, out, depth_left - 1);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml")
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Some(name) = parse_package_name(&content)
            && seen.insert(name.clone())
        {
            out.push((name, content));
        }
    }
}

/// Build a shallow graph from member manifests when there is no `Cargo.lock`:
/// each member plus its direct declared dependencies, versions unresolved.
fn shallow_graph(
    members: &[(String, String)],
    workspace_names: &HashSet<String>,
    roots: &[String],
) -> DependencyGraph {
    let mut member_pkgs: Vec<LockedPackage> = Vec::new();
    let mut external_pkgs: Vec<LockedPackage> = Vec::new();
    let mut external_seen: HashSet<String> = HashSet::new();

    for (name, content) in members {
        let items = CargoTomlParser
            .parse(content)
            .map(|m| m.items)
            .unwrap_or_default();
        let mut deps: Vec<String> = Vec::new();
        for item in &items {
            deps.push(item.name.clone());
            if !workspace_names.contains(&item.name) && external_seen.insert(item.name.clone()) {
                // Synthesize a source so classification matches the item's kind.
                let source = match item.source {
                    PackageSource::Git => Some("git+".to_owned()),
                    PackageSource::Local => None,
                    _ => Some("registry+".to_owned()),
                };
                external_pkgs.push(LockedPackage::new(
                    item.name.clone(),
                    String::new(),
                    source,
                    Vec::new(),
                ));
            }
        }
        deps.sort();
        deps.dedup();
        member_pkgs.push(LockedPackage::new(name.clone(), String::new(), None, deps));
    }

    member_pkgs.append(&mut external_pkgs);
    let resolved = ResolvedLockfile::from_packages(member_pkgs);
    DependencyGraph::from_resolved(&resolved, workspace_names, roots)
}

/// Read a file, mapping IO errors to [`TreeError::Io`] with the path attached.
fn read(path: &Path) -> Result<String, TreeError> {
    std::fs::read_to_string(path).map_err(|source| TreeError::Io {
        path: path.to_path_buf(),
        source,
    })
}
