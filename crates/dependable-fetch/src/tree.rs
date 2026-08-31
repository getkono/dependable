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
    CargoTomlParser, DependencyGraph, LockedPackage, LockfileKind, ManifestKind, PackageSource,
    ParseError, Parser, ResolvedLockfile, parse, parse_bun_lock_graph, parse_cargo_lock_graph,
    parse_composer_lock_graph, parse_mix_lock_graph, parse_package_lock_graph, parse_package_name,
    parse_project, parse_workspace,
};
use thiserror::Error;

/// Directories never descended into while collecting member manifests.
const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "vendor"];

/// Where a workspace graph's edges came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GraphSource {
    /// The full resolved transitive graph, read from the ecosystem's lockfile.
    Lockfile,
    /// A shallow graph from manifests only — no lockfile was found, so this is
    /// members plus their *direct* declared dependencies, versions unresolved.
    Manifests,
    /// A shallow graph because the ecosystem's lockfile **cannot** express edges.
    ///
    /// `pubspec.lock` and `go.sum` record resolved versions but not which package
    /// required which, so no transitive graph exists to read offline. This is
    /// distinct from [`Self::Manifests`], where a lockfile would have helped and
    /// simply was not there.
    Unsupported,
    /// A shallow graph because the lockfile that *is* there could not be used.
    ///
    /// Bun's binary `bun.lockb`, or a file that would not parse. Distinct from
    /// [`Self::Manifests`] because the user has something to act on: telling
    /// them no lockfile was found, when one is sitting beside the manifest, is
    /// worse than telling them nothing.
    UnreadableLockfile,
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
        .lockfiles()
        .first()
        .map_or("Cargo.lock", |lockfile| lockfile.file_name());
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
                // Synthesize a source so classification matches the item's kind. Only
                // `path` is genuinely local: a `workspace = true` entry names a crate
                // the root declares, which nothing here reads, so it classifies on the
                // common case (a registry crate) rather than as the path entry it is not.
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

/// Build a dependency graph for the project declared by `manifest`.
///
/// This is the ecosystem-aware entry point. A `Cargo.toml` is delegated to
/// [`build_workspace_graph`], which understands Cargo workspaces. Ecosystems whose
/// lockfile records edges — npm, Composer, Mix — get their full resolved transitive
/// graph. Everything else gets the project plus its *direct* declared dependencies,
/// reported as [`GraphSource::Unsupported`] so a caller can say why rather than
/// implying the packages have no dependencies of their own.
///
/// # Errors
/// Returns [`TreeError::NoManifest`] if `manifest` is not a recognized manifest,
/// [`TreeError::Io`] if it cannot be read, or [`TreeError::Parse`] if it or its
/// lockfile is malformed.
pub fn build_project_graph(
    manifest: &Path,
    opts: &WorkspaceGraphOptions,
) -> Result<WorkspaceGraph, TreeError> {
    let kind = ManifestKind::detect(manifest)
        .ok_or_else(|| TreeError::NoManifest(manifest.to_path_buf()))?;
    if kind == ManifestKind::CargoToml {
        let dir = manifest.parent().unwrap_or(Path::new("."));
        return build_workspace_graph(dir, opts);
    }

    let content = read(manifest)?;
    let meta = parse_project(kind, &content);
    let root_name = meta
        .name
        .clone()
        .or_else(|| project_name_from_path(manifest))
        .unwrap_or_else(|| kind.ecosystem().display_name().to_owned());
    let root_version = meta.literal_version().unwrap_or_default().to_owned();

    // The project's own declared dependencies, used as the root's edges whenever the
    // lockfile carries no entry for the project itself.
    let direct: Vec<String> = parse(kind, &content)
        .map(|parsed| parsed.items.into_iter().map(|i| i.name).collect())
        .unwrap_or_default();

    let workspace_names: HashSet<String> = std::iter::once(root_name.clone()).collect();
    let roots: Vec<String> = match &opts.package {
        Some(pkg) => vec![pkg.clone()],
        None => vec![root_name.clone()],
    };

    if !has_graph_parser(kind) {
        let graph = direct_graph(&root_name, &root_version, &direct, &workspace_names, &roots);
        return Ok(WorkspaceGraph {
            graph,
            source: GraphSource::Unsupported,
        });
    }

    let Some((lock_path, lock_kind)) = crate::discover::locate_lockfile(manifest, kind) else {
        let graph = direct_graph(&root_name, &root_version, &direct, &workspace_names, &roots);
        // Distinguish "there is none" from "there is one we cannot use".
        let source = if crate::discover::lockfile_notices(manifest, kind).is_empty() {
            GraphSource::Manifests
        } else {
            GraphSource::UnreadableLockfile
        };
        return Ok(WorkspaceGraph { graph, source });
    };

    // The manifest has *a* format we can read edges from, but the one actually
    // on disk may not be it.
    let Some(parser) = graph_parser(lock_kind) else {
        let graph = direct_graph(&root_name, &root_version, &direct, &workspace_names, &roots);
        return Ok(WorkspaceGraph {
            graph,
            source: GraphSource::Unsupported,
        });
    };

    let resolved = parser(&read(&lock_path)?)?;
    let resolved = with_root(resolved, &root_name, &root_version, direct);
    Ok(WorkspaceGraph {
        graph: DependencyGraph::from_resolved(&resolved, &workspace_names, &roots),
        source: GraphSource::Lockfile,
    })
}

/// A lockfile parser that preserves dependency edges.
type GraphParser = fn(&str) -> Result<ResolvedLockfile, ParseError>;

/// The graph-preserving parser for a lockfile, or `None` when that format
/// cannot express edges (Dart's `pubspec.lock`) or has no parser yet.
///
/// Keyed on the lockfile rather than the manifest: two lockfiles for the same
/// ecosystem are different formats and need different parsers.
fn graph_parser(kind: LockfileKind) -> Option<GraphParser> {
    match kind {
        LockfileKind::PackageLockJson => Some(parse_package_lock_graph),
        LockfileKind::BunLock => Some(parse_bun_lock_graph),
        LockfileKind::ComposerLock => Some(parse_composer_lock_graph),
        LockfileKind::MixLock => Some(parse_mix_lock_graph),
        _ => None,
    }
}

/// Whether any lockfile this manifest kind may have can express edges.
///
/// Asked before looking on disk so that an ecosystem which could never produce
/// a resolved graph says so, rather than reporting the lockfile as missing.
fn has_graph_parser(kind: ManifestKind) -> bool {
    kind.lockfiles()
        .iter()
        .any(|lockfile| graph_parser(*lockfile).is_some())
}

/// Ensure the project itself is a node, so the graph has a root to render from.
///
/// npm records the root as the `""` entry, so it is already present; Composer and
/// Mix lockfiles describe only dependencies, so the root is synthesized from what
/// the manifest declares.
fn with_root(
    mut resolved: ResolvedLockfile,
    root_name: &str,
    root_version: &str,
    direct: Vec<String>,
) -> ResolvedLockfile {
    if let Some(existing) = resolved
        .packages
        .iter_mut()
        .find(|p| p.name == root_name && p.source.is_none())
    {
        // A lockfile may name the project without recording what it depends on
        // (npm writes the `""` entry either way). Its manifest still says, and a
        // root with no edges would render as a project with no dependencies.
        if existing.dependencies.is_empty() && !direct.is_empty() {
            existing.dependencies = direct;
        }
        return resolved;
    }
    let mut packages = vec![LockedPackage::new(
        root_name.to_owned(),
        root_version.to_owned(),
        None,
        direct,
    )];
    packages.extend(resolved.packages);
    ResolvedLockfile::from_packages(packages)
}

/// A two-level graph: the project and the dependencies it declares, versions
/// unresolved. Used when no resolved graph is available.
fn direct_graph(
    root_name: &str,
    root_version: &str,
    direct: &[String],
    workspace_names: &HashSet<String>,
    roots: &[String],
) -> DependencyGraph {
    let mut packages = vec![LockedPackage::new(
        root_name.to_owned(),
        root_version.to_owned(),
        None,
        direct.to_vec(),
    )];
    let mut seen: HashSet<&str> = HashSet::new();
    for name in direct {
        if name != root_name && seen.insert(name.as_str()) {
            packages.push(LockedPackage::new(
                name.clone(),
                String::new(),
                Some("registry+".to_owned()),
                Vec::new(),
            ));
        }
    }
    let resolved = ResolvedLockfile::from_packages(packages);
    DependencyGraph::from_resolved(&resolved, workspace_names, roots)
}

/// A project name inferred from its manifest's directory, for manifests that
/// declare none (`requirements.txt`, a `*.csproj` named by its file).
fn project_name_from_path(manifest: &Path) -> Option<String> {
    if manifest.extension().is_some_and(|e| e == "csproj") {
        return manifest
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_owned);
    }
    manifest
        .parent()?
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
}
