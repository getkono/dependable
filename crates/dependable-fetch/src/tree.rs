//! Build a workspace dependency graph from files on disk.
//!
//! This is the thin, **synchronous** filesystem glue between the pure core
//! ([`dependable_core::graph`]) and the CLI: it locates the workspace root,
//! collects member crate names, reads `Cargo.lock`, and hands the content to the
//! pure graph assembler. No network and no async are involved — the resolved
//! graph already lives in `Cargo.lock`.
//!
//! When no `Cargo.lock` is present it degrades to a **shallow** graph built from
//! the manifests alone (members plus their direct declared dependencies), flagged
//! via [`GraphSource::Manifests`]. Such a dependency's version is normally unknown
//! — a manifest declares a constraint, not a resolution — except where the
//! constraint names exactly one release, which [`declared_pin`] reads off it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use dependable_core::{
    CargoTomlParser, DependencyGraph, DependencyKind, Ecosystem, Item, LockedPackage, LockfileKind,
    ManifestKind, PackageSource, ParseError, Parser, ResolvedLockfile, exact_pin, parse,
    parse_bun_lock_graph, parse_cargo_lock_graph, parse_composer_lock_graph, parse_mix_lock_graph,
    parse_package_lock_graph, parse_package_name, parse_project, parse_workspace,
    resolve_workspace_inheritance,
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
    let (members, scopes) = collect_members(&root_dir, &root_content, &excluded);
    let workspace_names: HashSet<String> =
        members.iter().map(|member| member.name.clone()).collect();

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

    let graph = shallow_graph(&members, &workspace_names, &roots, &scopes);
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

/// The authority one `[workspace]` root lends its members: both of Cargo's
/// inheritance tables, read off that root's manifest.
///
/// A single scan can span more than one workspace — a `fuzz/` or `examples/` tree
/// with its own `[workspace]` is a root in its own right — so "the workspace root"
/// is not a single thing and each member must be read against the one that
/// actually governs it. The two tables travel together because a member's
/// `version.workspace = true` and its `dep.workspace = true` name the *same* root;
/// answering them from different manifests is the bug this type exists to prevent.
///
/// The [`Default`] scope — both tables empty — is what an *opaque* boundary gets:
/// a root whose manifest cannot be read or parsed lends no authority at all, but
/// still stops the enclosing root's from reaching past it.
#[derive(Default)]
struct Scope {
    /// `[workspace.package]`, the source of a member's `version.workspace = true`.
    package_defaults: BTreeMap<String, String>,
    /// `[workspace.dependencies]`, the source of a member's `dep.workspace = true`.
    declarations: Vec<Item>,
}

/// Read a manifest's two workspace inheritance tables.
///
/// A table that is absent, or a manifest that does not parse, yields an empty one
/// — which is the honest answer rather than a fallback: a root declaring no
/// `[workspace.package] version` resolves its members' `version.workspace = true`
/// to nothing, never to some other root's number.
fn scope_of(content: &str) -> Scope {
    Scope {
        package_defaults: parse_workspace(content)
            .map(|ws| ws.package_defaults)
            .unwrap_or_default(),
        // A member's `dep.workspace = true` says nothing about what the crate *is* —
        // its root's declaration does. Resolving against it is what tells a
        // centrally-declared registry crate from a centrally-declared vendored path,
        // which the member's own text cannot.
        declarations: CargoTomlParser
            .parse(content)
            .map(|m| m.items)
            .unwrap_or_default()
            .into_iter()
            .filter(|item| item.kind == DependencyKind::Workspace)
            .collect(),
    }
}

/// What a directory's `Cargo.toml` tells the walk about the subtree beneath it.
///
/// The distinction that matters is between *absent* and *unusable*. A directory
/// with no manifest is plainly still governed by the enclosing workspace root; a
/// directory whose manifest exists but cannot be read or parsed is not — it may
/// well declare a `[workspace]`, and there is no way to tell. Collapsing the two
/// into "not a workspace" is what would let a crate below an unreadable nested
/// root inherit a version from a root with no authority over it.
enum Boundary {
    /// No `Cargo.toml` here. The enclosing scope still governs what is below.
    Absent,
    /// A `Cargo.toml` that was read and parses as TOML.
    Manifest(String),
    /// A `Cargo.toml` that exists but could not be read, or is not valid TOML.
    Opaque,
}

/// Classify a directory's `Cargo.toml` into a [`Boundary`].
///
/// Anything other than "the file is not there" is [`Boundary::Opaque`]: a
/// permission error, an unreadable device, a directory of that name, or a syntax
/// error all leave the manifest's contents unknown, and unknown is not the same as
/// empty.
fn boundary_at(dir: &Path) -> Boundary {
    match std::fs::read_to_string(dir.join("Cargo.toml")) {
        // `CargoTomlParser` fails only when the TOML itself does not parse, which is
        // exactly the question being asked here.
        Ok(content) if CargoTomlParser.parse(&content).is_ok() => Boundary::Manifest(content),
        Ok(_) => Boundary::Opaque,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Boundary::Absent,
        Err(_) => Boundary::Opaque,
    }
}

/// A crate manifest found under the scan root.
struct Member {
    /// The crate's `[package] name`.
    name: String,
    /// The manifest's text.
    content: String,
    /// Index into the scan's [`Scope`] arena: the workspace root that governs this
    /// crate, which is its **nearest** `[workspace]` ancestor.
    ///
    /// The scan root is index 0. A crate inside a nested, independent workspace — a
    /// `fuzz/` or `examples/` directory with its own `[workspace]` table — points at
    /// that nested root instead, because Cargo resolves it against *that* one and the
    /// scan root has no authority over it. An unreadable or unparseable manifest in
    /// between opens a scope too — an empty one, per [`Boundary::Opaque`].
    scope: usize,
}

/// Collect a [`Member`] for every crate under `root_dir`, deduplicated by name,
/// together with the [`Scope`] arena those members index into. A crate is treated
/// as in-workspace iff its `[package] name` appears here — this sidesteps needing
/// a glob engine.
fn collect_members(
    root_dir: &Path,
    root_content: &str,
    excluded: &HashSet<PathBuf>,
) -> (Vec<Member>, Vec<Scope>) {
    let mut walk = Walk {
        root_dir,
        excluded,
        seen: HashMap::new(),
        members: Vec::new(),
        // The scan root is index 0, and a nested root can only be pushed after the
        // root that contains it — so a smaller index is always the outer scope.
        scopes: vec![scope_of(root_content)],
    };
    walk.descend(root_dir, 64, 0);
    (walk.members, walk.scopes)
}

/// One run of the member walk.
///
/// The walk carries state across the whole recursion — the dedup index, the
/// members found, and the [`Scope`] arena that grows as nested workspace roots are
/// met — so it lives here rather than in an argument list threaded through every
/// call. Only what actually varies per directory stays an argument.
struct Walk<'a> {
    /// The scan root, the one directory whose `[workspace]` does not open a new scope.
    root_dir: &'a Path,
    /// Absolute directories named in the scan root's `[workspace] exclude`.
    excluded: &'a HashSet<PathBuf>,
    /// `[package] name` -> index into `members`; a crate name yields one member.
    seen: HashMap<String, usize>,
    members: Vec<Member>,
    scopes: Vec<Scope>,
}

impl Walk<'_> {
    /// Record `dir`'s crate, if it holds one, then descend into its subdirectories.
    fn descend(&mut self, dir: &Path, depth_left: usize, scope: usize) {
        // Read once: the same text answers both "is this a workspace root?" and "is
        // this a crate?", and a `cargo fuzz` manifest is routinely both.
        let manifest = boundary_at(dir);
        // A nested `[workspace]` is a workspace root in its own right. Cargo already
        // ignores such a subtree, so nobody lists it in `[workspace] exclude`, and the
        // walk still descends into it — but the outer root's tables have no authority
        // there. Everything at or below this manifest resolves against the nested root
        // instead. The scope is switched *before* this directory's own `[package]` is
        // read, so a manifest that is both a `[workspace]` and a `[package]` resolves
        // against itself.
        let scope = match &manifest {
            Boundary::Manifest(content)
                if dir != self.root_dir && parse_workspace(content).is_some() =>
            {
                self.scopes.push(scope_of(content));
                self.scopes.len() - 1
            }
            // A manifest that exists but cannot be read or parsed is an opaque
            // boundary, not an absent one: it may declare a `[workspace]`, and nothing
            // here can rule that out. Push an empty scope so the crates below it
            // resolve their `workspace = true` fields to nothing, rather than silently
            // borrowing an enclosing root's — a file that exists and cannot be read is
            // not evidence that the outer root governs what is beneath it.
            Boundary::Opaque if dir != self.root_dir => {
                self.scopes.push(Scope::default());
                self.scopes.len() - 1
            }
            _ => scope,
        };
        if let Boundary::Manifest(content) = manifest
            && let Some(name) = parse_package_name(&content)
        {
            match self.seen.get(&name).copied() {
                // Two crates can share a `[package] name` across a nested-workspace
                // boundary, and only one node can carry it. The outer scope wins: a
                // nested root is only pushed after the root containing it, so a
                // smaller index is the enclosing one. Between two crates in *sibling*
                // nested workspaces neither encloses the other, and the smaller index
                // is then the alphabetically earlier path — arbitrary, but fixed,
                // which is the point. Without this the answer would follow whichever
                // one the filesystem happened to hand back first.
                Some(idx) => {
                    if scope < self.members[idx].scope {
                        self.members[idx] = Member {
                            name,
                            content,
                            scope,
                        };
                    }
                }
                None => {
                    self.seen.insert(name.clone(), self.members.len());
                    self.members.push(Member {
                        name,
                        content,
                        scope,
                    });
                }
            }
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        // `read_dir` yields filesystem order, which can differ between machines holding
        // identical contents. Descending in a fixed order is what makes the walk — and
        // with it the duplicate-name rule above — reproducible.
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            if !path.is_dir() || depth_left == 0 || self.excluded.contains(&path) {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (SKIP_DIRS.contains(&name) || name.starts_with('.'))
            {
                continue;
            }
            self.descend(&path, depth_left - 1, scope);
        }
    }
}

/// Build a shallow graph from member manifests when there is no `Cargo.lock`:
/// each member plus its direct declared dependencies.
///
/// A member's *own* version is read from its `[package] version` — a path member
/// is not resolved against anything, so what the manifest declares **is** its
/// version, whether or not a lockfile exists. Its dependencies are a different
/// matter: a manifest declares a constraint, not a resolution, so those stay
/// unknown — unless the constraint names exactly one release (`= "1.0.200"`), in
/// which case the manifest has already resolved it and [`declared_pin`] reads it
/// off.
///
/// Both kinds of `workspace = true` — a member's own `version` and its
/// dependencies — are resolved against [`Member::scope`], the crate's nearest
/// `[workspace]` ancestor, rather than against the scan root. A crate in a nested,
/// independent workspace therefore reports what *its* root declares; where that
/// root declares nothing, nothing is reported, because borrowing an unrelated
/// root's number would be a confidently wrong answer rather than an absent one.
fn shallow_graph(
    members: &[Member],
    workspace_names: &HashSet<String>,
    roots: &[String],
    scopes: &[Scope],
) -> DependencyGraph {
    let mut member_pkgs: Vec<LockedPackage> = Vec::new();
    let mut external_pkgs: Vec<LockedPackage> = Vec::new();
    let mut external_seen: HashMap<String, usize> = HashMap::new();

    for member in members {
        // The root that governs *this* crate, which in a scan spanning more than one
        // workspace is not necessarily the scan root.
        let scope = &scopes[member.scope];
        let mut items = CargoTomlParser
            .parse(&member.content)
            .map(|m| m.items)
            .unwrap_or_default();
        let _ = resolve_workspace_inheritance(&mut items, &scope.declarations);
        let mut deps: Vec<String> = Vec::new();
        for item in &items {
            deps.push(item.name.clone());
            if workspace_names.contains(&item.name) {
                continue;
            }
            // Items are inheritance-resolved by now, so a member's
            // `dep.workspace = true` pointing at its own root's `= "1.0.200"` is read
            // here as the pin that root declared.
            let pin = declared_pin(item, Ecosystem::Rust).map(str::to_owned);
            match external_seen.get(&item.name) {
                // One node for the name, so a version survives only where every
                // member that declares it agrees. First-wins would make the graph
                // depend on the order the directory walk happened to find them in.
                Some(&idx) => {
                    if external_pkgs[idx].version != pin {
                        external_pkgs[idx].version = None;
                    }
                }
                None => {
                    // Synthesize a source so classification matches the item's kind. An
                    // inherited entry has already taken its root declaration's source above,
                    // so a centrally-declared `path` crate lands on the `Local` arm and a
                    // centrally-declared registry crate does not.
                    let source = match item.source {
                        PackageSource::Git => Some("git+".to_owned()),
                        PackageSource::Local => None,
                        _ => Some("registry+".to_owned()),
                    };
                    external_seen.insert(item.name.clone(), external_pkgs.len());
                    external_pkgs.push(LockedPackage::new(
                        item.name.clone(),
                        // Usually `None`: a manifest declares a constraint, not a
                        // resolved version, and nothing here read one.
                        pin,
                        source,
                        Vec::new(),
                    ));
                }
            }
        }
        deps.sort();
        deps.dedup();
        // The member's declared version, inherited one included. Unlike a
        // dependency's constraint this is not a range to resolve — it is what
        // this crate is — so leaving it unknown would understate what the
        // manifest already said.
        let version = parse_project(ManifestKind::CargoToml, &member.content)
            .version
            .as_ref()
            .and_then(|field| field.resolve(&scope.package_defaults, "version"))
            .map(str::to_owned);
        member_pkgs.push(LockedPackage::new(member.name.clone(), version, None, deps));
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
    // A manifest that declares no version of its own — a `pom.xml` inheriting
    // from a `<parent>`, a `*.csproj` — leaves this unknown rather than blank.
    let root_version: Option<String> = meta.literal_version().map(str::to_owned);

    // The project's own declared dependencies, used as the root's edges whenever the
    // lockfile carries no entry for the project itself. Kept as whole items: a
    // constraint that names one release is the only version a manifest-only graph
    // will ever have for these, and mapping to bare names here would discard it.
    let direct: Vec<Item> = parse(kind, &content)
        .map(|parsed| parsed.items)
        .unwrap_or_default();
    let direct_names: Vec<String> = direct.iter().map(|item| item.name.clone()).collect();

    let workspace_names: HashSet<String> = std::iter::once(root_name.clone()).collect();
    let roots: Vec<String> = match &opts.package {
        Some(pkg) => vec![pkg.clone()],
        None => vec![root_name.clone()],
    };

    if !has_graph_parser(kind) {
        let graph = direct_graph(
            &root_name,
            root_version.as_deref(),
            &direct,
            kind.ecosystem(),
            &workspace_names,
            &roots,
        );
        return Ok(WorkspaceGraph {
            graph,
            source: GraphSource::Unsupported,
        });
    }

    let Some((lock_path, lock_kind)) = crate::discover::locate_lockfile(manifest, kind) else {
        let graph = direct_graph(
            &root_name,
            root_version.as_deref(),
            &direct,
            kind.ecosystem(),
            &workspace_names,
            &roots,
        );
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
        let graph = direct_graph(
            &root_name,
            root_version.as_deref(),
            &direct,
            kind.ecosystem(),
            &workspace_names,
            &roots,
        );
        return Ok(WorkspaceGraph {
            graph,
            source: GraphSource::Unsupported,
        });
    };

    let resolved = parser(&read(&lock_path)?)?;
    let resolved = with_root(resolved, &root_name, root_version.as_deref(), direct_names);
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
    root_version: Option<&str>,
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
        root_version.map(str::to_owned),
        None,
        direct,
    )];
    packages.extend(resolved.packages);
    ResolvedLockfile::from_packages(packages)
}

/// The version a declared dependency is already resolved to, when its constraint
/// names exactly one release; `None` otherwise.
///
/// This is the whole difference between a manifest-only graph that reports
/// `unknown` for everything and one that reports what the manifest already
/// settled: `serde = "=1.0.200"` admits one release and nothing else, so calling
/// it unknown understates what was read, exactly as it would for a member's own
/// declared version.
///
/// Gated on [`Item::is_checkable`], the existing predicate for "there is a version
/// string here worth asking a registry about". That is what keeps a git or path
/// reference — and an `Inherited` entry no root has supplied a constraint for —
/// unknown, without a second rule that could drift from the first.
fn declared_pin(item: &Item, ecosystem: Ecosystem) -> Option<&str> {
    if !item.is_checkable() {
        return None;
    }
    exact_pin(&item.version_constraint, ecosystem)
}

/// A two-level graph: the project and the dependencies it declares. A version is
/// carried only where the declaration named one ([`declared_pin`]). Used when no
/// resolved graph is available.
fn direct_graph(
    root_name: &str,
    root_version: Option<&str>,
    direct: &[Item],
    ecosystem: Ecosystem,
    workspace_names: &HashSet<String>,
    roots: &[String],
) -> DependencyGraph {
    let mut packages = vec![LockedPackage::new(
        root_name.to_owned(),
        root_version.map(str::to_owned),
        None,
        direct.iter().map(|item| item.name.clone()).collect(),
    )];
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for item in direct {
        if item.name == root_name {
            continue;
        }
        let pin = declared_pin(item, ecosystem).map(str::to_owned);
        match seen.get(item.name.as_str()) {
            // Two declarations of one name collapse into one node, so a version
            // may only be carried when they agree on it. Taking the first would
            // make the answer depend on the order the manifest happens to list
            // them in, which is not a resolution of anything.
            Some(&idx) => {
                if packages[idx].version != pin {
                    packages[idx].version = None;
                }
            }
            None => {
                seen.insert(item.name.as_str(), packages.len());
                packages.push(LockedPackage::new(
                    item.name.clone(),
                    // A manifest names its dependencies and usually only
                    // constrains them; `None` is how the graph says so.
                    pin,
                    Some("registry+".to_owned()),
                    Vec::new(),
                ));
            }
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
