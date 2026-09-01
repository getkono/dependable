//! Depth-limited manifest discovery and lockfile location.
//!
//! Finding the manifests in a directory tree is filesystem work, so it lives here
//! rather than in the IO-free core — but it is not CLI-specific: every frontend
//! (the CLI, the TUI, an editor plugin) needs the same answer to "which manifests
//! are in this project, and which lockfile governs each one".
//!
//! Recognition is by [`ManifestKind::detect`]; manifests whose ecosystem is
//! unsupported or disabled are filtered by the caller, not here, so a frontend can
//! still tell the user that a manifest was seen and skipped.
//!
//! Locating a workspace root lives here too. It is the same upward walk as
//! [`find_lockfile`], answering the same shape of question — "which file above this one
//! governs it" — and, like a lockfile, what it finds has to be read and parsed before it
//! is useful. Which names to look for and how to recognize one is the manifest kind's
//! answer ([`ManifestKind::workspace_roots`]), not this module's, so the walk itself is
//! ecosystem-neutral. Reading it is IO; what to *do* with the result is
//! [`dependable_core::resolve_workspace_inheritance`], which stays pure.

use std::path::{Path, PathBuf};

use dependable_core::{
    DependencyKind, Ecosystem, Item, LockfileData, LockfileKind, ManifestKind,
    UNREADABLE_MANIFESTS, UnreadableManifest, parse, parse_lockfile_kind,
};

/// Directories never descended into during discovery: build output, vendored
/// dependencies, and VCS metadata. Dotted directories are skipped as well.
pub const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "vendor"];

/// Whether `name` is a directory discovery never descends into.
#[must_use]
pub fn is_skipped_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name) || name.starts_with('.')
}

/// Find every recognized manifest under `root`, searching up to `max_depth`
/// directories deep, skipping build/vendor directories.
///
/// The result is sorted, so callers render a stable order.
///
/// A caller that also wants [`manifest_notices`] should call [`discover`] instead
/// and take both from one walk.
#[must_use]
pub fn find_manifests(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    discover(root, max_depth, |_| false).manifests
}

/// What one walk of a project tree found: the manifests that can be read, and the
/// files that cannot.
///
/// The two used to be two identical recursive walks — same depth bound, same
/// skipped directories, run back to back by every caller that wanted both — which
/// is one `readdir` per directory too many in every project, Gradle or not.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovered {
    /// Every recognized manifest, sorted.
    pub manifests: Vec<PathBuf>,
    /// Every recognized-but-unreadable manifest, sorted, for the enabled
    /// ecosystems only.
    pub notices: Vec<LockfileNotice>,
}

/// Walk `root` once for both the manifests to read and the manifests that cannot be
/// read.
///
/// `enabled` says whether an ecosystem is switched on. It gates the notices only —
/// discovery still returns every manifest it recognizes, and narrowing that set
/// stays the caller's job (see the module docs) — because a notice is advice to
/// *enable* something, and giving it to someone who has turned that ecosystem off
/// is noise they cannot act on. A caller with no configuration to consult passes
/// `|_| true`.
#[must_use]
pub fn discover(root: &Path, max_depth: usize, enabled: impl Fn(Ecosystem) -> bool) -> Discovered {
    let mut found = Discovered::default();
    // Canonicalized once here rather than per unreadable file: it is the bound the
    // supersession walk stops at, and it is the same answer every time.
    let scan_root = std::fs::canonicalize(root).ok();
    walk(root, scan_root.as_deref(), max_depth, &enabled, &mut found);
    found.manifests.sort();
    found.notices.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

fn walk(
    dir: &Path,
    scan_root: Option<&Path>,
    depth_left: usize,
    enabled: &dyn Fn(Ecosystem) -> bool,
    found: &mut Discovered,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth_left == 0 {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && is_skipped_dir(name)
            {
                continue;
            }
            walk(&path, scan_root, depth_left - 1, enabled, found);
        } else if ManifestKind::detect(&path).is_some() {
            found.manifests.push(path);
        } else if let Some(unreadable) = unreadable_manifest(&path)
            && enabled(unreadable.ecosystem)
            && !is_superseded(dir, scan_root, unreadable)
        {
            found.notices.push(LockfileNotice {
                path,
                reason: unreadable.reason.to_owned(),
            });
        }
    }
}

/// The [`UnreadableManifest`] entry `path` names, if any.
fn unreadable_manifest(path: &Path) -> Option<&'static UnreadableManifest> {
    let name = path.file_name()?.to_str()?;
    UNREADABLE_MANIFESTS
        .iter()
        .find(|unreadable| unreadable.file_name == name)
}

/// Whether the dependencies of an unreadable manifest in `dir` are declared
/// somewhere readable after all.
///
/// The search walks **up** from `dir`, because supersession is build-root scoped
/// and not directory-local: one `<root>/gradle/libs.versions.toml` serves every
/// subproject of a Gradle build, and a subproject has no `gradle/` directory.
///
/// Three bounds stop the walk, and every one of them is load-bearing:
///
/// - The first directory holding a build-root marker, having checked that
///   directory, so one build never adopts the catalog of another beside it.
/// - A `.git`, the same repository boundary [`find_lockfile`] uses.
/// - `scan_root`, the canonicalized directory the scan was asked about — but as a
///   bound on *stepping out of the scanned tree*, not as a wall. Scanning one
///   module of a multi-module build (`dependable list <repo>/app`, or a CI matrix
///   job per module) is a normal thing to ask for, and the build root that declares
///   that module is by definition above the directory asked about: a hard stop here
///   warned that `app/build.gradle.kts` was unread and told the user to declare its
///   dependencies in the catalog they already have. So the walk may leave the
///   scanned tree, and only for a directory that declares subprojects.
///
/// That last rule bounds the walk to **one** directory above `scan_root`: every
/// `subproject_markers` file is a `build_root_markers` file too, so the ancestor the
/// walk is allowed to step onto is a build root and stops it. Without it, a checkout
/// with no `.git` (a source tarball, a `git archive`, a vendored copy) walked to `/`
/// once per unreadable file, adopting whatever it found on the way.
///
/// An ancestor's catalog counts only when that ancestor declares subprojects
/// (`subproject_markers`): a repository-root catalog with no `settings.gradle` is a
/// single-project build, and a `tools/build.gradle` under it is a separate build
/// whose dependencies really are unread. A catalog in the unreadable file's *own*
/// directory needs no such evidence.
///
/// `dir` is canonicalized first, for the reason [`nearest_workspace_root`]
/// documents: [`Path::parent`] is lexical, so walking up from a relative `.` yields
/// `""`, which every later `join` resolves against the current directory instead of
/// against an ancestor. A directory that cannot be canonicalized — or a scan whose
/// root cannot be, which leaves the walk with no bound to respect — is answered
/// from itself alone.
fn is_superseded(dir: &Path, scan_root: Option<&Path>, unreadable: &UnreadableManifest) -> bool {
    let holds = |dir: &Path| {
        unreadable
            .superseded_by
            .iter()
            .any(|relative| dir.join(relative).is_file())
    };
    let (Ok(canonical), Some(scan_root)) = (std::fs::canonicalize(dir), scan_root) else {
        return holds(dir);
    };
    let declares_subprojects = |dir: &Path| {
        unreadable
            .subproject_markers
            .iter()
            .any(|marker| dir.join(marker).is_file())
    };
    let mut cur = canonical.as_path();
    let mut own_directory = true;
    let mut leaving_scan = false;
    loop {
        let governs = own_directory || declares_subprojects(cur);
        if governs && holds(cur) {
            return true;
        }
        let at_root = unreadable
            .build_root_markers
            .iter()
            .any(|marker| cur.join(marker).is_file());
        if at_root || cur.join(".git").exists() {
            return false;
        }
        // Outside the scanned tree the walk moves only onto a directory that
        // declares subprojects — the build root the scanned module belongs to.
        leaving_scan |= cur == scan_root;
        match cur.parent() {
            Some(parent) if !leaving_scan || declares_subprojects(parent) => {
                cur = parent;
                own_directory = false;
            }
            _ => return false,
        }
    }
}

/// Locate the lockfile governing `manifest` without reading it.
///
/// Same upward walk as [`find_lockfile`] — the manifest's own directory first, then
/// each ancestor, stopping at a `.git` boundary — but it answers only "where is it",
/// which is what callers that need a different parse of the same file want.
#[must_use]
pub fn locate_lockfile(manifest: &Path, kind: ManifestKind) -> Option<(PathBuf, LockfileKind)> {
    let candidates = kind.lockfiles();
    if candidates.is_empty() {
        return None;
    }
    let mut dir = manifest.parent()?;
    loop {
        // A directory is searched for every candidate before moving up, so a
        // lockfile beside the manifest always beats one further away whichever
        // package manager wrote it.
        for lockfile in candidates {
            let candidate = dir.join(lockfile.file_name());
            if candidate.is_file() {
                return Some((candidate, *lockfile));
            }
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// Locate and read the lockfile governing `manifest`, searching its own directory
/// first and then each ancestor.
///
/// The search stops at a repository boundary (a directory containing `.git`), so a
/// project never adopts the lockfile of an unrelated sibling checkout above it. A
/// candidate that cannot be read or parsed does not end the search — the walk
/// continues upward, because an unreadable file governs nothing.
///
/// Returns the path and the parsed data, or `None` for manifest kinds that have no
/// lockfile ([`ManifestKind::lockfiles`]) and when none is found.
#[must_use]
pub fn find_lockfile(manifest: &Path, kind: ManifestKind) -> Option<(PathBuf, LockfileData)> {
    let candidates = kind.lockfiles();
    if candidates.is_empty() {
        return None;
    }
    let mut dir = manifest.parent()?;
    loop {
        for lockfile in candidates {
            let candidate = dir.join(lockfile.file_name());
            if let Ok(content) = std::fs::read_to_string(&candidate)
                && let Ok(parsed) = parse_lockfile_kind(*lockfile, &content)
            {
                return Some((candidate, parsed));
            }
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// The nearest manifest above `manifest` offering central dependency declarations, with
/// its path, the kind it is to be parsed as, and its content.
///
/// Which names to try in each directory, and what recognizes one as a root, come from
/// `kind` ([`ManifestKind::workspace_roots`]); a kind with no such indirection is
/// answered without touching the filesystem at all. Each directory is searched for every
/// candidate name before moving up, so a root beside the manifest always beats one
/// further away — the same precedence [`find_lockfile`] gives lockfiles.
///
/// The returned kind is the one the *matched name* is paired with, not `kind`: a member
/// and the root governing it need not share a file format, and within one ecosystem two
/// candidate names need not share one either. It is what the root's content must be
/// parsed with, so a caller reading the returned text passes it to
/// [`workspace_declarations`] unchanged.
///
/// `manifest` itself is excluded, so a member always resolves against a root *above* it.
/// A root that is also a package declares its own values literally, and
/// [`workspace_root_of`] is what handles it inheriting from its own table. The walk stops
/// at a repository boundary (a directory holding `.git`), so inheritance never resolves
/// against a manifest belonging to an unrelated checkout above the project.
///
/// # Why the path is canonicalized first
/// [`Path::parent`] is lexical: the parent of a relative `../sibling` is `..`, and the
/// parent of *that* is `""` — which every subsequent `join` resolves against the **current
/// directory**, a sibling of the manifest rather than an ancestor of it. Walking
/// `dependable check --manifest ../other/Cargo.toml` from inside a workspace would
/// otherwise hand `../other` that workspace's `[workspace.dependencies]`, and no `.git`
/// check catches it, because the boundary is tested against the current directory too.
///
/// The returned path is therefore absolute and symlink-resolved, whatever `manifest` was
/// spelled as. A manifest that cannot be canonicalized (it was deleted between discovery
/// and here) belongs to no workspace.
#[must_use]
pub fn nearest_workspace_root(
    manifest: &Path,
    kind: ManifestKind,
) -> Option<(PathBuf, ManifestKind, String)> {
    let roots = kind.workspace_roots()?;
    let manifest = std::fs::canonicalize(manifest).ok()?;
    let mut dir = manifest.parent()?;
    loop {
        if let Some(found) = root_in_dir(dir, roots.root_names, &manifest) {
            return Some(found);
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// The first of `candidates` present in `dir` that its own paired kind recognizes as a
/// root, with the path, that kind, and the content.
///
/// Each candidate is recognized by **its own** kind rather than by one kind shared across
/// the list, which is what lets an ecosystem name roots of more than one file format: a
/// pnpm member roots at `pnpm-workspace.yaml`, a Bun member at the workspace root's own
/// `package.json`, and a shared kind would run the YAML parser over one or the JSON
/// parser over the other. A candidate its paired kind does not recognize is walked past,
/// not treated as the end of the search, so a name that exists but declares nothing never
/// hides a real root further down the list.
///
/// `exclude` is the manifest doing the asking: a member always resolves against a root
/// *other than* itself, and [`workspace_root_of`] is what handles the self case.
fn root_in_dir(
    dir: &Path,
    candidates: &[(&str, ManifestKind)],
    exclude: &Path,
) -> Option<(PathBuf, ManifestKind, String)> {
    for (name, root_kind) in candidates {
        let candidate = dir.join(name);
        if !same_file(&candidate, exclude)
            && let Ok(content) = std::fs::read_to_string(&candidate)
            && root_kind.declares_workspace(&content)
        {
            return Some((simplified(candidate), *root_kind, content));
        }
    }
    None
}

/// The manifest whose central declarations govern `manifest`, the kind it is to be
/// parsed as, and its text.
///
/// A manifest that declares a root itself governs **itself**, where its kind allows that
/// ([`WorkspaceRoots::self_governing`](dependable_core::WorkspaceRoots)): Cargo lets a
/// root that is also a package write `serde.workspace = true` against its own table, and
/// walking past it would leave those entries unresolved. Otherwise the nearest ancestor
/// root governs. `content` is the manifest's own text, already in the caller's hand, so
/// the self case costs no extra read.
///
/// The self case reports `kind` as the root kind, because it is `kind`'s own
/// `declares_workspace` that accepted the text — recognising a root with one parser and
/// then reading it with another is exactly the mismatch
/// [`WorkspaceRoots::self_governing`](dependable_core::WorkspaceRoots) is documented to
/// forbid, and the `debug_assert` below is what catches a descriptor that breaks it.
///
/// Separate from [`workspace_declarations`] so a caller checking many members of one
/// workspace can key a cache on the root's path and parse it only once; use
/// [`workspace_source`] when that does not matter.
///
/// Returns `None` for a kind with no central declarations — before any filesystem
/// access, since the answer is in the kind — and when no root is found.
#[must_use]
pub fn workspace_root_of(
    manifest: &Path,
    kind: ManifestKind,
    content: &str,
) -> Option<(PathBuf, ManifestKind, String)> {
    let roots = kind.workspace_roots()?;
    debug_assert!(
        !roots.self_governing || roots.root_names.iter().any(|(_, root)| *root == kind),
        "{kind:?} governs itself but is not among its own root kinds: {:?}",
        roots.root_names
    );
    if roots.self_governing && kind.declares_workspace(content) {
        // Canonical, to match the shape [`nearest_workspace_root`] returns.
        let root = std::fs::canonicalize(manifest)
            .map(simplified)
            .unwrap_or_else(|_| manifest.to_path_buf());
        return Some((root, kind, content.to_owned()));
    }
    nearest_workspace_root(manifest, kind)
}

/// The governing manifest and the declarations it offers — the input
/// [`dependable_core::resolve_workspace_inheritance`] needs.
///
/// [`workspace_root_of`] followed by [`workspace_declarations`].
#[must_use]
pub fn workspace_source(
    manifest: &Path,
    kind: ManifestKind,
    content: &str,
) -> Option<(PathBuf, Vec<Item>)> {
    let (root, root_kind, root_content) = workspace_root_of(manifest, kind, content)?;
    Some((root, workspace_declarations(root_kind, &root_content)))
}

/// The central declarations offered by `content`, the text of a root of kind `root_kind`.
///
/// The kind taken is the **root's own**, not that of the member inheriting from it, since
/// an ecosystem may keep its central declarations in a different file format from the
/// manifests inheriting them. It is the kind [`workspace_root_of`] and
/// [`nearest_workspace_root`] return alongside the root, so a caller holding nothing but
/// a located root and its text can call this — which a caller taking the member's kind
/// could not.
///
/// A manifest that will not parse declares nothing, which is the same answer as a
/// manifest with no such table — neither is worth failing a whole check over, and neither
/// is a kind that has no central declarations to offer.
#[must_use]
pub fn workspace_declarations(root_kind: ManifestKind, content: &str) -> Vec<Item> {
    parse(root_kind, content)
        .map(|parsed| {
            parsed
                .items
                .into_iter()
                .filter(|item| item.kind == DependencyKind::Workspace)
                .collect()
        })
        .unwrap_or_default()
}

/// Drop Windows' `\\?\` extended-length prefix, which `std::fs::canonicalize` always
/// applies and which no user wants to read.
///
/// Only the plain-drive form is simplified: every other verbatim prefix (a UNC share, a
/// device path) has no equivalent without it, and shortening those would name a different
/// file. A no-op everywhere else, since the prefix cannot occur.
fn simplified(path: PathBuf) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1) == Some(&b':')
    {
        return PathBuf::from(rest);
    }
    path
}

/// Whether two paths name the same file. Compared after canonicalization, since a
/// discovered manifest (`./Cargo.toml`) and a candidate built while walking up
/// (`Cargo.toml`) can spell one file two ways.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// A file discovery found that exists but yields nothing — a lockfile it cannot
/// read, or a manifest it cannot read.
///
/// Every such case used to be a silent drop — an unreadable candidate was
/// discarded by `if let Ok(...)` and the walk carried on, so a project with a
/// lockfile it could not use was indistinguishable from one with none. That is
/// the state a user is most able to act on, and the one they were never told
/// about. The same reasoning covers a manifest that is a build script: reporting
/// a short dependency list is worse than reporting none, because only one of the
/// two looks wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockfileNotice {
    /// The file this is about.
    pub path: PathBuf,
    /// What is wrong with it, phrased for the person who has to fix it.
    pub reason: String,
}

impl std::fmt::Display for LockfileNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

/// Report lockfiles beside `manifest` that exist but cannot be used.
///
/// Covers two cases: a format we recognise and deliberately do not read (Bun's
/// binary `bun.lockb`), and one we do read that will not parse. Only the
/// manifest's own directory is searched — a file further up governs a different
/// project, and blaming this one for it would be noise.
#[must_use]
pub fn lockfile_notices(manifest: &Path, kind: ManifestKind) -> Vec<LockfileNotice> {
    let Some(dir) = manifest.parent() else {
        return Vec::new();
    };
    let mut notices = Vec::new();

    for unreadable in kind.unreadable_lockfiles() {
        let path = dir.join(unreadable.file_name);
        if path.is_file() {
            notices.push(LockfileNotice {
                path,
                reason: unreadable.reason.to_owned(),
            });
        }
    }

    for lockfile in kind.lockfiles() {
        let path = dir.join(lockfile.file_name());
        if !path.is_file() {
            continue;
        }
        let reason = match std::fs::read_to_string(&path) {
            Err(error) => format!("could not be read: {error}"),
            Ok(content) => match parse_lockfile_kind(*lockfile, &content) {
                Err(error) => format!("could not be parsed: {error}"),
                Ok(data) if data.versions.is_empty() => {
                    "was read but records no versions".to_owned()
                }
                Ok(_) => continue,
            },
        };
        notices.push(LockfileNotice { path, reason });
    }

    notices
}

/// Report manifests under `root` that are recognised but cannot be read, for the
/// ecosystems `enabled` says are switched on.
///
/// The companion to [`lockfile_notices`], and a directory scan rather than a
/// per-manifest check for the reason the notice exists at all: a Gradle project
/// with no version catalog produces **no** manifest for discovery to hand over, so
/// there is nothing to hang the question on.
///
/// A file whose readable alternative is present is not reported: a
/// `build.gradle.kts` under a build root holding `gradle/libs.versions.toml` had
/// its dependencies read from the catalog, and warning about it would be noise.
///
/// [`discover`] answers this and [`find_manifests`] from one walk; prefer it when
/// both are wanted.
#[must_use]
pub fn manifest_notices(
    root: &Path,
    max_depth: usize,
    enabled: impl Fn(Ecosystem) -> bool,
) -> Vec<LockfileNotice> {
    discover(root, max_depth, enabled).notices
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, content).expect("write");
    }

    #[test]
    fn finds_manifests_sorted_and_skips_build_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join("Cargo.toml"), "[package]\nname = \"a\"\n");
        write(&root.join("web/package.json"), "{}");
        // Both of these live in directories discovery must never descend into.
        write(&root.join("target/debug/Cargo.toml"), "[package]\n");
        write(&root.join("node_modules/dep/package.json"), "{}");
        write(&root.join(".hidden/Cargo.toml"), "[package]\n");

        let found = find_manifests(root, 3);

        assert_eq!(
            found,
            vec![root.join("Cargo.toml"), root.join("web/package.json")],
            "expected only the two real manifests, sorted"
        );
    }

    #[test]
    fn respects_the_depth_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            &root.join("a/b/c/Cargo.toml"),
            "[package]\nname = \"deep\"\n",
        );

        assert!(find_manifests(root, 2).is_empty(), "3 levels down, depth 2");
        assert_eq!(find_manifests(root, 3).len(), 1, "depth 3 reaches it");
    }

    #[test]
    fn finds_the_lockfile_in_an_ancestor_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let manifest = root.join("crates/member/Cargo.toml");
        write(&manifest, "[package]\nname = \"member\"\n");
        write(
            &root.join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\n",
        );

        let (path, data) = find_lockfile(&manifest, ManifestKind::CargoToml).expect("lockfile");

        assert_eq!(path, root.join("Cargo.lock"));
        assert!(data.versions.contains_key("serde"), "parsed the lockfile");
    }

    #[test]
    fn stops_at_a_repository_boundary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // An unrelated checkout above the repo must never supply its lockfile.
        write(&root.join("Cargo.lock"), "[[package]]\nname = \"x\"\n");
        let manifest = root.join("repo/Cargo.toml");
        write(&manifest, "[package]\nname = \"repo\"\n");
        std::fs::create_dir_all(root.join("repo/.git")).expect("mkdir .git");

        assert!(
            find_lockfile(&manifest, ManifestKind::CargoToml).is_none(),
            "the `.git` boundary should end the search"
        );
    }

    #[test]
    fn skips_an_unparseable_lockfile_and_keeps_walking_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            &root.join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\n",
        );
        let manifest = root.join("member/Cargo.toml");
        write(&manifest, "[package]\nname = \"member\"\n");
        write(
            &root.join("member/Cargo.lock"),
            "this is not valid toml {{{",
        );

        let (path, _) = find_lockfile(&manifest, ManifestKind::CargoToml).expect("lockfile");

        assert_eq!(
            path,
            root.join("Cargo.lock"),
            "the broken one governs nothing"
        );
    }

    #[test]
    fn a_located_lockfile_reports_which_format_it_is() {
        // The parser is chosen from this, so locating a file without saying what
        // it is would put us back to guessing from the manifest.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "").unwrap();

        let (path, kind) =
            locate_lockfile(&dir.path().join("Cargo.toml"), ManifestKind::CargoToml).unwrap();
        assert_eq!(path, dir.path().join("Cargo.lock"));
        assert_eq!(kind, LockfileKind::CargoLock);
    }

    #[test]
    fn a_nearer_lockfile_wins_over_one_further_up() {
        // Every candidate is tried in a directory before moving up, so proximity
        // decides, not the order the formats are listed in.
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".git"), "").unwrap();
        std::fs::write(root.path().join("package-lock.json"), "{}").unwrap();

        let nested = root.path().join("packages").join("app");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("package.json"), "{}").unwrap();
        std::fs::write(nested.join("package-lock.json"), "{}").unwrap();

        let (path, _) =
            locate_lockfile(&nested.join("package.json"), ManifestKind::PackageJson).unwrap();
        assert_eq!(path, nested.join("package-lock.json"));
    }

    #[test]
    fn a_binary_bun_lockfile_is_reported_rather_than_ignored() {
        // The state this exists for: a lockfile is right there, and the project
        // was being told none was found.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(dir.path().join("bun.lockb"), [0u8, 1, 2, 3]).unwrap();

        let notices = lockfile_notices(&dir.path().join("package.json"), ManifestKind::PackageJson);
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert_eq!(notices[0].path, dir.path().join("bun.lockb"));
        assert!(
            notices[0].reason.contains("--save-text-lockfile"),
            "the notice says how to fix it: {}",
            notices[0].reason
        );
    }

    #[test]
    fn a_readable_lockfile_produces_no_notice() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(
            dir.path().join("bun.lock"),
            r#"{"packages":{"react":["react@19.0.0","",{},"h"]}}"#,
        )
        .unwrap();

        let notices = lockfile_notices(&dir.path().join("package.json"), ManifestKind::PackageJson);
        assert!(notices.is_empty(), "{notices:?}");
    }

    #[test]
    fn a_lockfile_that_yields_nothing_is_reported() {
        // Silently reading a file and finding no versions in it is the failure
        // mode hardest to notice, so it is called out too.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(dir.path().join("bun.lock"), "{}").unwrap();

        let notices = lockfile_notices(&dir.path().join("package.json"), ManifestKind::PackageJson);
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].reason.contains("no versions"), "{notices:?}");
    }

    #[test]
    fn a_lockfile_further_up_is_not_this_projects_problem() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("bun.lockb"), [0u8]).unwrap();
        let nested = root.path().join("app");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("package.json"), "{}").unwrap();

        let notices = lockfile_notices(&nested.join("package.json"), ManifestKind::PackageJson);
        assert!(notices.is_empty(), "{notices:?}");
    }

    /// Windows' canonical form is the `\\?\` extended-length one, which is correct and
    /// unreadable. Testable on every platform, since it is pure string work.
    #[test]
    fn the_windows_extended_length_prefix_is_dropped_from_a_drive_path() {
        assert_eq!(
            simplified(PathBuf::from(r"\\?\D:\repo\Cargo.toml")),
            PathBuf::from(r"D:\repo\Cargo.toml")
        );
        // A UNC share has no form without the prefix, so shortening it would name a
        // different file.
        let unc = PathBuf::from(r"\\?\UNC\server\share\Cargo.toml");
        assert_eq!(simplified(unc.clone()), unc);
        // And an ordinary POSIX path is untouched.
        assert_eq!(
            simplified(PathBuf::from("/repo/Cargo.toml")),
            PathBuf::from("/repo/Cargo.toml")
        );
    }

    #[test]
    fn a_member_resolves_against_the_root_above_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Canonical, because the returned root is: on macOS the system temp directory is
        // reached through a `/var` -> `/private/var` symlink, so the two spellings of the
        // same file differ as strings.
        let root = &dir.path().canonicalize().expect("canonical");
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/app\"]\n\n[workspace.dependencies]\nserde = \"1.0.200\"\n",
        );
        let member = root.join("crates/app/Cargo.toml");
        let content = "[package]\nname = \"app\"\n\n[dependencies]\nserde.workspace = true\n";
        write(&member, content);

        let (found, declarations) =
            workspace_source(&member, ManifestKind::CargoToml, content).expect("a root");

        // `simplified` on both sides: the reported root has Windows' `\\?\` prefix dropped,
        // and `canonicalize` above put it there.
        assert_eq!(found, simplified(root.join("Cargo.toml")));
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].name, "serde");
        assert_eq!(declarations[0].version_constraint, "1.0.200");
    }

    /// Cargo lets a root be a package too, and lets that package write
    /// `serde.workspace = true` against its own table. Walking past itself to look for a
    /// root above would leave exactly those entries unresolved.
    #[test]
    fn a_root_that_is_also_a_package_governs_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir
            .path()
            .canonicalize()
            .expect("canonical")
            .join("Cargo.toml");
        let content = "[package]\nname = \"root\"\n\n[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1.0.200\"\n\n[dependencies]\nserde.workspace = true\n";
        write(&manifest, content);

        let (found, declarations) =
            workspace_source(&manifest, ManifestKind::CargoToml, content).expect("itself");

        assert_eq!(found, simplified(manifest.clone()));
        assert_eq!(declarations.len(), 1, "{declarations:?}");
        assert_eq!(declarations[0].name, "serde");
    }

    /// The trap a single `root_kind` over a whole name list sets: the paired kind, not
    /// the list's, decides which parser reads a candidate.
    ///
    /// The real case is a JavaScript member, which roots either at a
    /// `pnpm-workspace.yaml` or at the workspace root's own `package.json`. One kind
    /// across both names has to mis-read one of them. Cargo is the only kind that
    /// recognises anything today, so the heterogeneity is staged with a name whose usual
    /// kind is JSON: paired with `PackageJson` the file is not a root, paired with
    /// `CargoToml` the same bytes are.
    #[test]
    fn a_candidate_is_read_with_the_kind_it_is_paired_with() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = dir.path().canonicalize().expect("canonical");
        let central =
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1.0.200\"\n";
        write(&dir.join("package.json"), central);
        let nobody = dir.join("member/Cargo.toml");

        // Paired with `PackageJson`, the JSON parser reads TOML, sees no workspace, and
        // the candidate is not a root.
        assert!(
            root_in_dir(
                &dir,
                &[("package.json", ManifestKind::PackageJson)],
                &nobody
            )
            .is_none()
        );

        // Paired with `CargoToml`, the very same bytes are a root — and the kind reported
        // back is the pair's, so the caller parses it with the parser that recognised it.
        let (path, root_kind, content) =
            root_in_dir(&dir, &[("package.json", ManifestKind::CargoToml)], &nobody)
                .expect("a root");
        assert_eq!(path, simplified(dir.join("package.json")));
        assert_eq!(root_kind, ManifestKind::CargoToml);
        let declarations = workspace_declarations(ManifestKind::CargoToml, &content);
        assert_eq!(declarations.len(), 1, "{declarations:?}");
        assert_eq!(declarations[0].name, "serde");
    }

    /// A candidate its own kind cannot recognise is walked past, not taken as the answer:
    /// with one kind over a heterogeneous list, the unreadable name would silently hide
    /// the real root later in the list.
    #[test]
    fn an_unrecognised_candidate_does_not_hide_a_later_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = dir.path().canonicalize().expect("canonical");
        write(&dir.join("package.json"), "{\"name\": \"web\"}");
        write(
            &dir.join("Cargo.toml"),
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1\"\n",
        );
        let nobody = dir.join("member/Cargo.toml");

        let (path, root_kind, _) = root_in_dir(
            &dir,
            &[
                ("package.json", ManifestKind::PackageJson),
                ("Cargo.toml", ManifestKind::CargoToml),
            ],
            &nobody,
        )
        .expect("the second candidate");

        assert_eq!(path, simplified(dir.join("Cargo.toml")));
        assert_eq!(root_kind, ManifestKind::CargoToml);
    }

    /// A root that governs itself is reported as its own kind, which is what
    /// `self_governing` promises: the parser that accepted the text is the parser that
    /// then reads it. Reporting the descriptor's root kind instead would, for a kind
    /// whose ancestors are a different format, hand the caller a parser that returns
    /// `Err` — and an unparseable root declares nothing, so every inherited entry comes
    /// back unresolved rather than wrong.
    #[test]
    fn a_self_governing_root_is_reported_as_its_own_kind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir
            .path()
            .canonicalize()
            .expect("canonical")
            .join("Cargo.toml");
        let content = "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1\"\n";
        write(&manifest, content);

        let (_, root_kind, _) =
            workspace_root_of(&manifest, ManifestKind::CargoToml, content).expect("itself");
        assert_eq!(root_kind, ManifestKind::CargoToml);
    }

    /// The same boundary the lockfile search respects: an unrelated checkout above the
    /// repository must never lend its `[workspace.dependencies]`.
    #[test]
    fn the_workspace_search_stops_at_a_repository_boundary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"x\"]\n\n[workspace.dependencies]\nserde = \"1\"\n",
        );
        let member = root.join("repo/crates/app/Cargo.toml");
        let content = "[package]\nname = \"app\"\n";
        write(&member, content);
        std::fs::create_dir_all(root.join("repo/.git")).expect("mkdir .git");

        assert!(workspace_source(&member, ManifestKind::CargoToml, content).is_none());
    }

    #[test]
    fn a_standalone_crate_and_a_non_cargo_manifest_have_no_workspace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let solo = root.join("Cargo.toml");
        let content = "[package]\nname = \"solo\"\n";
        write(&solo, content);
        std::fs::create_dir_all(root.join(".git")).expect("mkdir .git");
        assert!(workspace_source(&solo, ManifestKind::CargoToml, content).is_none());

        // A `package.json` has no Cargo workspace whatever sits above it — and is
        // answered from its kind alone, without a walk.
        let js = root.join("web/package.json");
        write(&js, "{}");
        assert!(workspace_source(&js, ManifestKind::PackageJson, "{}").is_none());
    }

    /// Only the central declarations are on offer — a root's own `[dependencies]` are
    /// its own business.
    #[test]
    fn only_central_declarations_are_offered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\"]\n\n[workspace.dependencies]\nserde = \"1\"\n\n[dependencies]\ntokio = \"1\"\n",
        );
        let member = root.join("app/Cargo.toml");
        let content = "[package]\nname = \"app\"\n";
        write(&member, content);

        let (_, declarations) =
            workspace_source(&member, ManifestKind::CargoToml, content).expect("a root");

        let names: Vec<_> = declarations.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["serde"], "{declarations:?}");
    }

    #[test]
    fn reports_no_lockfile_for_kinds_that_have_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("requirements.txt");
        write(&manifest, "requests==2.0.0\n");

        assert!(find_lockfile(&manifest, ManifestKind::RequirementsTxt).is_none());
    }

    /// The failure this prevents: a Gradle project reporting nothing, or a handful
    /// of catalog entries, as though that were the whole dependency list.
    #[test]
    fn a_gradle_build_script_with_no_catalog_is_reported_unread() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join("app/build.gradle.kts"), "dependencies {}\n");

        let notices = manifest_notices(root, 3, |_| true);
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert_eq!(notices[0].path, root.join("app/build.gradle.kts"));
        assert!(
            notices[0].reason.contains("libs.versions.toml"),
            "{}",
            notices[0].reason
        );
    }

    /// A build script beside a catalog had its dependencies read from the catalog,
    /// so there is nothing missing to report.
    #[test]
    fn a_build_script_beside_a_catalog_is_not_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join("build.gradle.kts"), "dependencies {}\n");
        write(
            &root.join("gradle/libs.versions.toml"),
            "[versions]\nkotlin = \"1.9.24\"\n",
        );

        assert!(manifest_notices(root, 3, |_| true).is_empty());
    }

    /// A Gradle catalog is build-root scoped: one `<root>/gradle/libs.versions.toml`
    /// serves every subproject, and a subproject has no `gradle/` directory of its
    /// own. Resolving supersession in the containing directory therefore called
    /// every module of a *correctly* configured multi-module build unread, and told
    /// each of them to declare its dependencies in a catalog that already held them.
    #[test]
    fn a_multi_module_build_is_superseded_by_its_root_catalog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join(".git/HEAD"), "ref: refs/heads/main\n");
        write(&root.join("settings.gradle.kts"), "include(\":app\")\n");
        write(&root.join("build.gradle.kts"), "plugins {}\n");
        write(
            &root.join("gradle/libs.versions.toml"),
            "[versions]\nkotlin = \"1.9.24\"\n",
        );
        for module in ["app", "core", "data", "ui", "cli"] {
            write(
                &root.join(module).join("build.gradle.kts"),
                "dependencies {}\n",
            );
        }

        assert!(
            manifest_notices(root, 3, |_| true).is_empty(),
            "the catalog above every module is the one they all read"
        );
    }

    /// The walk up stops at the build root, so one build's catalog never speaks for
    /// a different build beside it.
    #[test]
    fn a_neighbouring_builds_catalog_supersedes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join(".git/HEAD"), "ref: refs/heads/main\n");
        write(&root.join("gradle/libs.versions.toml"), "[versions]\n");
        write(&root.join("other/settings.gradle"), "\n");
        write(&root.join("other/app/build.gradle"), "dependencies {}\n");

        let notices = manifest_notices(root, 3, |_| true);
        let paths: Vec<&Path> = notices.iter().map(|n| n.path.as_path()).collect();
        assert_eq!(
            paths,
            [root.join("other/app/build.gradle").as_path()],
            "`other/` is its own build and declares no catalog"
        );
    }

    /// The walk leaves the scanned tree for the build root that declares the scanned
    /// module, and for nothing else — so it stops one directory above `scan_root`.
    ///
    /// It used to stop only at a build root, a `.git`, or `/`, so in a checkout with
    /// no `.git` (a source tarball, a `git archive`, a vendored copy) it ran to the
    /// filesystem root once per unreadable file, adopting whatever it found on the
    /// way. Here the catalog is two levels up, behind a directory that declares
    /// nothing, and the walk never reaches it.
    #[test]
    fn the_walk_out_of_the_scanned_tree_stops_at_the_first_directory_that_declares_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let top = dir.path();
        write(&top.join("settings.gradle"), "include(\":app\")\n");
        write(&top.join("gradle/libs.versions.toml"), "[versions]\n");
        // `unrelated/` is neither a build root nor a declarer of subprojects.
        write(
            &top.join("unrelated/scanned/app/build.gradle"),
            "dependencies {}\n",
        );

        let scanned = top.join("unrelated/scanned");
        let notices = manifest_notices(&scanned, 3, |_| true);
        let paths: Vec<&Path> = notices.iter().map(|n| n.path.as_path()).collect();
        assert_eq!(
            paths,
            [scanned.join("app/build.gradle").as_path()],
            "the catalog is two directories above the one the user asked about"
        );
    }

    /// Scanning one module of a multi-module build — `dependable list <repo>/app`,
    /// or a CI matrix job per module — is a normal thing to ask for, and the
    /// `settings.gradle.kts` that declares the module is above the directory asked
    /// about by definition.
    ///
    /// Stopping the walk at the scanned directory therefore warned that
    /// `app/build.gradle.kts` could not be read and told the user to declare its
    /// dependencies in the catalog they already have. Scanning the repository root
    /// was silent, which is the same build answered two different ways.
    #[test]
    fn scanning_one_module_of_a_build_reads_its_root_catalog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join(".git/HEAD"), "ref: refs/heads/main\n");
        write(&root.join("settings.gradle.kts"), "include(\":app\")\n");
        write(
            &root.join("gradle/libs.versions.toml"),
            "[versions]\nkotlin = \"1.9.24\"\n",
        );
        write(&root.join("app/build.gradle.kts"), "dependencies {}\n");

        assert!(
            manifest_notices(root, 3, |_| true).is_empty(),
            "scanning the repository root is quiet"
        );
        let notices = manifest_notices(&root.join("app"), 3, |_| true);
        assert!(
            notices.is_empty(),
            "and scanning the module has the same catalog to read: {notices:?}"
        );
    }

    /// A catalog is a build root, but a build root is not automatically a *parent*:
    /// a single-project build declares no subprojects, so its catalog speaks for its
    /// own directory and nothing below it.
    #[test]
    fn a_single_project_catalog_does_not_answer_for_a_build_beside_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join(".git/HEAD"), "ref: refs/heads/main\n");
        // No `settings.gradle`: one project, at the root, with a catalog.
        write(&root.join("gradle/libs.versions.toml"), "[versions]\n");
        write(&root.join("build.gradle"), "dependencies {}\n");
        write(&root.join("tools/build.gradle"), "dependencies {}\n");

        let notices = manifest_notices(root, 3, |_| true);
        let paths: Vec<&Path> = notices.iter().map(|n| n.path.as_path()).collect();
        assert_eq!(
            paths,
            [root.join("tools/build.gradle").as_path()],
            "`tools/` is not a subproject of anything, and its dependencies are unread"
        );
    }

    /// A warning about an unread manifest is advice to enable something. Someone who
    /// turned the ecosystem off has already answered it.
    #[test]
    fn a_disabled_ecosystem_is_not_warned_about() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join(".git/HEAD"), "ref: refs/heads/main\n");
        write(&root.join("build.gradle.kts"), "dependencies {}\n");

        assert_eq!(manifest_notices(root, 3, |_| true).len(), 1);
        assert!(
            manifest_notices(root, 3, |eco| eco != Ecosystem::Jvm).is_empty(),
            "`[jvm] enabled = false` is an answer, not a question"
        );
    }

    /// Discovery reads each directory once for both answers, which is what stopped
    /// the notice scan from being a second full walk beside `find_manifests`.
    #[test]
    fn one_walk_answers_both_questions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join(".git/HEAD"), "ref: refs/heads/main\n");
        write(&root.join("Cargo.toml"), "[package]\nname = \"a\"\n");
        write(&root.join("app/build.gradle"), "dependencies {}\n");

        let found = discover(root, 3, |_| true);
        assert_eq!(found.manifests, vec![root.join("Cargo.toml")]);
        assert_eq!(
            found
                .notices
                .iter()
                .map(|n| n.path.clone())
                .collect::<Vec<_>>(),
            vec![root.join("app/build.gradle")]
        );
        assert_eq!(found.manifests, find_manifests(root, 3));
    }

    /// The same tree `find_manifests` sees: build output and vendored code are not
    /// somebody's project, and the depth bound is the one the user asked for.
    #[test]
    fn the_scan_skips_what_discovery_skips_and_stops_where_it_stops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(&root.join("build/tmp/build.gradle"), "\n");
        write(&root.join(".git/hooks/build.gradle"), "\n");
        write(&root.join("node_modules/x/build.gradle"), "\n");
        write(&root.join("a/b/c/build.gradle"), "\n");

        // `build/` is not in SKIP_DIRS, so only the dotted and vendored ones go.
        let deep = manifest_notices(root, 9, |_| true);
        let paths: Vec<&Path> = deep.iter().map(|n| n.path.as_path()).collect();
        assert!(paths.contains(&root.join("a/b/c/build.gradle").as_path()));
        assert!(!paths.contains(&root.join(".git/hooks/build.gradle").as_path()));
        assert!(!paths.contains(&root.join("node_modules/x/build.gradle").as_path()));

        let shallow = manifest_notices(root, 2, |_| true);
        assert!(
            !shallow
                .iter()
                .any(|n| n.path == root.join("a/b/c/build.gradle")),
            "depth 2 cannot reach a/b/c"
        );
    }
}
