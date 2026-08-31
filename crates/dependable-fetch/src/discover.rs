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
//! Locating a Cargo workspace root lives here too. It is the same upward walk as
//! [`find_lockfile`], answering the same shape of question — "which file above this one
//! governs it" — and, like a lockfile, what it finds has to be read and parsed before it
//! is useful. Reading it is IO; what to *do* with the result is
//! [`dependable_core::resolve_workspace_inheritance`], which stays pure.

use std::path::{Path, PathBuf};

use dependable_core::{
    DependencyKind, Item, LockfileData, LockfileKind, ManifestKind, WorkspaceDecl, parse,
    parse_lockfile_kind, parse_workspace,
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
#[must_use]
pub fn find_manifests(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, max_depth, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, depth_left: usize, out: &mut Vec<PathBuf>) {
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
            walk(&path, depth_left - 1, out);
        } else if ManifestKind::detect(&path).is_some() {
            out.push(path);
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

/// The nearest `Cargo.toml` declaring a `[workspace]` at or above `manifest`, with its
/// path and content.
///
/// `manifest` itself is excluded, so a member always resolves against a root *above* it.
/// A root that is also a package declares its own `[package]` values literally, and
/// [`workspace_source`] is what handles it inheriting from its own table. The walk stops
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
pub fn nearest_workspace_root(manifest: &Path) -> Option<(PathBuf, WorkspaceDecl, String)> {
    let manifest = std::fs::canonicalize(manifest).ok()?;
    let mut dir = manifest.parent()?;
    loop {
        let candidate = dir.join("Cargo.toml");
        if !same_file(&candidate, &manifest)
            && let Ok(content) = std::fs::read_to_string(&candidate)
            && let Some(workspace) = parse_workspace(&content)
        {
            return Some((simplified(candidate), workspace, content));
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// The manifest whose `[workspace.dependencies]` govern `manifest`, and its text.
///
/// A manifest declaring its own `[workspace]` governs **itself**: Cargo lets a root that
/// is also a package write `serde.workspace = true` against its own table, and walking
/// past it would leave those entries unresolved. Otherwise the nearest ancestor root
/// governs. `content` is the manifest's own text, already in the caller's hand, so the
/// self case costs no extra read.
///
/// Separate from [`workspace_declarations`] so a caller checking many members of one
/// workspace can key a cache on the root's path and parse it only once; use
/// [`workspace_source`] when that does not matter.
///
/// Returns `None` for a non-Cargo manifest and when no root is found.
#[must_use]
pub fn workspace_root_of(
    manifest: &Path,
    kind: ManifestKind,
    content: &str,
) -> Option<(PathBuf, String)> {
    if kind != ManifestKind::CargoToml {
        return None;
    }
    if parse_workspace(content).is_some() {
        // Canonical, to match the shape [`nearest_workspace_root`] returns.
        let root = std::fs::canonicalize(manifest)
            .map(simplified)
            .unwrap_or_else(|_| manifest.to_path_buf());
        return Some((root, content.to_owned()));
    }
    let (root, _, root_content) = nearest_workspace_root(manifest)?;
    Some((root, root_content))
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
    let (root, root_content) = workspace_root_of(manifest, kind, content)?;
    Some((root, workspace_declarations(&root_content)))
}

/// The `[workspace.dependencies]` entries of one parsed Cargo manifest.
///
/// A manifest that will not parse declares nothing, which is the same answer as a
/// manifest with no such table — neither is worth failing a whole check over.
#[must_use]
pub fn workspace_declarations(content: &str) -> Vec<Item> {
    parse(ManifestKind::CargoToml, content)
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

/// A lockfile beside a manifest that exists but yields nothing.
///
/// Every such case used to be a silent drop — an unreadable candidate was
/// discarded by `if let Ok(...)` and the walk carried on, so a project with a
/// lockfile it could not use was indistinguishable from one with none. That is
/// the state a user is most able to act on, and the one they were never told
/// about.
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

        assert_eq!(found, root.join("Cargo.toml"));
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

        assert_eq!(found, manifest);
        assert_eq!(declarations.len(), 1, "{declarations:?}");
        assert_eq!(declarations[0].name, "serde");
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
}
