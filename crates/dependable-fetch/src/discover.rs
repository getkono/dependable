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

use std::path::{Path, PathBuf};

use dependable_core::{LockfileData, LockfileKind, ManifestKind, parse_lockfile_kind};

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
    fn reports_no_lockfile_for_kinds_that_have_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("requirements.txt");
        write(&manifest, "requests==2.0.0\n");

        assert!(find_lockfile(&manifest, ManifestKind::RequirementsTxt).is_none());
    }
}
