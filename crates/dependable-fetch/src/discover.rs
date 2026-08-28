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

    #[test]
    fn reports_no_lockfile_for_kinds_that_have_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("requirements.txt");
        write(&manifest, "requests==2.0.0\n");

        assert!(find_lockfile(&manifest, ManifestKind::RequirementsTxt).is_none());
    }
}
