//! Depth-limited manifest discovery.

use std::path::{Path, PathBuf};

use dependable_fetch::ManifestKind;

/// Directories never descended into during discovery.
const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "vendor"];

/// Find every recognized manifest under `root`, searching up to `max_depth`
/// directories deep, skipping build/vendor directories. Recognition is by
/// [`ManifestKind::detect`]; unsupported ecosystems are filtered later, not here.
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
                && (SKIP_DIRS.contains(&name) || name.starts_with('.'))
            {
                continue;
            }
            walk(&path, depth_left - 1, out);
        } else if ManifestKind::detect(&path).is_some() {
            out.push(path);
        }
    }
}
