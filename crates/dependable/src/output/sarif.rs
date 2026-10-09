//! SARIF v2.1.0 output — the adapter between the CLI's per-manifest reports and
//! [`dependable_report::sarif`], which owns the document itself.
//!
//! Everything interesting (the rule catalogue, the status → rule → level
//! mapping, URI relativization, fingerprints) lives in `dependable-report`, so
//! an IDE or CI integration linking that crate gets identical SARIF without
//! going through the binary. This module only reshapes the input and prints.

use std::path::{Path, PathBuf};

use dependable_report::{ManifestResults, Report};

use super::ManifestReport;

/// Render `reports` as a SARIF v2.1.0 log on stdout.
///
/// # Errors
/// Returns an error if the log cannot be serialized.
pub fn render(reports: &[ManifestReport]) -> anyhow::Result<()> {
    let mut report = Report::new(scan_root(reports));
    for manifest in reports {
        report.push(ManifestResults::new(
            manifest.path.clone(),
            manifest.ecosystem,
            manifest.results.clone(),
        ));
    }
    println!("{}", dependable_report::sarif::render(&report)?);
    Ok(())
}

/// The root SARIF paths are reported relative to, derived from the manifest
/// paths themselves.
///
/// `output::render` takes only the reports, so the scanned path is not available
/// here — and deriving it is enough:
///
/// 1. Every manifest path relative (the overwhelmingly common case: `check` was
///    given a relative path, or none at all) → `.`. Stripping `.` off
///    `./crates/app/Cargo.toml` yields `crates/app/Cargo.toml`, and a path with
///    no leading `./` falls through unchanged, which is already correct.
/// 2. Otherwise → the longest common ancestor of the manifests' directories.
/// 3. Nothing in common → the current directory, so URIs stay repo-relative
///    rather than absolute.
fn scan_root(reports: &[ManifestReport]) -> PathBuf {
    if reports.iter().all(|report| report.path.is_relative()) {
        return PathBuf::from(".");
    }
    let mut common: Option<PathBuf> = None;
    for report in reports {
        let parent = report.path.parent().unwrap_or_else(|| Path::new(""));
        common = Some(match common {
            None => parent.to_path_buf(),
            Some(current) => common_ancestor(&current, parent),
        });
    }
    common
        .filter(|root| root.components().next().is_some())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// The longest path that is a prefix of both `a` and `b`, component-wise.
/// Empty when they share nothing.
fn common_ancestor(a: &Path, b: &Path) -> PathBuf {
    let mut shared = PathBuf::new();
    for (left, right) in a.components().zip(b.components()) {
        if left != right {
            break;
        }
        shared.push(left.as_os_str());
    }
    shared
}

#[cfg(test)]
mod tests {
    use dependable_fetch::Ecosystem;

    use super::*;

    fn report(path: &str) -> ManifestReport {
        ManifestReport {
            integrity: crate::output::ScanIntegrity::default(),
            path: PathBuf::from(path),
            ecosystem: Ecosystem::Rust,
            results: Vec::new(),
            workspace_root: None,
        }
    }

    #[test]
    fn scan_root_is_dot_when_every_manifest_is_relative() {
        assert_eq!(
            scan_root(&[report("Cargo.toml"), report("./crates/app/Cargo.toml")]),
            PathBuf::from(".")
        );
        // No manifests at all is vacuously "all relative".
        assert_eq!(scan_root(&[]), PathBuf::from("."));
    }

    /// A root that is genuinely absolute on the platform the test runs on.
    ///
    /// `/repo` is *relative* on Windows — [`Path::is_absolute`] there wants a
    /// drive or UNC prefix — so a Unix-only fixture sends [`scan_root`] down its
    /// all-relative early return and asserts nothing about the branch under
    /// test. The production path is unaffected: a real Windows manifest path is
    /// `C:\...` and is absolute.
    #[cfg(windows)]
    const ABS_ROOT: &str = r"C:\repo";
    #[cfg(not(windows))]
    const ABS_ROOT: &str = "/repo";

    /// `ABS_ROOT` joined with a forward-slashed relative path. Windows accepts
    /// `/` as a separator and `Path` compares component-wise, so the mixed
    /// separators in `C:\repo/crates/app` are irrelevant to the assertions.
    fn abs(relative: &str) -> String {
        format!("{ABS_ROOT}/{relative}")
    }

    #[test]
    fn scan_root_is_the_common_ancestor_of_absolute_manifests() {
        assert_eq!(
            scan_root(&[
                report(&abs("Cargo.toml")),
                report(&abs("crates/app/Cargo.toml")),
                report(&abs("crates/lib/Cargo.toml")),
            ]),
            PathBuf::from(ABS_ROOT)
        );
        assert_eq!(
            scan_root(&[
                report(&abs("crates/app/Cargo.toml")),
                report(&abs("crates/lib/Cargo.toml")),
            ]),
            PathBuf::from(abs("crates"))
        );
    }

    #[test]
    fn common_ancestor_of_disjoint_paths_is_empty() {
        assert_eq!(
            common_ancestor(Path::new("crates/a"), Path::new("vendor/b")),
            PathBuf::new()
        );
    }
}
