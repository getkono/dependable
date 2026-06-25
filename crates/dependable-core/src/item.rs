//! The fundamental dependency unit as it appears in a manifest.

/// A single dependency as declared in a manifest.
///
/// Carries the byte position of the version *value* so the CLI can rewrite it in
/// place during `--fix` without disturbing surrounding formatting or comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Package name as declared in the manifest.
    pub name: String,
    /// Version constraint exactly as written (e.g. `"^1.2.3"`, `"=1.0.0"`).
    pub version_constraint: String,
    /// Source qualifier; non-registry sources are skipped for version checks.
    pub source: PackageSource,
    /// Zero-indexed line where the version value starts.
    pub version_line: usize,
    /// Byte offset of the version value start within that line (no quotes).
    pub version_col_start: usize,
    /// Byte offset of the version value end within that line (exclusive).
    pub version_col_end: usize,
    /// Alternate registry alias (Rust `registry = "..."`).
    pub registry: Option<String>,
    /// Resolved locked version from a lockfile, if available.
    pub locked_version: Option<String>,
}

impl Item {
    /// Whether the constraint pins an exact version (`=1.2.3`, not `==`), which
    /// excludes it from a blanket `--update-all`.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        let c = self.version_constraint.trim_start();
        c.starts_with('=') && !c.starts_with("==")
    }

    /// Whether this item should be fetched + version-checked. Local and git
    /// sources are skipped.
    #[must_use]
    pub fn is_checkable(&self) -> bool {
        matches!(self.source, PackageSource::Registry | PackageSource::Jsr)
    }
}

/// Where a dependency comes from. Determines whether it is version-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PackageSource {
    /// A normal registry package (the default).
    #[default]
    Registry,
    /// A JSR-hosted package (unused in V1).
    Jsr,
    /// A `path`/`workspace` dependency — skipped for version checks.
    Local,
    /// A git dependency — skipped for version checks.
    Git,
}
