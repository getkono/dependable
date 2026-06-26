//! Version / constraint normalization helpers and pre-release filtering.

use crate::ecosystem::Ecosystem;

/// How to treat pre-release / unstable versions when deciding what is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum UnstableFilter {
    /// Hide pre-releases (default).
    #[default]
    Exclude,
    /// Always consider pre-releases.
    IncludeAlways,
    /// Consider pre-releases only when the current version is itself a pre-release.
    IncludeIfCurrent,
}

impl UnstableFilter {
    /// Filter a candidate `versions` list according to this mode.
    ///
    /// `current` is the dependency's current version (its locked version, or its
    /// constraint when no lockfile is present) — used only by
    /// [`UnstableFilter::IncludeIfCurrent`]. If filtering would remove every
    /// candidate, the original list is returned unchanged so a pre-release-only
    /// package still resolves.
    #[must_use]
    pub fn filter(
        self,
        versions: &[String],
        current: Option<&str>,
        ecosystem: Ecosystem,
    ) -> Vec<String> {
        let keep_prereleases = match self {
            UnstableFilter::IncludeAlways => true,
            UnstableFilter::Exclude => false,
            UnstableFilter::IncludeIfCurrent => {
                current.is_some_and(|c| is_prerelease(c, ecosystem))
            }
        };
        if keep_prereleases {
            return versions.to_vec();
        }
        let stable: Vec<String> = versions
            .iter()
            .filter(|v| !is_prerelease(v, ecosystem))
            .cloned()
            .collect();
        if stable.is_empty() {
            versions.to_vec()
        } else {
            stable
        }
    }
}

/// Universal (case-insensitive) pre-release markers checked for every ecosystem.
const UNIVERSAL_PRERELEASE: &[&str] = &[
    "-alpha",
    "-beta",
    "-rc",
    "-snapshot",
    "-dev",
    "-preview",
    "-experimental",
    "-canary",
    "-pre",
    "-next",
    "-nightly",
    "-nullsafety",
    "-nnbd",
];

/// Additional dot-prefixed markers Python (PEP 440) uses.
const PYTHON_PRERELEASE: &[&str] = &[
    ".alpha",
    ".beta",
    ".rc",
    ".dev",
    ".snapshot",
    ".preview",
    ".experimental",
    ".canary",
    ".pre",
    ".post",
];

/// Whether `version` looks like a pre-release / unstable version for `ecosystem`.
///
/// Uses a case-insensitive substring match against a marker set, plus Python's
/// implicit forms (`1.0a1`, `1.0b2`, `1.0rc1`).
#[must_use]
pub fn is_prerelease(version: &str, ecosystem: Ecosystem) -> bool {
    let lower = version.to_ascii_lowercase();
    if UNIVERSAL_PRERELEASE.iter().any(|m| lower.contains(m)) {
        return true;
    }
    if ecosystem == Ecosystem::Python {
        if PYTHON_PRERELEASE.iter().any(|m| lower.contains(m)) {
            return true;
        }
        if python_implicit_prerelease(&lower) {
            return true;
        }
    }
    false
}

/// Detect PEP 440 implicit pre-release segments: `a`/`b` followed by a digit, or
/// a `rc` segment adjacent to a digit (e.g. `1.0a1`, `1.0b2`, `1.0rc1`).
fn python_implicit_prerelease(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    for i in 0..bytes.len() {
        let c = bytes[i];
        if (c == b'a' || c == b'b') && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return true;
        }
        if c == b'r' && bytes.get(i + 1) == Some(&b'c') {
            let after_digit = bytes.get(i + 2).is_some_and(u8::is_ascii_digit);
            let before_digit = i > 0 && bytes[i - 1].is_ascii_digit();
            if after_digit || before_digit {
                return true;
            }
        }
    }
    false
}

/// Normalize a version requirement string into something `semver::VersionReq`
/// accepts.
///
/// For Rust this is largely a pass-through — the `semver` crate already
/// understands Cargo's syntax (`1`, `1.2`, `^1.2.3`, `=1.0.0`, `>=1, <2`) — so we
/// only trim surrounding whitespace. Other ecosystems will translate their own
/// constraint dialects in dedicated modules.
#[must_use]
pub fn normalize_constraint(constraint: &str) -> String {
    constraint.trim().to_string()
}

/// Convert a constraint into a `semver::VersionReq`-compatible string for the
/// given ecosystem. Python uses PEP 440 translation; every other ecosystem is
/// already semver-compatible and only needs [`normalize_constraint`].
#[must_use]
pub fn to_semver_constraint(constraint: &str, ecosystem: Ecosystem) -> String {
    match ecosystem {
        Ecosystem::Python => crate::semver::python::pep440_constraint_to_semver(constraint),
        _ => normalize_constraint(constraint),
    }
}

/// Normalize a concrete version string: strip a leading `v`/`V` and pad partial
/// versions (`1` → `1.0.0`, `1.2` → `1.2.0`) so they parse as `semver::Version`.
#[must_use]
pub fn normalize_version(version: &str) -> String {
    let trimmed = version.trim();
    let stripped = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    let core = stripped.split(['-', '+']).next().unwrap_or(stripped);
    let suffix = &stripped[core.len()..];
    match core.bytes().filter(|&b| b == b'.').count() {
        0 => format!("{core}.0.0{suffix}"),
        1 => format!("{core}.0{suffix}"),
        _ => stripped.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_partial_versions() {
        assert_eq!(normalize_version("1"), "1.0.0");
        assert_eq!(normalize_version("1.2"), "1.2.0");
        assert_eq!(normalize_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn strips_v_prefix() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("V2.0"), "2.0.0");
    }

    #[test]
    fn trims_constraint() {
        assert_eq!(normalize_constraint("  ^1.0 "), "^1.0");
    }

    fn vers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn universal_prerelease_markers() {
        for v in ["1.0.0-alpha", "1.0.0-RC1", "2.0.0-beta.3", "1.0.0-SNAPSHOT"] {
            assert!(is_prerelease(v, Ecosystem::Rust), "{v}");
        }
        assert!(!is_prerelease("1.0.0", Ecosystem::Rust));
        assert!(!is_prerelease("1.2.3+build.5", Ecosystem::Rust));
    }

    #[test]
    fn python_specific_prereleases() {
        for v in ["1.0a1", "1.0b2", "1.0rc1", "1.0.dev3", "1.0.post1"] {
            assert!(is_prerelease(v, Ecosystem::Python), "{v}");
        }
        // The `[ab]\d` rule must not fire on non-Python ecosystems.
        assert!(!is_prerelease("1.0a1", Ecosystem::Rust));
        // A bare stable version is never a pre-release.
        assert!(!is_prerelease("1.0.0", Ecosystem::Python));
    }

    #[test]
    fn filter_exclude_drops_prereleases() {
        let out = UnstableFilter::Exclude.filter(
            &vers(&["1.0.0", "1.1.0-rc1", "1.2.0"]),
            None,
            Ecosystem::Rust,
        );
        assert_eq!(out, vers(&["1.0.0", "1.2.0"]));
    }

    #[test]
    fn filter_include_always_keeps_everything() {
        let input = vers(&["1.0.0", "1.1.0-rc1"]);
        let out = UnstableFilter::IncludeAlways.filter(&input, None, Ecosystem::Rust);
        assert_eq!(out, input);
    }

    #[test]
    fn filter_if_current_depends_on_current() {
        let input = vers(&["1.0.0", "1.1.0-rc1"]);
        // Stable current → drop pre-releases.
        let stable =
            UnstableFilter::IncludeIfCurrent.filter(&input, Some("1.0.0"), Ecosystem::Rust);
        assert_eq!(stable, vers(&["1.0.0"]));
        // Pre-release current → keep them.
        let pre =
            UnstableFilter::IncludeIfCurrent.filter(&input, Some("1.0.0-rc1"), Ecosystem::Rust);
        assert_eq!(pre, input);
    }

    #[test]
    fn filter_falls_back_when_only_prereleases() {
        let input = vers(&["1.0.0-rc1", "1.0.0-rc2"]);
        let out = UnstableFilter::Exclude.filter(&input, None, Ecosystem::Rust);
        assert_eq!(out, input);
    }
}
