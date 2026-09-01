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
];

/// Whether `version` looks like a pre-release / unstable version for `ecosystem`.
///
/// A version that parses as semver answers for itself — that is the definition, and it
/// is exact in both directions. The substring test alone was wrong both ways:
/// `1.0.0-M1` and `1.0.0-unstable.3` are pre-releases carrying no listed marker, and
/// `1.2.3+build-rc` is a *stable* release whose build metadata happens to contain one.
///
/// The marker list is the fallback for the many ecosystem versions that are *not*
/// semver (PEP 440, NuGet's four-part versions, Go's `v` prefix), where a substring is
/// the best available signal, plus Python's implicit forms (`1.0a1`, `1.0b2`, `1.0rc1`).
///
/// The JVM needs both exceptions. Maven separates a qualifier with a dot as readily as
/// with a hyphen (`6.0.0.M1`, `8.0.0.Beta1`, `5.3.0.RC1`) and abbreviates the word
/// (`2.0-M1`, `2.0-CR1`, `2.0-a1`), none of which the marker list spells, so
/// [`maven::is_prerelease`](crate::semver::maven::is_prerelease) is consulted; and it
/// treats a trailing word as a build variant rather than a preview, so `32.1.3-android`
/// — which *is* semver with a pre-release segment — is a release, and the semver
/// reading is skipped there. Before both, the default `Exclude` filter offered a beta
/// as the latest stable release.
#[must_use]
pub fn is_prerelease(version: &str, ecosystem: Ecosystem) -> bool {
    // The semver reading is skipped for the JVM: `32.1.3-android` parses as semver with
    // a pre-release segment, but under Maven's order that trailing word is a build
    // variant of a release. Maven's tokenizer, consulted below, is the authority there.
    if !matches!(ecosystem, Ecosystem::Jvm)
        && let Ok(parsed) = ::semver::Version::parse(version.trim_start_matches('v'))
    {
        return !parsed.pre.is_empty();
    }
    let lower = version.to_ascii_lowercase();
    if UNIVERSAL_PRERELEASE.iter().any(|m| lower.contains(m)) {
        return true;
    }
    match ecosystem {
        Ecosystem::Python => {
            PYTHON_PRERELEASE.iter().any(|m| lower.contains(m))
                || python_implicit_prerelease(&lower)
        }
        // Maven's qualifiers are tokens, not suffixes, so they are recognized by the
        // tokenizer that already models Maven's order rather than by substring — which
        // would read `9.4.51.v20230217` (a dated build of a release) as unstable.
        Ecosystem::Jvm => crate::semver::maven::is_prerelease(version),
        _ => false,
    }
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
/// understands Cargo's syntax (`1`, `1.2`, `^1.2.3`, `=1.0.0`, `>=1, <2`). We trim
/// whitespace and strip a leading `v`/`V` before a digit (Go's `v1.2.3`, some PHP
/// tags), which `semver::VersionReq` would otherwise reject. Ecosystems with
/// richer dialects (e.g. PEP 440) translate in dedicated modules.
#[must_use]
pub fn normalize_constraint(constraint: &str) -> String {
    let trimmed = constraint.trim();
    match trimmed.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest.to_string(),
        _ => trimmed.to_string(),
    }
}

/// Convert a constraint into a `semver::VersionReq`-compatible string for the
/// given ecosystem. Python uses PEP 440 translation; every other ecosystem is
/// already semver-compatible and only needs [`normalize_constraint`].
#[must_use]
pub fn to_semver_constraint(constraint: &str, ecosystem: Ecosystem) -> String {
    match ecosystem {
        Ecosystem::Python => crate::semver::python::pep440_constraint_to_semver(constraint),
        Ecosystem::CSharp => crate::semver::nuget::nuget_constraint_to_semver(constraint),
        Ecosystem::Elixir => crate::semver::elixir::hex_constraint_to_semver(constraint),
        Ecosystem::Jvm => crate::semver::maven::maven_constraint_to_semver(constraint),
        _ => normalize_constraint(constraint),
    }
}

/// Convert a constraint for `semver`, or `None` when the ecosystem's dialect could
/// not be expressed as a `semver::VersionReq`.
///
/// Three of the four translators signal failure by dropping everything they could
/// not read: [`maven_constraint_to_semver`](crate::semver::maven::maven_constraint_to_semver)
/// and [`nuget_constraint_to_semver`](crate::semver::nuget::nuget_constraint_to_semver)
/// return an empty string for an unreadable version or a malformed interval, and
/// [`pep440_constraint_to_semver`](crate::semver::python::pep440_constraint_to_semver)
/// does the same once every clause has been dropped. An empty result is therefore
/// ambiguous on its own: it means "the author declared no constraint" *and* "we
/// could not read the constraint the author declared", and the checker treating the
/// second as the first turned it into `*` — which resolves to the newest release and
/// reports `up to date`, the one answer a constraint that was never understood must
/// not give.
///
/// The two are told apart by what went in: an empty result from a **non-empty**
/// input is a failed translation, and nothing else produces one.
#[must_use]
pub fn try_to_semver_constraint(constraint: &str, ecosystem: Ecosystem) -> Option<String> {
    let translated = to_semver_constraint(constraint, ecosystem);
    if translated.trim().is_empty() && !constraint.trim().is_empty() {
        return None;
    }
    Some(translated)
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

    #[test]
    fn strips_leading_v_from_constraint() {
        assert_eq!(normalize_constraint("v1.2.3"), "1.2.3");
        assert_eq!(normalize_constraint("V2.0"), "2.0");
        // A `v` not before a digit (or part of an operator constraint) is kept.
        assert_eq!(normalize_constraint("^1.0"), "^1.0");
        assert_eq!(normalize_constraint(">=1, <2"), ">=1, <2");
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
        for v in ["1.0a1", "1.0b2", "1.0rc1", "1.0.dev3"] {
            assert!(is_prerelease(v, Ecosystem::Python), "{v}");
        }
        // The `[ab]\d` rule must not fire on non-Python ecosystems.
        assert!(!is_prerelease("1.0a1", Ecosystem::Rust));
        // A bare stable version is never a pre-release.
        assert!(!is_prerelease("1.0.0", Ecosystem::Python));
    }

    /// PEP 440 orders `1.0 < 1.0.post1`: a post-release is a *later* release of the same
    /// version, not a preview of it. Treating it as unstable hid it from the default
    /// filter, so a project on `1.0` was told it was current.
    #[test]
    fn a_python_post_release_is_not_a_prerelease() {
        for v in ["1.0.post1", "1.0.post2", "2.1.post0"] {
            assert!(!is_prerelease(v, Ecosystem::Python), "{v}");
        }
        // A post-release of a pre-release is still a pre-release.
        assert!(is_prerelease("1.0rc1.post1", Ecosystem::Python));
    }

    /// The old substring test was wrong in both directions, and each direction cost
    /// something: a missed pre-release is recommended as an upgrade, and a stable
    /// release whose build metadata happens to read `-rc` is hidden from one.
    #[test]
    fn semver_versions_are_classified_by_parsing_not_by_substring() {
        for v in [
            "1.0.0-M1",
            "1.0.0-CR2",
            "1.0.0-unstable.3",
            "1.0.0-0",
            "4.0.0-insiders",
        ] {
            assert!(is_prerelease(v, Ecosystem::Rust), "{v}");
        }
        for v in ["1.2.3+build-rc", "1.2.3+alpha", "1.0.0", "10.20.30"] {
            assert!(!is_prerelease(v, Ecosystem::Rust), "{v}");
        }
    }

    /// The marker list is hyphen-prefixed; Maven's qualifiers are not. Under the
    /// default `Exclude` filter this offered `8.0.0.Beta1` as Hibernate's latest
    /// release and `7.1.0.M1` as Spring's.
    #[test]
    fn jvm_specific_prereleases() {
        for v in ["6.0.0.M1", "8.0.0.Beta1", "5.3.0.RC1", "2.0-M1", "2.0-a1"] {
            assert!(is_prerelease(v, Ecosystem::Jvm), "{v}");
            // Nothing in the universal list matches these, which is the defect.
            assert!(!is_prerelease(v, Ecosystem::Rust), "{v}");
        }
        // `-SNAPSHOT` is the one form the universal list already covered.
        assert!(is_prerelease("1.0-SNAPSHOT", Ecosystem::Jvm));
        for v in [
            "6.4.4.Final",
            "5.3.9.RELEASE",
            "9.4.51.v20230217",
            "32.1.3-android",
        ] {
            assert!(!is_prerelease(v, Ecosystem::Jvm), "{v}");
        }
    }

    /// Under the default filter, the newest *release* is what a JVM project is
    /// offered — the whole list is not thrown away just because a beta tops it.
    #[test]
    fn the_default_filter_keeps_a_jvm_release_over_a_beta() {
        let out = UnstableFilter::Exclude.filter(
            &vers(&["8.0.0.Beta1", "6.6.0.Final", "6.4.4.Final"]),
            Some("6.4.4.Final"),
            Ecosystem::Jvm,
        );
        assert_eq!(out, vers(&["6.6.0.Final", "6.4.4.Final"]));
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
