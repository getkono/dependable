//! pub (`pubspec.yaml`) → semver constraint translation for Dart.
//!
//! pub's range syntax is close enough to Cargo's that the shared front-end
//! [`normalize_range_constraint`] reads every form of it — `^1.2.3`, `>=1.0.0
//! <2.0.0` with its comparators separated by a space, and `any` — with one
//! exception: a **bare** version. pub reads `foo: 6.0.5` as exactly `6.0.5` and
//! spells the caret range `^6.0.5`; Cargo and the shared front-end read the bare
//! form as the caret range. Left to the shared front-end, a pubspec pin was
//! reported satisfied by every later 6.x release and never reported as resolved.
//!
//! So the bare form is the one this module reads itself, and everything else goes
//! through the shared front-end unchanged.

use crate::semver::normalize::normalize_range_constraint;

/// Convert a pub version constraint into a `semver::VersionReq`-compatible string.
///
/// A bare version — one that parses as a complete `semver::Version`, which is the
/// only bare form pub accepts — becomes the exact comparator `=x.y.z`. Build
/// metadata is dropped from the comparator: `semver::VersionReq` does not accept it
/// there, and an exact comparator ignores it when matching, so `6.0.5+1` translates
/// to `=6.0.5`. Every other spelling (`^`, `>=`, `<`, a space-separated range,
/// `any`) is handed to [`normalize_range_constraint`] exactly as before.
///
/// Pure: consults no registry, filesystem, or network.
///
/// # Examples
/// ```
/// use dependable_core::semver::dart::dart_constraint_to_semver;
///
/// assert_eq!(dart_constraint_to_semver("6.0.5"), "=6.0.5");
/// assert_eq!(dart_constraint_to_semver("^1.1.0"), "^1.1.0");
/// assert_eq!(dart_constraint_to_semver("any"), "*");
/// ```
#[must_use]
pub fn dart_constraint_to_semver(constraint: &str) -> String {
    let trimmed = constraint.trim();
    match ::semver::Version::parse(trimmed) {
        Ok(mut version) => {
            version.build = ::semver::BuildMetadata::EMPTY;
            format!("={version}")
        }
        Err(_) => normalize_range_constraint(constraint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::semver::{Version, VersionReq};

    fn admits(constraint: &str, version: &str) -> bool {
        VersionReq::parse(&dart_constraint_to_semver(constraint))
            .unwrap_or_else(|e| panic!("{constraint:?} must translate to a VersionReq: {e}"))
            .matches(&Version::parse(version).expect("a version"))
    }

    #[test]
    fn a_bare_version_is_exact() {
        assert_eq!(dart_constraint_to_semver("6.0.5"), "=6.0.5");
        assert_eq!(dart_constraint_to_semver("  6.0.5 "), "=6.0.5");
        assert!(admits("6.0.5", "6.0.5"));
        assert!(!admits("6.0.5", "6.0.6"));
        assert!(!admits("6.0.5", "6.1.0"));
    }

    #[test]
    fn a_bare_pre_release_is_exact_and_build_metadata_is_dropped() {
        assert_eq!(dart_constraint_to_semver("2.0.0-dev.1"), "=2.0.0-dev.1");
        assert!(admits("2.0.0-dev.1", "2.0.0-dev.1"));
        assert!(!admits("2.0.0-dev.1", "2.0.0"));
        assert_eq!(dart_constraint_to_semver("1.2.3+4"), "=1.2.3");
    }

    #[test]
    fn every_other_spelling_is_left_to_the_shared_front_end() {
        for constraint in [
            "^1.1.0",
            ">=1.0.0",
            "<2.0.0",
            ">=1.0.0 <2.0.0",
            "any",
            "",
            // pub rejects a partial bare version; it is not read as exact here.
            "1.2",
        ] {
            assert_eq!(
                dart_constraint_to_semver(constraint),
                normalize_range_constraint(constraint),
                "{constraint:?}"
            );
        }
        assert!(admits("^1.1.0", "1.9.0"));
        assert!(admits(">=1.0.0 <2.0.0", "1.5.0"));
        assert!(!admits(">=1.0.0 <2.0.0", "2.0.0"));
        assert!(admits("any", "9.9.9"));
    }
}
