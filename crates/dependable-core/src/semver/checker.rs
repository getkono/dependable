//! Classify a dependency against the set of available versions.

use ::semver::{Version, VersionReq};

use super::normalize::normalize_constraint;
use crate::result::DependencyStatus;

/// The outcome of evaluating one constraint against a set of available versions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Evaluation {
    /// The classified status.
    pub status: DependencyStatus,
    /// Best version satisfying the declared constraint.
    pub latest_compatible: Option<String>,
    /// Absolute latest available version (may be outside the constraint).
    pub latest_available: Option<String>,
    /// Whether a patch-level update exists within the constraint.
    pub patch_available: bool,
}

/// Parse a version-requirement string into a [`semver::VersionReq`].
///
/// # Errors
/// Returns an error if the (normalized) constraint is not a valid requirement.
pub fn to_version_req(constraint: &str) -> Result<VersionReq, ::semver::Error> {
    VersionReq::parse(&normalize_constraint(constraint))
}

/// Whether `constraint` is an npm dist-tag that tracks the newest release
/// (currently just `latest`) rather than a version range.
fn is_latest_tag(constraint: &str) -> bool {
    constraint.trim() == "latest"
}

/// Classify a dependency.
///
/// `versions` may be in any order; `locked_at` is the resolved version from a
/// lockfile if known. Without a lockfile, the effective "current" version is the
/// best version the constraint already allows. Vulnerability status is layered on
/// by the caller after querying OSV.
#[must_use]
pub fn check_version(constraint: &str, versions: &[String], locked_at: Option<&str>) -> Evaluation {
    let mut parsed: Vec<Version> = versions
        .iter()
        .filter_map(|v| Version::parse(v).ok())
        .collect();
    parsed.sort();
    parsed.dedup();

    let Some(latest_available) = parsed.last().cloned() else {
        return Evaluation {
            status: DependencyStatus::Error("no parseable versions".to_string()),
            latest_compatible: None,
            latest_available: None,
            patch_available: false,
        };
    };

    // An npm dist-tag such as `latest` isn't a version range; treat it as `*` so
    // it resolves to the newest available release (D8) rather than failing to
    // parse and being misreported. `--fix` still never rewrites the tag (see the
    // fix layer), so the manifest keeps tracking the channel.
    let req = match to_version_req(constraint) {
        Ok(req) => Some(req),
        Err(_) if is_latest_tag(constraint) => Some(VersionReq::STAR),
        Err(_) => None,
    };
    let latest_compatible = req
        .as_ref()
        .and_then(|r| parsed.iter().rev().find(|v| r.matches(v)).cloned());
    let locked = locked_at.and_then(|s| Version::parse(s).ok());

    // A locked version that no longer satisfies the declared constraint.
    if let (Some(req), Some(locked)) = (req.as_ref(), locked.as_ref()) {
        if !req.matches(locked) {
            return Evaluation {
                status: DependencyStatus::Outdated,
                latest_compatible: latest_compatible.map(|v| v.to_string()),
                latest_available: Some(latest_available.to_string()),
                patch_available: false,
            };
        }
    }

    let current = locked.clone().or_else(|| latest_compatible.clone());

    let status = match current.as_ref() {
        // Nothing the constraint allows is available at all.
        None => DependencyStatus::UpdateAvailable,
        Some(cur) if *cur >= latest_available => DependencyStatus::UpToDate,
        Some(cur) => match latest_compatible.as_ref() {
            Some(lc) if lc > cur && lc.major == cur.major && lc.minor == cur.minor => {
                DependencyStatus::PatchAvailable
            }
            _ => DependencyStatus::UpdateAvailable,
        },
    };

    let patch_available = status == DependencyStatus::PatchAvailable;

    Evaluation {
        status,
        latest_compatible: latest_compatible.map(|v| v.to_string()),
        latest_available: Some(latest_available.to_string()),
        patch_available,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn up_to_date_when_constraint_allows_latest() {
        let e = check_version("1", &vers(&["1.0.0", "1.2.0", "1.5.0"]), None);
        assert_eq!(e.status, DependencyStatus::UpToDate);
        assert_eq!(e.latest_available.as_deref(), Some("1.5.0"));
    }

    #[test]
    fn patch_available_within_constraint() {
        let e = check_version("^1.4", &vers(&["1.4.0", "1.4.8", "1.4.9"]), Some("1.4.8"));
        assert_eq!(e.status, DependencyStatus::PatchAvailable);
        assert!(e.patch_available);
        assert_eq!(e.latest_compatible.as_deref(), Some("1.4.9"));
    }

    #[test]
    fn update_available_for_minor_bump() {
        let e = check_version("^1.0", &vers(&["1.0.0", "1.2.0", "1.5.0"]), Some("1.2.0"));
        assert_eq!(e.status, DependencyStatus::UpdateAvailable);
    }

    #[test]
    fn outdated_when_locked_violates_constraint() {
        let e = check_version("=1.2.0", &vers(&["1.1.0", "1.2.0"]), Some("1.1.0"));
        assert_eq!(e.status, DependencyStatus::Outdated);
    }

    #[test]
    fn pinned_with_newer_available_is_update() {
        let e = check_version("=1.2.0", &vers(&["1.2.0", "1.5.0"]), None);
        assert_eq!(e.status, DependencyStatus::UpdateAvailable);
    }

    #[test]
    fn unparseable_versions_yield_error() {
        let e = check_version("1", &vers(&["not-a-version"]), None);
        assert!(matches!(e.status, DependencyStatus::Error(_)));
    }

    #[test]
    fn latest_dist_tag_resolves_to_newest_and_is_up_to_date() {
        // `latest` tracks the channel: resolve it to the newest release and report
        // up-to-date, instead of failing to parse as a version requirement.
        let e = check_version("latest", &vers(&["1.0.0", "2.3.0", "2.1.0"]), None);
        assert_eq!(e.status, DependencyStatus::UpToDate);
        assert_eq!(e.latest_compatible.as_deref(), Some("2.3.0"));
        assert_eq!(e.latest_available.as_deref(), Some("2.3.0"));
    }

    #[test]
    fn latest_dist_tag_with_older_lockfile_is_update_available() {
        // With a lockfile pinned behind the newest release, a re-install would bump
        // it, so `latest` surfaces as an available update (resolved to the newest).
        let e = check_version("latest", &vers(&["1.0.0", "2.3.0"]), Some("1.0.0"));
        assert_eq!(e.status, DependencyStatus::UpdateAvailable);
        assert_eq!(e.latest_compatible.as_deref(), Some("2.3.0"));
    }

    #[test]
    fn latest_dist_tag_with_no_versions_still_errors() {
        let e = check_version("latest", &vers(&["not-a-version"]), None);
        assert!(matches!(e.status, DependencyStatus::Error(_)));
    }
}
