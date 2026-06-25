//! Classify a dependency against the set of available versions.

use ::semver::{Version, VersionReq};

use super::normalize::normalize_constraint;
use crate::result::DependencyStatus;

/// The outcome of evaluating one constraint against a set of available versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub status: DependencyStatus,
    pub latest_compatible: Option<String>,
    pub latest_available: Option<String>,
    pub patch_available: bool,
}

/// Parse a version-requirement string into a [`semver::VersionReq`].
///
/// # Errors
/// Returns an error if the (normalized) constraint is not a valid requirement.
pub fn to_version_req(constraint: &str) -> Result<VersionReq, ::semver::Error> {
    VersionReq::parse(&normalize_constraint(constraint))
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

    let req = to_version_req(constraint).ok();
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
}
