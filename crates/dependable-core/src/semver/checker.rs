//! Classify a dependency against the set of available versions.

use ::semver::{Version, VersionReq};

use super::normalize::{normalize_constraint, try_to_semver_constraint};
use crate::ecosystem::Ecosystem;
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

/// Classify a dependency whose constraint is written in `ecosystem`'s dialect.
///
/// The wrapper [`check_version`] cannot see the difference between an author who
/// declared no constraint and a constraint this crate failed to translate, because
/// the failing translators hand it the same empty string for both — so an
/// untranslatable range became `*`, resolved to the newest release, and reported
/// `up to date`. Translating here keeps that distinction: a failed translation is
/// [`DependencyStatus::Undetermined`], which claims nothing about currency.
#[must_use]
pub fn check_version_for(
    constraint: &str,
    ecosystem: Ecosystem,
    versions: &[String],
    locked_at: Option<&str>,
) -> Evaluation {
    match try_to_semver_constraint(constraint, ecosystem) {
        Some(translated) => check_version(&translated, versions, locked_at),
        None => Evaluation {
            status: DependencyStatus::Undetermined,
            latest_compatible: None,
            latest_available: newest(versions).map(|v| v.to_string()),
            patch_available: false,
        },
    }
}

/// The newest parseable version in `versions`, if any.
fn newest(versions: &[String]) -> Option<Version> {
    versions.iter().filter_map(|v| Version::parse(v).ok()).max()
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
        Ok(req) => req,
        // An absent requirement means "any version" — a bare `numpy` in a requirements
        // file, or a manifest entry that names no range. `VersionReq` rejects the empty
        // string, so the intent has to be spelled out.
        Err(_) if constraint.trim().is_empty() => VersionReq::STAR,
        Err(_) if is_latest_tag(constraint) => VersionReq::STAR,
        // A constraint we cannot read is not an upgrade recommendation. It used to fall
        // through as `UpdateAvailable`, which reads as "a newer version is waiting for
        // you" — the one message a dependency whose requirement was never understood
        // must not send. npm-native ranges the `semver` crate has no dialect for
        // (`^1 || ^2`, `>=1.0.0 <2.0.0`) land here. Wildcards do not: `1.x` and `1.*`
        // are requirements the crate parses, so they stay real evaluations and reach
        // the fix layer, where the wildcard guard declines to pin them.
        Err(e) => {
            return Evaluation {
                status: DependencyStatus::Error(format!("unparseable constraint: {e}")),
                latest_compatible: None,
                latest_available: Some(latest_available.to_string()),
                patch_available: false,
            };
        }
    };
    let latest_compatible = parsed.iter().rev().find(|v| req.matches(v)).cloned();
    let locked = locked_at.and_then(|s| Version::parse(s).ok());

    // A locked version that no longer satisfies the declared constraint.
    if let Some(locked) = locked.as_ref()
        && !req.matches(locked)
    {
        return Evaluation {
            status: DependencyStatus::Outdated,
            latest_compatible: latest_compatible.map(|v| v.to_string()),
            latest_available: Some(latest_available.to_string()),
            patch_available: false,
        };
    }

    let current = locked.clone().or_else(|| latest_compatible.clone());

    let status = match current.as_ref() {
        // Nothing the constraint allows is available at all.
        None => DependencyStatus::UpdateAvailable,
        Some(cur) if *cur >= latest_available => DependencyStatus::UpToDate,
        Some(cur) => match latest_compatible.as_ref() {
            // Under semver's 0.x rules the leftmost non-zero component is the breaking
            // axis, so on `0.0.z` every bump is breaking and nothing there is a patch.
            // Calling it one would hand `--fix` a green light it has not earned.
            Some(lc)
                if lc > cur
                    && lc.major == cur.major
                    && lc.minor == cur.minor
                    && !(cur.major == 0 && cur.minor == 0) =>
            {
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

    /// A constraint whose dialect did not translate must not be reported as current.
    ///
    /// Maven, NuGet, and PEP 440 all signal a failed translation by returning the empty
    /// string, which the checker read as "no constraint declared" and turned into `*` —
    /// so `latest_compatible` became the newest release and the status became
    /// `UpToDate`, disarming `--fail-on outdated` at every ecosystem that translates.
    /// One case per affected ecosystem, each taken from a manifest that parses.
    #[test]
    fn an_untranslatable_constraint_is_undetermined_not_up_to_date() {
        // A Gradle version catalog with an unclosed Maven interval.
        let jvm = check_version_for(
            "[4.0,4.9",
            Ecosystem::Jvm,
            &vers(&["4.0.0", "4.9.0", "5.5.0"]),
            None,
        );
        assert_eq!(jvm.status, DependencyStatus::Undetermined, "{jvm:?}");
        assert_eq!(jvm.latest_compatible, None);
        assert_eq!(jvm.latest_available.as_deref(), Some("5.5.0"));

        // Maven's `LATEST` keyword, which is a version *selector*, not a range.
        let latest_keyword =
            check_version_for("LATEST", Ecosystem::Jvm, &vers(&["2.10.0", "2.14.0"]), None);
        assert_eq!(latest_keyword.status, DependencyStatus::Undetermined);

        // A NuGet interval missing its closing bracket. The newest release is *outside*
        // the range the author meant, so `UpToDate` here was actively wrong.
        let nuget = check_version_for(
            "[12.0.0,13.0.0",
            Ecosystem::CSharp,
            &vers(&["12.0.3", "13.0.4"]),
            None,
        );
        assert_eq!(nuget.status, DependencyStatus::Undetermined, "{nuget:?}");

        // PEP 440 `!=`, which has no `semver::VersionReq` spelling, so every clause is
        // dropped and nothing is left to compare against.
        let python = check_version_for(
            "!=2.31.0",
            Ecosystem::Python,
            &vers(&["2.31.0", "2.34.2"]),
            None,
        );
        assert_eq!(python.status, DependencyStatus::Undetermined, "{python:?}");
    }

    /// The other half of the same distinction: an author who declared *no* constraint
    /// still means "any version", and must keep evaluating as `*` rather than becoming
    /// undetermined.
    #[test]
    fn an_absent_constraint_still_means_any_version() {
        for ecosystem in [
            Ecosystem::Python,
            Ecosystem::CSharp,
            Ecosystem::Jvm,
            Ecosystem::Elixir,
            Ecosystem::Rust,
        ] {
            let e = check_version_for("", ecosystem, &vers(&["1.0.0", "2.0.0"]), Some("2.0.0"));
            assert_eq!(e.status, DependencyStatus::UpToDate, "{ecosystem:?}: {e:?}");
            assert_eq!(e.latest_compatible.as_deref(), Some("2.0.0"));
        }
    }

    /// A constraint the ecosystem *can* translate keeps its real evaluation, so the
    /// guard above is not simply refusing to answer.
    #[test]
    fn a_translatable_constraint_is_still_evaluated() {
        let e = check_version_for(
            "[1.0,2.0)",
            Ecosystem::Jvm,
            &vers(&["1.0.0", "1.9.0", "2.5.0"]),
            None,
        );
        assert_eq!(e.status, DependencyStatus::UpdateAvailable, "{e:?}");
        assert_eq!(e.latest_compatible.as_deref(), Some("1.9.0"));
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

    /// A requirement nobody could parse is not an upgrade recommendation. npm-native
    /// ranges reach the Rust `semver` crate untranslated, and every one of them used to
    /// come back as `UpdateAvailable` — indistinguishable from a real available upgrade.
    #[test]
    fn an_unparseable_constraint_is_an_error_not_an_upgrade() {
        let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        for constraint in [
            "^1 || ^2",
            ">=1.0.0 <2.0.0",
            "next",
            "not-a-range",
            "workspace:^",
        ] {
            let ev = check_version(constraint, &versions, None);
            assert!(
                matches!(ev.status, DependencyStatus::Error(_)),
                "{constraint} yielded {:?}",
                ev.status
            );
            assert!(ev.latest_compatible.is_none(), "{constraint}");
            // The registry answered, so what it said is still worth reporting.
            assert_eq!(
                ev.latest_available.as_deref(),
                Some("2.0.0"),
                "{constraint}"
            );
        }
    }

    /// An empty constraint is `*`, not an error — a bare `numpy` in a requirements file
    /// is a legitimate declaration and must keep resolving.
    #[test]
    fn an_empty_constraint_still_resolves() {
        let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        let ev = check_version("", &versions, None);
        assert!(
            !matches!(ev.status, DependencyStatus::Error(_)),
            "{:?}",
            ev.status
        );
        assert_eq!(ev.latest_compatible.as_deref(), Some("2.0.0"));
    }

    /// Under semver's 0.x rules the leftmost non-zero component is the breaking axis, so
    /// on `0.0.z` there is no compatible axis left and nothing is a patch.
    #[test]
    fn zero_zero_versions_have_no_patch_axis() {
        let versions = vec!["0.0.3".to_string(), "0.0.4".to_string()];
        let ev = check_version("^0.0.3", &versions, Some("0.0.3"));
        assert_eq!(
            ev.status,
            DependencyStatus::UpdateAvailable,
            "0.0.3 -> 0.0.4 is a breaking bump"
        );
        assert!(!ev.patch_available);

        // `0.2.z` still has one: the patch component floats under `^0.2.3`.
        let versions = vec!["0.2.3".to_string(), "0.2.9".to_string()];
        let ev = check_version("^0.2.3", &versions, Some("0.2.3"));
        assert_eq!(ev.status, DependencyStatus::PatchAvailable);
    }

    /// The reachability witness for issue #87: a wildcard constraint really does
    /// reach the fix layer as an upgradable dependency, so the guard there is not
    /// dead code. `1.x` allows `1.9.0` but not `2.0.0`, so the newest release sits
    /// outside the range and the item is reported as an available update.
    #[test]
    fn wildcard_constraint_is_reported_as_upgradable() {
        let e = check_version("1.x", &vers(&["1.0.0", "1.9.0", "2.0.0"]), None);
        assert_eq!(e.status, DependencyStatus::UpdateAvailable);
        assert_eq!(e.latest_compatible.as_deref(), Some("1.9.0"));
        assert_eq!(e.latest_available.as_deref(), Some("2.0.0"));
    }
}
