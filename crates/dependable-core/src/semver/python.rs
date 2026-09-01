//! PEP 440 → semver translation for Python versions and constraints.
//!
//! Python versions (`1.0a1`, `1.0.post1`, `1.0.dev2`, `1.2`) and constraints
//! (`>=1.0,<2.0`, `==1.0.*`, `~=1.4`) don't match the `semver` crate directly.
//! These helpers translate both into the closest semver equivalent so the generic
//! version engine can compare them. The translation is lossy at the edges (epochs,
//! 4+ release segments, `!=` exclusions, post-vs-pre ordering) — all rare, and
//! pre/dev/post releases are excluded by default anyway.

/// Convert a PEP 440 version into a parseable semver string.
///
/// Returns `None` only if there is no numeric release component at all.
#[must_use]
pub fn pep440_to_semver(version: &str) -> Option<String> {
    let v = version.trim();
    // Drop an epoch (`1!1.0` → `1.0`) and a local segment (`1.0+abc` → `1.0`).
    let v = v.split_once('!').map_or(v, |(_, rest)| rest);
    let v = v.split('+').next().unwrap_or(v);

    // The release is the leading run of digits and dots.
    let release_end = v
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(v.len());
    let release = &v[..release_end];
    let suffix = &v[release_end..];

    let nums: Vec<&str> = release.split('.').filter(|s| !s.is_empty()).collect();
    if nums.is_empty() {
        return None;
    }
    let major = nums.first().copied().unwrap_or("0");
    let minor = nums.get(1).copied().unwrap_or("0");
    let patch = nums.get(2).copied().unwrap_or("0");
    let core = format!("{major}.{minor}.{patch}");

    let pre = convert_suffix(suffix);
    if pre.is_empty() {
        Some(core)
    } else {
        Some(format!("{core}-{pre}"))
    }
}

/// Convert a PEP 440 pre/post/dev suffix into a semver pre-release identifier
/// (`a1` → `alpha.1`, `rc1` → `rc.1`, `.dev2` → `dev.2`, `.post1` → `post.1`).
fn convert_suffix(suffix: &str) -> String {
    let lower = suffix.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let canon = match &lower[start..i] {
                "a" | "alpha" => "alpha",
                "b" | "beta" => "beta",
                "c" | "rc" | "pre" | "preview" => "rc",
                "post" | "rev" | "r" => "post",
                "dev" => "dev",
                other => other,
            };
            parts.push(canon.to_string());
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            parts.push(lower[start..i].to_string());
        } else {
            i += 1; // separators: . - _
        }
    }
    parts.join(".")
}

/// Convert a PEP 440 (or Poetry) constraint into a `semver::VersionReq` string.
///
/// Splits on commas, strips `;` environment markers, and converts each clause.
/// Poetry's `^`/`~`/`*` and the comparison operators pass through; `~=` and `==…*`
/// expand to ranges; `!=` is dropped (semver can't express exclusion).
#[must_use]
pub fn pep440_constraint_to_semver(constraint: &str) -> String {
    let clauses: Vec<String> = constraint
        .split(',')
        .map(|clause| clause.split(';').next().unwrap_or(clause).trim())
        .filter(|clause| !clause.is_empty())
        .filter_map(convert_clause)
        .collect();
    clauses.join(", ")
}

/// Comparison/compatibility operators, longest-first so `>=` wins over `>`.
const OPERATORS: &[&str] = &["===", "==", "~=", "!=", ">=", "<=", "^", "~", ">", "<", "="];

fn convert_clause(clause: &str) -> Option<String> {
    for op in OPERATORS {
        if let Some(rest) = clause.strip_prefix(op) {
            return convert_op(op, rest.trim());
        }
    }
    // A bare version (`1.2.3`) — treat like Poetry/Cargo caret semantics.
    pep440_to_semver(clause)
}

fn convert_op(op: &str, version: &str) -> Option<String> {
    match op {
        "==" | "===" => {
            if let Some(prefix) = version.strip_suffix(".*") {
                wildcard_range(prefix)
            } else {
                pep440_to_semver(version).map(|v| format!("={v}"))
            }
        }
        "=" => pep440_to_semver(version).map(|v| format!("={v}")),
        "~=" => compatible_release(version),
        "!=" => None, // exclusion is not expressible in semver
        "^" | "~" => Some(format!("{op}{version}")), // Poetry / semver-native
        ">=" | "<=" | ">" | "<" => pep440_to_semver(version).map(|v| format!("{op}{v}")),
        _ => None,
    }
}

/// `==1.0.*` → `>=1.0.0, <1.1.0` (the next release of the last specified segment).
fn wildcard_range(prefix: &str) -> Option<String> {
    let nums: Vec<u64> = prefix
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    let lower = pad_to_semver(&nums);
    let upper = bump_last(&nums)?;
    Some(format!(">={lower}, <{upper}"))
}

/// `~=1.4` → `>=1.4.0, <2.0.0`; `~=1.4.2` → `>=1.4.2, <1.5.0`.
fn compatible_release(version: &str) -> Option<String> {
    let nums: Vec<u64> = version
        .split('.')
        .map(str::trim)
        .take_while(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    if nums.len() < 2 {
        return None;
    }
    let lower = pad_to_semver(&nums);
    // The upper bound drops the last component and bumps the new last one.
    let upper = bump_last(&nums[..nums.len() - 1])?;
    Some(format!(">={lower}, <{upper}"))
}

/// What [`pep440_to_semver`] threw away, as a comparison key.
///
/// The translation keeps three release segments and the pre/post/dev suffix, and
/// drops the epoch and every release segment past the third — so `2.7.6` and
/// `2.7.6.1` (both published by `psycopg2-binary`) and `3.3.0`/`3.3.0.1` (both
/// published by `zope.interface`) translate alike and compare equal. Which of them
/// is actually the newer is decided by exactly what was dropped, and this is it:
/// the epoch first, since PEP 440 ranks it above everything (`1!2.0` outranks
/// `2.0`), then segment by segment (`2.7.6.1` outranks `2.7.6`, which has no
/// fourth segment at all).
///
/// A caller that has to name one published artifact out of a group translating
/// alike orders them by this rather than by their position in a list, which is what
/// makes the answer independent of the order the registry happened to return —
/// PyPI's `releases` map has no order of its own to lend.
#[must_use]
pub fn discarded_precision(version: &str) -> Vec<u64> {
    let v = version.trim();
    let (epoch, v) = match v.split_once('!') {
        Some((epoch, rest)) => (epoch.trim().parse().unwrap_or(0), rest),
        None => (0, v),
    };
    let v = v.split('+').next().unwrap_or(v);
    let release_end = v
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(v.len());
    let mut key = vec![epoch];
    key.extend(
        v[..release_end]
            .split('.')
            .filter(|segment| !segment.is_empty())
            .skip(3)
            .map(|segment| segment.parse().unwrap_or(0)),
    );
    key
}

/// Render version numbers as an `X.Y.Z` semver string (padding with zeros).
fn pad_to_semver(nums: &[u64]) -> String {
    let major = nums.first().copied().unwrap_or(0);
    let minor = nums.get(1).copied().unwrap_or(0);
    let patch = nums.get(2).copied().unwrap_or(0);
    format!("{major}.{minor}.{patch}")
}

/// Bump the last given segment by one and zero the rest, as a semver string
/// (`[1,4]` → `2.0.0`; `[1,4,2]` → `1.5.0`).
fn bump_last(nums: &[u64]) -> Option<String> {
    let (last, head) = nums.split_last()?;
    let mut out: Vec<u64> = head.to_vec();
    out.push(last + 1);
    Some(pad_to_semver(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reported version, the string `--fix` writes, and the version sent to OSV
    /// all name one artifact out of a translation group, so the group has to have an
    /// order of its own.
    #[test]
    fn a_dropped_segment_or_epoch_still_ranks_two_versions_that_translate_alike() {
        assert_eq!(pep440_to_semver("2.7.6").as_deref(), Some("2.7.6"));
        assert_eq!(pep440_to_semver("2.7.6.1").as_deref(), Some("2.7.6"));
        assert!(discarded_precision("2.7.6") < discarded_precision("2.7.6.1"));
        assert!(discarded_precision("3.3.0") < discarded_precision("3.3.0.1"));
        assert!(discarded_precision("2.7.6.1") < discarded_precision("2.7.6.2"));
        assert!(discarded_precision("2.7.6.9") < discarded_precision("2.7.6.10"));
        // An epoch outranks any amount of trailing precision without one.
        assert!(discarded_precision("2.0.0.99") < discarded_precision("1!2.0.0"));
        assert_eq!(discarded_precision("2.7.6"), discarded_precision("2.7.6"));
    }

    #[test]
    fn converts_release_versions() {
        assert_eq!(pep440_to_semver("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(pep440_to_semver("2.1").as_deref(), Some("2.1.0"));
        assert_eq!(pep440_to_semver("3").as_deref(), Some("3.0.0"));
        assert_eq!(pep440_to_semver("1.0+ubuntu1").as_deref(), Some("1.0.0"));
        assert_eq!(pep440_to_semver("1!2.0").as_deref(), Some("2.0.0"));
    }

    #[test]
    fn converts_pre_post_dev() {
        assert_eq!(pep440_to_semver("1.0a1").as_deref(), Some("1.0.0-alpha.1"));
        assert_eq!(pep440_to_semver("1.0b2").as_deref(), Some("1.0.0-beta.2"));
        assert_eq!(pep440_to_semver("1.0rc1").as_deref(), Some("1.0.0-rc.1"));
        assert_eq!(pep440_to_semver("1.0.dev3").as_deref(), Some("1.0.0-dev.3"));
        assert_eq!(
            pep440_to_semver("1.0.post1").as_deref(),
            Some("1.0.0-post.1")
        );
    }

    #[test]
    fn converts_comparison_constraints() {
        assert_eq!(pep440_constraint_to_semver(">=1.0"), ">=1.0.0");
        assert_eq!(pep440_constraint_to_semver(">=1.0,<2.0"), ">=1.0.0, <2.0.0");
        assert_eq!(pep440_constraint_to_semver("==1.2.3"), "=1.2.3");
    }

    #[test]
    fn strips_environment_markers() {
        assert_eq!(
            pep440_constraint_to_semver(">=2.0 ; python_version < \"3.8\""),
            ">=2.0.0"
        );
    }

    #[test]
    fn expands_wildcards_and_compatible_release() {
        assert_eq!(pep440_constraint_to_semver("==1.0.*"), ">=1.0.0, <1.1.0");
        assert_eq!(pep440_constraint_to_semver("~=1.4"), ">=1.4.0, <2.0.0");
        assert_eq!(pep440_constraint_to_semver("~=1.4.2"), ">=1.4.2, <1.5.0");
    }

    #[test]
    fn passes_through_poetry_operators_and_drops_exclusions() {
        assert_eq!(pep440_constraint_to_semver("^1.2.3"), "^1.2.3");
        assert_eq!(pep440_constraint_to_semver("~1.2"), "~1.2");
        // `!=` is dropped, leaving the expressible clauses.
        assert_eq!(pep440_constraint_to_semver(">=1.0,!=1.5"), ">=1.0.0");
    }
}
