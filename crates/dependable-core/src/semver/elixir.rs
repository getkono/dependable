//! Hex (`~>`) → semver constraint translation for Elixir.
//!
//! Hex *versions* are already semver, so only *constraints* need translating. The
//! `~>` operator differs from semver's `~`: `~> 2.1` means `>=2.1.0, <3.0.0` (only
//! the last given component is bounded), whereas `~> 2.1.3` means `>=2.1.3,
//! <2.2.0`. The comparison operators (`>=`, `>`, `<=`, `<`, `==`) map directly and a
//! bare version is exact.
//!
//! `and` (intersection) is semver's comma. `or` (union) has no semver spelling, so one
//! clause has to be chosen; we take the one with the highest lower bound rather than
//! whichever was written last, because Hex does not require clauses in ascending order
//! and `~> 2.0 or ~> 1.0` would otherwise resolve to the 1.x range and report every 2.x
//! release as out of range.

/// Convert a Hex version requirement into a `semver::VersionReq`-compatible string.
///
/// A constraint that cannot be translated is returned **unchanged** so it fails to parse
/// downstream and the dependency is reported as an error. Returning an empty string
/// instead made it `*`, which matches every version — a constraint nobody could read
/// became a dependency that was always up to date.
#[must_use]
pub fn hex_constraint_to_semver(constraint: &str) -> String {
    let unions: Vec<&str> = constraint.split(" or ").map(str::trim).collect();
    let mut best: Option<(::semver::Version, String)> = None;
    for union in unions {
        // `and` is an intersection, which semver writes as a comma-separated list.
        let Some(converted) = union
            .split(" and ")
            .map(|clause| convert_clause(clause.trim()))
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join(", "))
        else {
            continue;
        };
        let bound = lower_bound(&converted);
        if best.as_ref().is_none_or(|(b, _)| bound > *b) {
            best = Some((bound, converted));
        }
    }
    best.map_or_else(|| constraint.to_string(), |(_, converted)| converted)
}

/// The lowest version a converted clause admits, used only to rank union branches.
fn lower_bound(converted: &str) -> ::semver::Version {
    let zero = ::semver::Version::new(0, 0, 0);
    converted
        .split(',')
        .filter_map(|part| {
            let p = part.trim();
            let rest = p
                .strip_prefix(">=")
                .or_else(|| p.strip_prefix('='))
                .or_else(|| p.strip_prefix('>'))?;
            ::semver::Version::parse(rest.trim()).ok()
        })
        .max()
        .unwrap_or(zero)
}

fn convert_clause(clause: &str) -> Option<String> {
    let c = clause.trim();
    if let Some(rest) = c.strip_prefix("~>") {
        return tilde(rest.trim());
    }
    // Longest operators first so `>=` wins over `>`.
    for op in [">=", "<=", "==", ">", "<"] {
        if let Some(rest) = c.strip_prefix(op) {
            let v = to_semver_version(rest.trim())?;
            let semver_op = if op == "==" { "=" } else { op };
            return Some(format!("{semver_op}{v}"));
        }
    }
    // A bare version in Hex is an exact match.
    to_semver_version(c).map(|v| format!("={v}"))
}

/// Expand a Hex `~>` clause. `~> a.b.c` → `>=a.b.c, <a.(b+1).0`;
/// `~> a.b` → `>=a.b.0, <(a+1).0.0`.
fn tilde(version: &str) -> Option<String> {
    // Split off any pre-release/build so we count only the numeric components.
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let nums: Vec<u64> = core
        .split('.')
        .map(|s| s.trim().parse().ok())
        .collect::<Option<_>>()?;
    if nums.is_empty() {
        return None;
    }
    let lower = to_semver_version(version)?;
    // Components are parsed straight from a manifest, so `u64::MAX` is reachable input
    // and a plain `+ 1` panics in debug and wraps in release.
    let upper = if nums.len() >= 3 {
        // Bound the minor: only the patch may float.
        format!("{}.{}.0", nums[0], nums[1].saturating_add(1))
    } else {
        // Bound the major: the minor may float.
        format!("{}.0.0", nums[0].saturating_add(1))
    };
    Some(format!(">={lower}, <{upper}"))
}

/// Normalize a Hex version operand into a padded `X.Y.Z[-pre]` semver string.
fn to_semver_version(version: &str) -> Option<String> {
    let v = version.trim();
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let suffix = &v[core.len()..];
    let nums: Vec<&str> = core.split('.').collect();
    let major = nums.first().copied().unwrap_or("");
    let minor = nums.get(1).copied().unwrap_or("0");
    let patch = nums.get(2).copied().unwrap_or("0");
    for seg in [major, minor, patch] {
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!("{major}.{minor}.{patch}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_bounds_last_component() {
        // Two components float the minor up to the next major.
        assert_eq!(hex_constraint_to_semver("~> 2.1"), ">=2.1.0, <3.0.0");
        // Three components float only the patch.
        assert_eq!(hex_constraint_to_semver("~> 2.1.3"), ">=2.1.3, <2.2.0");
        assert_eq!(hex_constraint_to_semver("~> 1.0.0"), ">=1.0.0, <1.1.0");
    }

    #[test]
    fn comparison_and_exact() {
        assert_eq!(hex_constraint_to_semver(">= 3.0.0"), ">=3.0.0");
        assert_eq!(hex_constraint_to_semver("> 1.2"), ">1.2.0");
        assert_eq!(hex_constraint_to_semver("== 1.2.3"), "=1.2.3");
        // Bare version is exact.
        assert_eq!(hex_constraint_to_semver("1.2.3"), "=1.2.3");
    }

    #[test]
    fn keeps_last_clause_of_a_union() {
        assert_eq!(
            hex_constraint_to_semver("~> 1.0 or ~> 2.0"),
            ">=2.0.0, <3.0.0"
        );
    }

    /// An untranslatable constraint used to collapse to the empty string, which
    /// `VersionReq` reads as `*` — so a requirement nobody could parse matched every
    /// version and the dependency was always up to date. Returning it unchanged makes it
    /// fail to parse downstream, which is reported as an error.
    #[test]
    fn an_untranslatable_constraint_is_not_widened_to_star() {
        for constraint in ["~> not.a.version", "@@@", ">= banana"] {
            let converted = hex_constraint_to_semver(constraint);
            assert_ne!(converted, "", "{constraint} collapsed to `*`");
            assert!(
                ::semver::VersionReq::parse(&converted).is_err(),
                "{constraint} -> {converted} must not parse"
            );
        }
    }

    /// `and` is an intersection, which semver writes as a comma.
    #[test]
    fn intersections_become_comma_separated_bounds() {
        let converted = hex_constraint_to_semver(">= 1.0.0 and < 2.0.0");
        let req = ::semver::VersionReq::parse(&converted).expect(&converted);
        assert!(req.matches(&::semver::Version::parse("1.5.0").unwrap()));
        assert!(!req.matches(&::semver::Version::parse("2.0.0").unwrap()));
        assert!(!req.matches(&::semver::Version::parse("0.9.0").unwrap()));
    }

    /// Hex does not require union clauses in ascending order, so taking the last one
    /// could pick the *older* range and report every newer release as out of range.
    #[test]
    fn a_union_picks_the_newest_clause_regardless_of_order() {
        for constraint in ["~> 2.0 or ~> 1.0", "~> 1.0 or ~> 2.0"] {
            let converted = hex_constraint_to_semver(constraint);
            let req = ::semver::VersionReq::parse(&converted).expect(&converted);
            assert!(
                req.matches(&::semver::Version::parse("2.3.0").unwrap()),
                "{constraint} -> {converted} rejected 2.3.0"
            );
        }
    }

    /// Version components come straight from a manifest, so `u64::MAX` is reachable and
    /// the `+ 1` that bounds a `~>` range must not panic on it.
    #[test]
    fn an_enormous_version_component_does_not_overflow() {
        let _ = hex_constraint_to_semver("~> 18446744073709551615.0.0");
        let _ = hex_constraint_to_semver("~> 18446744073709551615.18446744073709551615");
    }
}
