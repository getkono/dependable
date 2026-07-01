//! Hex (`~>`) → semver constraint translation for Elixir.
//!
//! Hex *versions* are already semver, so only *constraints* need translating. The
//! `~>` operator differs from semver's `~`: `~> 2.1` means `>=2.1.0, <3.0.0` (only
//! the last given component is bounded), whereas `~> 2.1.3` means `>=2.1.3,
//! <2.2.0`. The comparison operators (`>=`, `>`, `<=`, `<`, `==`) map directly, a
//! bare version is exact, and `or` (union) is not expressible in `semver::VersionReq`
//! — we keep the last (newest-allowing) clause, which is lossy only for multi-range
//! disjunctions.

/// Convert a Hex version requirement into a `semver::VersionReq`-compatible string.
#[must_use]
pub fn hex_constraint_to_semver(constraint: &str) -> String {
    // `A or B` is a union; semver can't express it, so keep the last clause.
    let clause = constraint
        .rsplit(" or ")
        .next()
        .unwrap_or(constraint)
        .trim();
    convert_clause(clause).unwrap_or_default()
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
    let upper = if nums.len() >= 3 {
        // Bound the minor: only the patch may float.
        format!("{}.{}.0", nums[0], nums[1] + 1)
    } else {
        // Bound the major: the minor may float.
        format!("{}.0.0", nums[0] + 1)
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
}
