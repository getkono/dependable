//! NuGet → semver translation for C#/.NET versions and version ranges.
//!
//! NuGet versions are close to semver but allow a 4th "revision" segment
//! (`1.0.0.0`) and short forms (`1`, `1.2`); NuGet *constraints* use interval
//! notation (`[1.0,2.0)`, `[1.0]`, `(1.0,)`) and floating wildcards (`1.*`).
//! These helpers translate both into the closest `semver`/`semver::VersionReq`
//! equivalent so the generic engine can compare them. The 4th revision segment is
//! dropped (rare on the SemVer 2.0 registration feed), which is lossy only when two
//! versions differ solely in that segment.

/// Convert a NuGet version into a parseable semver string.
///
/// Normalizes the numeric core to exactly `Major.Minor.Patch` (padding short
/// forms, dropping a 4th revision segment) and preserves the `-prerelease` and
/// `+build` suffixes. Returns `None` if there is no numeric release component.
#[must_use]
pub fn nuget_to_semver(version: &str) -> Option<String> {
    let v = version.trim();
    let (rest, build) = split_once(v, '+');
    let (core, pre) = split_once(rest, '-');

    let nums: Vec<&str> = core.split('.').collect();
    let major = nums.first().copied().unwrap_or("");
    let minor = nums.get(1).copied().unwrap_or("0");
    let patch = nums.get(2).copied().unwrap_or("0");
    // Every used segment must be a non-empty run of digits.
    for seg in [major, minor, patch] {
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }

    let mut out = format!("{major}.{minor}.{patch}");
    if let Some(pre) = pre.filter(|p| !p.is_empty()) {
        out.push('-');
        out.push_str(pre);
    }
    if let Some(build) = build.filter(|b| !b.is_empty()) {
        out.push('+');
        out.push_str(build);
    }
    Some(out)
}

/// Convert a NuGet version range into a `semver::VersionReq`-compatible string.
///
/// Handles interval notation (`[1.0,2.0)`, `[1.0]`, `(1.0,)`, `(,2.0]`), floating
/// wildcards (`*`, `1.*`, `1.0.*`), and a bare version (`1.0`), which NuGet reads
/// as an inclusive minimum (`>=1.0`).
#[must_use]
pub fn nuget_constraint_to_semver(constraint: &str) -> String {
    let c = constraint.trim();
    if c.is_empty() {
        return String::new();
    }
    if c.contains('*') {
        return floating_range(c).unwrap_or_else(|| "*".to_string());
    }
    if c.starts_with('[') || c.starts_with('(') {
        return interval_range(c).unwrap_or_default();
    }
    // A bare version is an inclusive minimum in NuGet.
    nuget_to_semver(c).map_or_else(String::new, |v| format!(">={v}"))
}

/// Parse an interval such as `[1.0,2.0)` / `[1.0]` / `(1.0,)` / `(,2.0]`.
fn interval_range(c: &str) -> Option<String> {
    let open_incl = c.starts_with('[');
    let close_incl = c.ends_with(']');
    if !(c.ends_with(']') || c.ends_with(')')) {
        return None;
    }
    let inner = &c[1..c.len() - 1];
    match inner.split_once(',') {
        Some((lo, hi)) => {
            let mut clauses = Vec::new();
            let lo = lo.trim();
            let hi = hi.trim();
            if !lo.is_empty() {
                let v = nuget_to_semver(lo)?;
                clauses.push(format!("{}{v}", if open_incl { ">=" } else { ">" }));
            }
            if !hi.is_empty() {
                let v = nuget_to_semver(hi)?;
                clauses.push(format!("{}{v}", if close_incl { "<=" } else { "<" }));
            }
            if clauses.is_empty() {
                return Some("*".to_string());
            }
            Some(clauses.join(", "))
        }
        // No comma: an exact version, e.g. `[1.0]` → `=1.0.0`.
        None => nuget_to_semver(inner.trim()).map(|v| format!("={v}")),
    }
}

/// Expand a floating wildcard: `*` → any, `1.*` → `>=1.0.0, <2.0.0`,
/// `1.0.*` → `>=1.0.0, <1.1.0`.
fn floating_range(c: &str) -> Option<String> {
    if c == "*" {
        return Some("*".to_string());
    }
    let prefix = c.strip_suffix(".*")?;
    let nums: Vec<u64> = prefix
        .split('.')
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    if nums.is_empty() {
        return None;
    }
    let lower = pad_to_semver(&nums);
    let upper = bump_last(&nums)?;
    Some(format!(">={lower}, <{upper}"))
}

/// Split on the first occurrence of `sep`, returning the head and an optional tail.
fn split_once(s: &str, sep: char) -> (&str, Option<&str>) {
    match s.split_once(sep) {
        Some((head, tail)) => (head, Some(tail)),
        None => (s, None),
    }
}

/// Render version numbers as an `X.Y.Z` semver string (padding with zeros).
fn pad_to_semver(nums: &[u64]) -> String {
    let major = nums.first().copied().unwrap_or(0);
    let minor = nums.get(1).copied().unwrap_or(0);
    let patch = nums.get(2).copied().unwrap_or(0);
    format!("{major}.{minor}.{patch}")
}

/// Bump the last given segment by one and zero the rest (`[1]` → `2.0.0`;
/// `[1,0]` → `1.1.0`).
fn bump_last(nums: &[u64]) -> Option<String> {
    let (last, head) = nums.split_last()?;
    let mut out: Vec<u64> = head.to_vec();
    out.push(last + 1);
    Some(pad_to_semver(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_versions() {
        assert_eq!(nuget_to_semver("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(nuget_to_semver("1.2").as_deref(), Some("1.2.0"));
        assert_eq!(nuget_to_semver("1").as_deref(), Some("1.0.0"));
        assert_eq!(nuget_to_semver("1.0.0.4").as_deref(), Some("1.0.0")); // revision dropped
        assert_eq!(
            nuget_to_semver("13.0.1-beta1").as_deref(),
            Some("13.0.1-beta1")
        );
        assert_eq!(nuget_to_semver("$(Version)"), None);
    }

    #[test]
    fn converts_interval_ranges() {
        assert_eq!(nuget_constraint_to_semver("[1.0,2.0)"), ">=1.0.0, <2.0.0");
        assert_eq!(nuget_constraint_to_semver("(1.0,2.0]"), ">1.0.0, <=2.0.0");
        assert_eq!(nuget_constraint_to_semver("[1.0]"), "=1.0.0");
        assert_eq!(nuget_constraint_to_semver("[1.0,)"), ">=1.0.0");
        assert_eq!(nuget_constraint_to_semver("(,2.0]"), "<=2.0.0");
    }

    #[test]
    fn converts_bare_and_floating() {
        // Bare version → inclusive minimum.
        assert_eq!(nuget_constraint_to_semver("1.0"), ">=1.0.0");
        assert_eq!(nuget_constraint_to_semver("*"), "*");
        assert_eq!(nuget_constraint_to_semver("1.*"), ">=1.0.0, <2.0.0");
        assert_eq!(nuget_constraint_to_semver("1.2.*"), ">=1.2.0, <1.3.0");
    }
}
