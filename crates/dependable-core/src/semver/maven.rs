//! Maven → semver translation for JVM versions and version ranges.
//!
//! Maven's own order (`ComparableVersion`) is not semver's. It splits a version on
//! `.`/`-` *and* on every digit↔letter transition, drops trailing null segments so
//! `1.0` and `1.0.0` are the same version, and orders the trailing qualifier by a
//! fixed table rather than lexically:
//!
//! ```text
//! alpha < beta < milestone < rc < snapshot < "" (a release) < sp
//! ```
//!
//! Two facts make that table expressible here. Those qualifier words are already in
//! ASCII order (`alpha` < `beta` < `milestone` < `rc` < `snapshot` < `sp`), which is
//! how `semver` compares alphanumeric pre-release identifiers; and semver ranks *any*
//! pre-release below the release it qualifies, which is Maven's rule for everything up
//! to `snapshot`.
//!
//! What is lost, and why each loss is the cheaper one:
//!
//! - **`sp`** (service pack) sorts *above* a release in Maven and below it here.
//!   Nothing in semver is both greater than `1.0.0` and less than `1.0.1`, so the
//!   alternative is a version string that names no real artifact.
//! - **A fourth or later numeric segment** becomes a pre-release identifier
//!   (`1.2.3.4` → `1.2.3-4`), so it sorts below `1.2.3` where Maven sorts it above.
//!   Segment-to-segment order among them is preserved, which dropping the segment —
//!   NuGet's answer — would not do.
//! - **An unrecognized qualifier** (`1.0-jre`) is ordered lexically among the known
//!   ones instead of after `sp`.
//! - **`ga`/`final`/`release`** are Maven's aliases for "no qualifier", so
//!   `6.4.4.Final` translates to `6.4.4` — correct for comparison, and the reason a
//!   version *reported* for such an artifact is spelled without the suffix.

/// Convert a Maven version into a parseable semver string.
///
/// The leading run of numeric segments becomes `Major.Minor.Patch` (padded, so
/// `1.0` and `1.0.0` are one version); everything after it — extra numeric segments
/// and the qualifier alike — becomes the pre-release. Returns `None` when the
/// version does not start with a number, which is the only form with no numeric
/// release component to anchor.
#[must_use]
pub fn maven_to_semver(version: &str) -> Option<String> {
    let tokens = tokenize(version);
    let numeric = tokens
        .iter()
        .take_while(|t| is_numeric(t))
        .cloned()
        .collect::<Vec<_>>();
    if numeric.is_empty() {
        return None;
    }
    let major = release_segment(numeric.first())?;
    let minor = release_segment(numeric.get(1)).unwrap_or(0);
    let patch = release_segment(numeric.get(2)).unwrap_or(0);

    let mut pre: Vec<String> = numeric
        .iter()
        .skip(3)
        .map(|t| strip_leading_zeros(t).to_owned())
        .collect();
    for token in tokens.iter().skip(numeric.len()) {
        if is_numeric(token) {
            pre.push(strip_leading_zeros(token).to_owned());
        } else {
            // A release alias contributes nothing: Maven reads `1.0.0.RELEASE` as
            // exactly `1.0.0`.
            match qualifier_alias(token) {
                Some(canonical) => pre.push(canonical.to_owned()),
                None => continue,
            }
        }
    }

    let mut out = format!("{major}.{minor}.{patch}");
    if !pre.is_empty() {
        out.push('-');
        out.push_str(&pre.join("."));
    }
    Some(out)
}

/// Convert a Maven / Gradle version constraint into a
/// `semver::VersionReq`-compatible string.
///
/// Handles Maven's interval notation (`[1.0,2.0)`, `[1.0]`, `(1.0,)`, `(,2.0]`),
/// Gradle's `+` wildcards (`+`, `1.2.+`) and `latest.*` selectors, and a bare
/// version.
///
/// A bare version is read as **exact**, as Hex's is. Maven calls it a soft
/// requirement — the version this project gets unless some other dependency in the
/// graph forces a higher one — so the version actually resolved here is the one
/// written, and reading it as an open `>=` bound would report every project as
/// already up to date.
///
/// A union (`(,1.0],[1.2,)`) is not expressible in `semver::VersionReq`; the last
/// (newest-allowing) interval is kept, matching the Hex translation.
#[must_use]
pub fn maven_constraint_to_semver(constraint: &str) -> String {
    let c = constraint.trim();
    if c.is_empty() {
        return String::new();
    }
    // Gradle's dynamic selectors name a channel, not a range.
    if c.eq_ignore_ascii_case("latest.release") || c.eq_ignore_ascii_case("latest.integration") {
        return "*".to_string();
    }
    if c.contains('+') {
        return wildcard_range(c).unwrap_or_else(|| "*".to_string());
    }
    if c.starts_with('[') || c.starts_with('(') {
        return interval_range(c).unwrap_or_default();
    }
    maven_to_semver(c).map_or_else(String::new, |v| format!("={v}"))
}

/// Parse an interval such as `[1.0,2.0)` / `[1.0]` / `(1.0,)` / `(,2.0]`, keeping
/// the last interval of a comma-joined union.
fn interval_range(c: &str) -> Option<String> {
    let open = c.rfind(['[', '('])?;
    let group = c[open..].trim_end();
    let open_incl = group.starts_with('[');
    let close_incl = match group.chars().last()? {
        ']' => true,
        ')' => false,
        _ => return None,
    };
    let inner = &group[1..group.len() - 1];
    let Some((lo, hi)) = inner.split_once(',') else {
        // No comma: an exact version, e.g. `[1.0]` → `=1.0.0`.
        return maven_to_semver(inner.trim()).map(|v| format!("={v}"));
    };
    let mut clauses = Vec::new();
    let (lo, hi) = (lo.trim(), hi.trim());
    if !lo.is_empty() {
        let v = maven_to_semver(lo)?;
        clauses.push(format!("{}{v}", if open_incl { ">=" } else { ">" }));
    }
    if !hi.is_empty() {
        let v = maven_to_semver(hi)?;
        clauses.push(format!("{}{v}", if close_incl { "<=" } else { "<" }));
    }
    if clauses.is_empty() {
        return Some("*".to_string());
    }
    Some(clauses.join(", "))
}

/// Expand a Gradle wildcard: `+` → any, `1.+` → `>=1.0.0, <2.0.0`,
/// `1.2.+` → `>=1.2.0, <1.3.0`.
fn wildcard_range(c: &str) -> Option<String> {
    if c == "+" {
        return Some("*".to_string());
    }
    let prefix = c.strip_suffix(".+")?;
    let nums: Vec<u64> = prefix
        .split('.')
        .map(|s| s.trim().parse().ok())
        .collect::<Option<_>>()?;
    let (last, head) = nums.split_last()?;
    let lower = pad(&nums);
    let mut upper: Vec<u64> = head.to_vec();
    upper.push(last.checked_add(1)?);
    Some(format!(">={lower}, <{}", pad(&upper)))
}

/// Render numbers as an `X.Y.Z` semver string, padding with zeros.
fn pad(nums: &[u64]) -> String {
    let major = nums.first().copied().unwrap_or(0);
    let minor = nums.get(1).copied().unwrap_or(0);
    let patch = nums.get(2).copied().unwrap_or(0);
    format!("{major}.{minor}.{patch}")
}

/// Split a version the way Maven does: on every separator, and on every
/// digit↔letter transition. Anything that is not ASCII alphanumeric separates,
/// which also keeps every token spellable as a semver identifier.
fn tokenize(version: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_is_digit: Option<bool> = None;
    for c in version.trim().chars() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            current_is_digit = None;
            continue;
        }
        let is_digit = c.is_ascii_digit();
        if current_is_digit.is_some_and(|was| was != is_digit) && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current_is_digit = Some(is_digit);
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Whether a token is a run of ASCII digits.
fn is_numeric(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit())
}

/// One of `Major`/`Minor`/`Patch`, or `None` when the number does not fit.
fn release_segment(token: Option<&String>) -> Option<u64> {
    token?.parse().ok()
}

/// Drop leading zeros, which semver forbids in a numeric pre-release identifier.
fn strip_leading_zeros(token: &str) -> &str {
    let trimmed = token.trim_start_matches('0');
    if trimmed.is_empty() { "0" } else { trimmed }
}

/// The canonical spelling of a qualifier word, or `None` for Maven's aliases for
/// "no qualifier at all".
fn qualifier_alias(token: &str) -> Option<&str> {
    match token {
        "a" | "alpha" => Some("alpha"),
        "b" | "beta" => Some("beta"),
        "m" | "milestone" => Some("milestone"),
        "cr" | "rc" => Some("rc"),
        "snapshot" => Some("snapshot"),
        "sp" => Some("sp"),
        "ga" | "final" | "release" => None,
        other => Some(other),
    }
}

#[cfg(test)]
mod tests {
    use ::semver::{Version, VersionReq};

    use super::*;

    fn parsed(version: &str) -> Version {
        let translated = maven_to_semver(version)
            .unwrap_or_else(|| panic!("{version} has no numeric release component"));
        Version::parse(&translated)
            .unwrap_or_else(|e| panic!("{version} → {translated} is not semver: {e}"))
    }

    #[test]
    fn a_short_version_is_the_same_version_as_its_padded_form() {
        assert_eq!(maven_to_semver("1.0").as_deref(), Some("1.0.0"));
        assert_eq!(maven_to_semver("1").as_deref(), Some("1.0.0"));
        assert_eq!(parsed("1.0"), parsed("1.0.0"));
        assert_eq!(parsed("1"), parsed("1.0.0"));
    }

    #[test]
    fn qualifiers_keep_mavens_order() {
        // Maven's own table, minus the one entry semver cannot hold (see the
        // module docs on `sp`).
        let ascending = [
            "1.0-alpha1",
            "1.0-alpha2",
            "1.0-beta1",
            "1.0-milestone1",
            "1.0-rc1",
            "1.0-SNAPSHOT",
            "1.0",
        ];
        for pair in ascending.windows(2) {
            assert!(
                parsed(pair[0]) < parsed(pair[1]),
                "{} should precede {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn qualifier_aliases_are_canonicalized() {
        // `a`/`b`/`m`/`cr` are Maven's short spellings, so they have to sort where
        // the words they abbreviate do.
        assert_eq!(parsed("1.0-a1"), parsed("1.0-alpha1"));
        assert_eq!(parsed("1.0-b2"), parsed("1.0-beta2"));
        assert_eq!(parsed("1.0-m3"), parsed("1.0-milestone3"));
        assert_eq!(parsed("1.0-cr1"), parsed("1.0-rc1"));
        // `ga`/`final`/`release` mean "no qualifier", so they are the release.
        assert_eq!(parsed("6.4.4.Final"), parsed("6.4.4"));
        assert_eq!(parsed("5.3.9.RELEASE"), parsed("5.3.9"));
        assert_eq!(parsed("1.0-ga"), parsed("1.0"));
    }

    #[test]
    fn a_qualifier_number_compares_numerically() {
        // Split into its own identifier, or `rc10` would sort below `rc9`.
        assert!(parsed("1.0-rc9") < parsed("1.0-rc10"));
        assert_eq!(maven_to_semver("1.0-rc10").as_deref(), Some("1.0.0-rc.10"));
        // Leading zeros are illegal in a numeric pre-release identifier.
        assert_eq!(
            maven_to_semver("2.5.6-sec03").as_deref(),
            Some("2.5.6-sec.3")
        );
    }

    #[test]
    fn four_or_more_segments_stay_ordered_among_themselves() {
        assert_eq!(maven_to_semver("1.2.3.4").as_deref(), Some("1.2.3-4"));
        assert!(parsed("1.2.3.4") < parsed("1.2.3.5"));
        assert!(parsed("1.2.3.9") < parsed("1.2.3.10"));
        assert!(parsed("1.2.3.4") < parsed("1.2.4"));
        // A dated build qualifier (Jetty) keeps its numeric order too.
        assert!(parsed("9.4.51.v20230217") < parsed("9.4.53.v20231009"));
    }

    #[test]
    fn a_version_without_a_number_has_nothing_to_anchor() {
        assert_eq!(maven_to_semver("RELEASE"), None);
        assert_eq!(maven_to_semver(""), None);
    }

    #[test]
    fn a_bare_constraint_is_the_version_this_project_resolves() {
        assert_eq!(maven_constraint_to_semver("1.9.24"), "=1.9.24");
        assert_eq!(maven_constraint_to_semver(" 1.0 "), "=1.0.0");
        assert_eq!(maven_constraint_to_semver(""), "");
    }

    #[test]
    fn intervals_translate_to_bounds() {
        assert_eq!(maven_constraint_to_semver("[1.0,2.0)"), ">=1.0.0, <2.0.0");
        assert_eq!(maven_constraint_to_semver("(1.0,2.0]"), ">1.0.0, <=2.0.0");
        assert_eq!(maven_constraint_to_semver("[1.5,)"), ">=1.5.0");
        assert_eq!(maven_constraint_to_semver("(,2.0]"), "<=2.0.0");
        assert_eq!(maven_constraint_to_semver("[1.0]"), "=1.0.0");
        // A union keeps the newest-allowing interval.
        assert_eq!(maven_constraint_to_semver("(,1.0],[1.2,)"), ">=1.2.0");
    }

    #[test]
    fn gradle_wildcards_and_selectors() {
        assert_eq!(maven_constraint_to_semver("+"), "*");
        assert_eq!(maven_constraint_to_semver("1.+"), ">=1.0.0, <2.0.0");
        assert_eq!(maven_constraint_to_semver("1.2.+"), ">=1.2.0, <1.3.0");
        assert_eq!(maven_constraint_to_semver("latest.release"), "*");
    }

    #[test]
    fn every_translated_constraint_is_a_parseable_requirement() {
        for constraint in [
            "1.9.24",
            "[1.0,2.0)",
            "(1.0,2.0]",
            "[1.5,)",
            "(,2.0]",
            "[1.0]",
            "1.2.+",
            "+",
            "latest.release",
            "1.0-rc1",
        ] {
            let translated = maven_constraint_to_semver(constraint);
            VersionReq::parse(&translated)
                .unwrap_or_else(|e| panic!("{constraint} → {translated}: {e}"));
        }
    }
}
