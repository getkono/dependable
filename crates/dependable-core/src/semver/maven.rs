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
//!   ones instead of after `sp`. Where such a qualifier is a *flavour* — a build
//!   variant published under the same version number, as `guava` publishes
//!   `32.1.3-android` beside `32.1.3-jre` — that order is not merely different from
//!   Maven's, it is meaningless: neither variant is an upgrade of the other. See
//!   [`partitioning_flavours`], which is what lets a caller compare only within one
//!   of them — and which reads the flavours off the published list, because the
//!   version string alone cannot tell a variant from a release-channel word.
//! - **`ga`/`final`/`release`** are Maven's aliases for "no qualifier", so
//!   `6.4.4.Final` translates to `6.4.4` — correct for comparison, and the reason a
//!   version *reported* for such an artifact is spelled without the suffix.

use std::collections::{BTreeMap, BTreeSet};

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

/// The word a Maven version *could* be flavoured on, if any.
///
/// A flavour is a variant of one release built for a different target —
/// `com.google.guava:guava` publishes `32.1.3-android` and `32.1.3-jre`, and an
/// Android project moved onto the JRE jar is the classic desugaring break. It is
/// not a version: nothing in the `android` line is an upgrade of anything in the
/// `jre` line, so the two are never ranked against each other.
///
/// A version flavours on its **final** token, when that token is not numeric and is
/// not one of Maven's own qualifier words ([`qualifier_alias`] recognizes those, so
/// `6.4.4.Final`, `1.0-rc1`, and `1.0-SNAPSHOT` all flavour as `None`).
///
/// This is a question about one string, and one string cannot answer it: `-android`
/// and `-incubating` tokenize identically, and only the first names a variant. So
/// this is a *candidate* word, and whether it really partitions the artifact is
/// [`partitioning_flavours`]'s answer, from the published list. A caller
/// restricting candidates to a flavour must ask that one — filtering on the word
/// alone hides `0.8.0` from a project on `0.7.0-incubating`.
///
/// A flavour carrying its own number (`1.0-jdk8`) is deliberately **not**
/// recognized. It tokenizes exactly like a dated build stamp (`9.4.51.v20230217`,
/// which Jetty publishes across its whole 9.4 line), and reading that as a flavour
/// would restrict Jetty to the 9.4 line and hide every major release above it —
/// a worse failure than the one it would fix, and unguessable from the version
/// string alone.
#[must_use]
pub fn flavour(version: &str) -> Option<String> {
    flavour_of(&tokenize(version))
}

/// [`flavour`] for a version that is already tokenized.
fn flavour_of(tokens: &[String]) -> Option<String> {
    let last = tokens.last()?;
    if is_numeric(last) {
        return None;
    }
    // A word Maven itself ranks is a qualifier, not a variant; `ga`/`final`/
    // `release` (which alias to `None`) are the release itself.
    (qualifier_alias(last) == Some(last.as_str()) && !KNOWN_QUALIFIERS.contains(&last.as_str()))
        .then(|| last.clone())
}

/// The flavour words a published version list is actually *partitioned* by.
///
/// A flavour is a **parallel** line: the same numeric release is published under it
/// and under at least one other spelling, because the two are builds of one release
/// rather than successive releases. `33.7.1-android` beside `33.7.1-jre` is that
/// shape; `0.7.0-incubating` graduating to `0.8.0` is not — each release is
/// published once, under one spelling.
///
/// That difference is only visible in the list, which is why it is derived here and
/// not from the version string. A word this does not return is part of the version,
/// not a variant of it, and restricting a candidate list to it would hide releases:
/// Apache projects graduate out of `-incubating`, and Guava's own line is
/// unflavoured through `23.0` and flavoured from `23.1` on, so a project on either
/// side of that split would be told it is up to date forever.
///
/// Releases are grouped by their [`maven_to_semver`] translation, so `1.0` and
/// `1.0.0` — one version in Maven's order — are one release here too.
#[must_use]
pub fn partitioning_flavours<'a>(versions: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let mut spellings: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::new();
    for version in versions {
        let tokens = tokenize(version);
        let flavour = flavour_of(&tokens);
        let release = if flavour.is_some() {
            &tokens[..tokens.len() - 1]
        } else {
            &tokens[..]
        };
        let joined = release.join(".");
        let key = maven_to_semver(&joined).unwrap_or(joined);
        spellings.entry(key).or_default().insert(flavour);
    }
    spellings
        .into_values()
        .filter(|under| under.len() > 1)
        .flat_map(|under| under.into_iter().flatten())
        .collect()
}

/// Whether a Maven version names a pre-release.
///
/// Maven spells these with a dot as readily as with a hyphen (`6.0.0.M1`,
/// `8.0.0.Beta1`, `5.3.0.RC1`) and abbreviates the words (`2.0-M1`, `2.0-CR1`,
/// `2.0-a1`), so no fixed set of `-alpha`-style suffixes finds them. Tokenizing the
/// way Maven does and canonicalizing each qualifier word through
/// [`qualifier_alias`] finds every spelling of one, and only in qualifier position:
/// `9.4.51.v20230217` is a dated build of a release, not a milestone.
#[must_use]
pub fn is_prerelease(version: &str) -> bool {
    tokenize(version)
        .iter()
        .filter(|token| !is_numeric(token))
        .filter_map(|token| qualifier_alias(token))
        .any(|canonical| PRERELEASE_QUALIFIERS.contains(&canonical))
}

/// Every qualifier word Maven's own order ranks, in its canonical spelling.
const KNOWN_QUALIFIERS: &[&str] = &["alpha", "beta", "milestone", "rc", "snapshot", "sp"];

/// The qualifiers that mark a version as not yet released. Maven's table plus
/// `pre`/`dev`, which projects use for the same purpose without Maven ranking them.
const PRERELEASE_QUALIFIERS: &[&str] =
    &["alpha", "beta", "milestone", "rc", "snapshot", "pre", "dev"];

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

    /// Maven separates a qualifier with a dot as readily as with a hyphen, and
    /// abbreviates the word — so a `-alpha`/`-beta`/`-rc` suffix list finds almost
    /// none of them, and the default filter offered a beta as the latest release.
    #[test]
    fn a_qualifier_marks_a_prerelease_however_maven_spells_it() {
        for version in [
            "6.0.0.M1",
            "8.0.0.Beta1",
            "5.3.0.RC1",
            "2.0-M1",
            "2.0-CR1",
            "2.0-a1",
            "1.0-alpha1",
            "1.0-SNAPSHOT",
            "7.1.0-milestone.1",
        ] {
            assert!(is_prerelease(version), "{version} is a pre-release");
        }
    }

    #[test]
    fn a_release_is_not_a_prerelease_whatever_it_is_stamped_with() {
        for version in [
            "6.4.4.Final",
            "5.3.9.RELEASE",
            "1.0-ga",
            "1.0.0",
            "32.1.3-android",
            "33.7.1-jre",
            // A dated build of a release, not a milestone: the `v` is not a
            // qualifier word and the number is not a milestone number.
            "9.4.51.v20230217",
            "2.5.6-sec03",
            "1.2.3.4",
        ] {
            assert!(!is_prerelease(version), "{version} is a release");
        }
    }

    /// A flavour is which artifact, not which release: `guava` publishes
    /// `32.1.3-android` beside `32.1.3-jre`, and neither is an upgrade of the other.
    #[test]
    fn an_unknown_trailing_qualifier_is_a_flavour() {
        assert_eq!(flavour("32.1.3-android").as_deref(), Some("android"));
        assert_eq!(flavour("33.7.1-jre").as_deref(), Some("jre"));
        assert_ne!(flavour("32.1.3-android"), flavour("33.7.1-jre"));
    }

    #[test]
    fn a_qualifier_maven_ranks_is_not_a_flavour() {
        for version in [
            "1.0.0",
            "6.4.4.Final",
            "5.3.9.RELEASE",
            "1.0-rc1",
            "1.0-cr1",
            "1.0-SNAPSHOT",
            "1.0-alpha1",
            "1.0-sp1",
            "1.2.3.4",
            // The reason a flavour is read off the *final* token only: this
            // tokenizes exactly as `1.0-jdk8` does, and reading it as a variant
            // would pin Jetty to its 9.4 line and hide every release above it.
            "9.4.51.v20230217",
            "2.5.6-sec03",
        ] {
            assert_eq!(flavour(version), None, "{version}");
        }
    }

    /// The word is only a candidate. What makes it a flavour is the registry
    /// publishing one release under it *and* under another spelling — Guava's
    /// `33.7.1` exists as both `-android` and `-jre`, so both words partition.
    #[test]
    fn a_word_two_builds_of_one_release_share_is_a_flavour() {
        let guava = [
            "33.7.1-jre",
            "33.7.1-android",
            "23.1-jre",
            "23.1-android",
            "23.0",
            "22.0",
        ];
        let found = partitioning_flavours(guava);
        assert!(found.contains("android"), "{found:?}");
        assert!(found.contains("jre"), "{found:?}");
    }

    /// And a word each release is published under exactly once is not a flavour,
    /// however unfamiliar it looks. Apache projects graduate out of `-incubating`
    /// to a plain release; treating the word as a variant would hide every
    /// graduated version from a project still on the incubating one.
    #[test]
    fn a_release_channel_word_is_not_a_flavour() {
        for line in [
            ["0.9.0", "0.8.0", "0.7.0-incubating"],
            ["2.0.0", "1.1.0", "1.0.0-preview"],
            ["1.2.0", "1.1.0", "1.0.0-dev"],
        ] {
            assert!(
                partitioning_flavours(line).is_empty(),
                "{line:?} publishes each release once"
            );
        }
    }

    /// A dated build stamp partitions nothing either: Jetty stamps its whole 9.4
    /// line, but each stamp belongs to one release.
    #[test]
    fn a_line_with_no_parallel_builds_partitions_on_nothing() {
        assert!(
            partitioning_flavours(["12.0.9", "9.4.53.v20231009", "9.4.51.v20230217"]).is_empty()
        );
        assert!(partitioning_flavours(["6.6.0.Final", "6.4.4.Final"]).is_empty());
    }

    /// `1.0` and `1.0.0` are one version in Maven's order, so a build published
    /// against the short spelling is a parallel build of the padded one.
    #[test]
    fn a_release_is_grouped_by_its_translation_not_its_spelling() {
        let found = partitioning_flavours(["1.0.0", "1.0-jre"]);
        assert!(found.contains("jre"), "{found:?}");
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
