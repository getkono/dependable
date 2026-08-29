//! CVSS base-score arithmetic for the vector strings OSV publishes.
//!
//! OSV never publishes a numeric CVSS score — a `severity` entry's `score` field
//! is always a *vector string* — so a numeric score has to be computed. This
//! implements the CVSS v3.1 specification §7.1 and Appendix A base-score
//! equations directly, which keeps the scoring dependency-free.
//!
//! Only v3.0 and v3.1 are scored. A v2 or v4 vector is recognized (so the
//! advisory still records which revision it was published in) but not scored:
//! v4's base score is a 270-entry MacroVector lookup with interpolation, far
//! more embedded data than the small minority of v4-only advisories warrants,
//! and a v4 vector almost always ships alongside a v3 one that is scored.
//!
//! Temporal and environmental metrics (`E:`, `RL:`, `RC:`, `CR:`, …) are parsed
//! past and ignored — the base score is what NVD and GitHub publish as "the CVSS
//! score". A vector that is truncated, malformed, or carries an unrecognized
//! value for a base metric yields `None`, never a partial score.

use dependable_core::result::CvssVersion;

/// Which CVSS revision `vector` is written in, if it looks like a CVSS vector.
///
/// v3 and v4 vectors are self-identifying via their `CVSS:<major>.<minor>/`
/// prefix. A v2 vector has no prefix at all, so it is recognized by its shape:
/// it starts with the access-vector metric and carries v2's `Au` metric.
pub(super) fn version_of(vector: &str) -> Option<CvssVersion> {
    let vector = vector.trim().trim_start_matches('(');
    if vector.starts_with("CVSS:3.") {
        Some(CvssVersion::V3)
    } else if vector.starts_with("CVSS:4.") {
        Some(CvssVersion::V4)
    } else if vector.starts_with("CVSS:2.") || (vector.starts_with("AV:") && vector.contains("Au:"))
    {
        Some(CvssVersion::V2)
    } else {
        None
    }
}

/// The CVSS base score for a v3.0 or v3.1 vector, in `0.0..=10.0`.
///
/// Returns `None` for any vector this cannot score with confidence: a v2 or v4
/// vector, a missing or duplicated-away base metric, an unrecognized metric
/// value, or a malformed segment.
pub(super) fn base_score(vector: &str) -> Option<f64> {
    let vector = vector.trim();
    // v3.1 and v3.0 differ only in how the final value is rounded up, but they
    // deliberately disagree: v3.1's integer roundup exists to fix the
    // floating-point edge cases v3.0's decimal ceiling got wrong.
    let (body, roundup): (&str, fn(f64) -> f64) = vector
        .strip_prefix("CVSS:3.1/")
        .map(|body| (body, roundup_v3_1 as fn(f64) -> f64))
        .or_else(|| {
            vector
                .strip_prefix("CVSS:3.0/")
                .map(|body| (body, roundup_v3_0 as fn(f64) -> f64))
        })?;

    let mut metrics: Vec<(&str, &str)> = Vec::new();
    for segment in body.split('/') {
        let (key, value) = segment.split_once(':')?;
        if key.is_empty() || value.is_empty() {
            return None;
        }
        metrics.push((key, value));
    }
    let get = |key: &str| metrics.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);

    // Scope is resolved first: it selects the privileges-required weights and
    // both the impact equation and the final multiplier.
    let scope_changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let attack_vector = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let attack_complexity = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let privileges_required = match get("PR")? {
        "N" => 0.85,
        "L" if scope_changed => 0.68,
        "L" => 0.62,
        "H" if scope_changed => 0.50,
        "H" => 0.27,
        _ => return None,
    };
    let user_interaction = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let confidentiality = impact_metric(get("C")?)?;
    let integrity = impact_metric(get("I")?)?;
    let availability = impact_metric(get("A")?)?;

    let iss = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup(raw))
}

/// The weight of one confidentiality/integrity/availability impact metric.
fn impact_metric(value: &str) -> Option<f64> {
    match value {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    }
}

/// CVSS v3.1 Appendix A `Roundup`: round to the smallest one-decimal value that
/// is not smaller than the input, computed on integers so that a value only
/// *representationally* above a decimal boundary is not rounded up past it.
fn roundup_v3_1(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) as f64 + 1.0) / 10.0
    }
}

/// CVSS v3.0's roundup: a plain decimal ceiling. Kept distinct from
/// [`roundup_v3_1`] because the two disagree, and a v3.0 vector must score the
/// way its publisher scored it.
fn roundup_v3_0(value: f64) -> f64 {
    (value * 10.0).ceil() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use dependable_core::result::Severity;

    /// Scores are one-decimal values, so an exact-equality assertion would be
    /// hostage to the last floating-point bit.
    fn assert_score(vector: &str, expected: f64) {
        let actual = base_score(vector).unwrap_or_else(|| panic!("{vector} did not score"));
        assert!(
            (actual - expected).abs() < 1e-9,
            "{vector}: expected {expected}, got {actual}"
        );
    }

    #[test]
    fn scores_the_golden_vectors() {
        // (vector, base score, band) — each verified against the published score
        // for the advisory or example it comes from.
        let cases: &[(&str, f64, Severity)] = &[
            // RUSTSEC-2020-0071.
            (
                "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                6.2,
                Severity::Medium,
            ),
            // GHSA-29mw-wpgm-hmr9 (lodash).
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                5.3,
                Severity::Medium,
            ),
            // High privileges, total impact.
            (
                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                7.2,
                Severity::High,
            ),
            // Scope-changed XSS: exercises the changed impact equation, the
            // changed privileges table, and the 1.08 multiplier.
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                6.1,
                Severity::Medium,
            ),
            // Unauthenticated remote total compromise, published as v3.0.
            (
                "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                9.8,
                Severity::Critical,
            ),
            // No impact at all: zero, not "unscorable".
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                0.0,
                Severity::None,
            ),
        ];
        for (vector, expected, band) in cases {
            assert_score(vector, *expected);
            assert_eq!(Severity::from_score(*expected), *band, "{vector}");
        }
    }

    #[test]
    fn temporal_metrics_do_not_move_the_base_score() {
        assert_score(
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C",
            6.2,
        );
    }

    #[test]
    fn the_two_roundups_disagree_where_they_are_meant_to() {
        // A value a hair above a one-decimal boundary: v3.0's decimal ceiling
        // pushes it up a whole tenth, while v3.1's integer roundup — which
        // exists precisely to fix this — keeps it where it belongs.
        let just_over = 6.0 + 1e-15;
        assert!(just_over > 6.0, "the test value must be distinct from 6.0");
        assert!((roundup_v3_1(just_over) - 6.0).abs() < 1e-9);
        assert!((roundup_v3_0(just_over) - 6.1).abs() < 1e-9);
        // Where the input is unambiguously mid-band the two agree.
        assert!((roundup_v3_1(6.11) - 6.2).abs() < 1e-9);
        assert!((roundup_v3_0(6.11) - 6.2).abs() < 1e-9);
        // An exact one-decimal value is left alone by both.
        assert!((roundup_v3_1(6.2) - 6.2).abs() < 1e-9);
        assert!((roundup_v3_0(6.2) - 6.2).abs() < 1e-9);
    }

    #[test]
    fn unscorable_vectors_yield_no_score() {
        // v4: recognized, deliberately not scored.
        assert_eq!(
            base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            None
        );
        // v2: recognized, deliberately not scored.
        assert_eq!(base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
        // Truncated: base metrics missing.
        assert_eq!(base_score("CVSS:3.1/AV:N/AC:L"), None);
        // An unrecognized value for a base metric.
        assert_eq!(
            base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"),
            None
        );
        // A malformed segment.
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
        // Not a CVSS vector at all.
        assert_eq!(base_score("nonsense"), None);
        assert_eq!(base_score(""), None);
    }

    #[test]
    fn recognizes_the_revision_of_each_vector() {
        assert_eq!(
            version_of("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
            Some(CvssVersion::V3)
        );
        assert_eq!(
            version_of("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(CvssVersion::V3)
        );
        assert_eq!(
            version_of("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"),
            Some(CvssVersion::V4)
        );
        assert_eq!(
            version_of("AV:N/AC:L/Au:N/C:P/I:P/A:P"),
            Some(CvssVersion::V2)
        );
        assert_eq!(
            version_of("(AV:N/AC:L/Au:N/C:P/I:P/A:P)"),
            Some(CvssVersion::V2)
        );
        assert_eq!(version_of("nonsense"), None);
    }
}
