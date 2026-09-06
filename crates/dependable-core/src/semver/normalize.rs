//! Version / constraint normalization helpers and pre-release filtering.

use crate::ecosystem::Ecosystem;

/// How to treat pre-release / unstable versions when deciding what is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum UnstableFilter {
    /// Hide pre-releases (default).
    #[default]
    Exclude,
    /// Always consider pre-releases.
    IncludeAlways,
    /// Consider pre-releases only when the current version is itself a pre-release.
    IncludeIfCurrent,
}

impl UnstableFilter {
    /// Filter a candidate `versions` list according to this mode.
    ///
    /// `current` is the dependency's current version (its locked version, or its
    /// constraint when no lockfile is present) — used only by
    /// [`UnstableFilter::IncludeIfCurrent`]. If filtering would remove every
    /// candidate, the original list is returned unchanged so a pre-release-only
    /// package still resolves.
    #[must_use]
    pub fn filter(
        self,
        versions: &[String],
        current: Option<&str>,
        ecosystem: Ecosystem,
    ) -> Vec<String> {
        let keep_prereleases = match self {
            UnstableFilter::IncludeAlways => true,
            UnstableFilter::Exclude => false,
            UnstableFilter::IncludeIfCurrent => {
                current.is_some_and(|c| is_prerelease(c, ecosystem))
            }
        };
        if keep_prereleases {
            return versions.to_vec();
        }
        let stable: Vec<String> = versions
            .iter()
            .filter(|v| !is_prerelease(v, ecosystem))
            .cloned()
            .collect();
        if stable.is_empty() {
            versions.to_vec()
        } else {
            stable
        }
    }
}

/// Universal (case-insensitive) pre-release markers checked for every ecosystem.
const UNIVERSAL_PRERELEASE: &[&str] = &[
    "-alpha",
    "-beta",
    "-rc",
    "-snapshot",
    "-dev",
    "-preview",
    "-experimental",
    "-canary",
    "-pre",
    "-next",
    "-nightly",
    "-nullsafety",
    "-nnbd",
];

/// Additional dot-prefixed markers Python (PEP 440) uses.
const PYTHON_PRERELEASE: &[&str] = &[
    ".alpha",
    ".beta",
    ".rc",
    ".dev",
    ".snapshot",
    ".preview",
    ".experimental",
    ".canary",
    ".pre",
];

/// Whether `version` looks like a pre-release / unstable version for `ecosystem`.
///
/// A version that parses as semver answers for itself — that is the definition, and it
/// is exact in both directions. The substring test alone was wrong both ways:
/// `1.0.0-M1` and `1.0.0-unstable.3` are pre-releases carrying no listed marker, and
/// `1.2.3+build-rc` is a *stable* release whose build metadata happens to contain one.
///
/// The marker list is the fallback for the many ecosystem versions that are *not*
/// semver (PEP 440, NuGet's four-part versions, Go's `v` prefix), where a substring is
/// the best available signal, plus Python's implicit forms (`1.0a1`, `1.0b2`, `1.0rc1`).
///
/// The JVM needs both exceptions. Maven separates a qualifier with a dot as readily as
/// with a hyphen (`6.0.0.M1`, `8.0.0.Beta1`, `5.3.0.RC1`) and abbreviates the word
/// (`2.0-M1`, `2.0-CR1`, `2.0-a1`), none of which the marker list spells, so
/// [`maven::is_prerelease`](crate::semver::maven::is_prerelease) is consulted; and it
/// treats a trailing word as a build variant rather than a preview, so `32.1.3-android`
/// — which *is* semver with a pre-release segment — is a release, and the semver
/// reading is skipped there. Before both, the default `Exclude` filter offered a beta
/// as the latest stable release.
#[must_use]
pub fn is_prerelease(version: &str, ecosystem: Ecosystem) -> bool {
    // The semver reading is skipped for the JVM: `32.1.3-android` parses as semver with
    // a pre-release segment, but under Maven's order that trailing word is a build
    // variant of a release. Maven's tokenizer, consulted below, is the authority there.
    if !matches!(ecosystem, Ecosystem::Jvm)
        && let Ok(parsed) = ::semver::Version::parse(version.trim_start_matches('v'))
    {
        return !parsed.pre.is_empty();
    }
    let lower = version.to_ascii_lowercase();
    if UNIVERSAL_PRERELEASE.iter().any(|m| lower.contains(m)) {
        return true;
    }
    match ecosystem {
        Ecosystem::Python => {
            PYTHON_PRERELEASE.iter().any(|m| lower.contains(m))
                || python_implicit_prerelease(&lower)
        }
        // Maven's qualifiers are tokens, not suffixes, so they are recognized by the
        // tokenizer that already models Maven's order rather than by substring — which
        // would read `9.4.51.v20230217` (a dated build of a release) as unstable.
        Ecosystem::Jvm => crate::semver::maven::is_prerelease(version),
        _ => false,
    }
}

/// Detect PEP 440 implicit pre-release segments: `a`/`b` followed by a digit, or
/// a `rc` segment adjacent to a digit (e.g. `1.0a1`, `1.0b2`, `1.0rc1`).
fn python_implicit_prerelease(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    for i in 0..bytes.len() {
        let c = bytes[i];
        if (c == b'a' || c == b'b') && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return true;
        }
        if c == b'r' && bytes.get(i + 1) == Some(&b'c') {
            let after_digit = bytes.get(i + 2).is_some_and(u8::is_ascii_digit);
            let before_digit = i > 0 && bytes[i - 1].is_ascii_digit();
            if after_digit || before_digit {
                return true;
            }
        }
    }
    false
}

/// Normalize a version requirement string into something `semver::VersionReq`
/// accepts.
///
/// For Rust this is largely a pass-through — the `semver` crate already
/// understands Cargo's syntax (`1`, `1.2`, `^1.2.3`, `=1.0.0`, `>=1, <2`). We trim
/// whitespace and strip a leading `v`/`V` before a digit (Go's `v1.2.3`, some PHP
/// tags), which `semver::VersionReq` would otherwise reject. Ecosystems with
/// richer dialects (e.g. PEP 440) translate in dedicated modules.
#[must_use]
pub fn normalize_constraint(constraint: &str) -> String {
    let trimmed = constraint.trim();
    match trimmed.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest.to_string(),
        _ => trimmed.to_string(),
    }
}

/// Composer's stability flags. They qualify which *stability* of a release the
/// constraint admits, never which versions, so `2.8.*@dev` admits exactly what
/// `2.8.*` admits and a bare `@dev` admits everything.
const STABILITY_FLAGS: &[&str] = &["dev", "alpha", "beta", "rc", "stable"];

/// Strip a trailing Composer stability flag, returning the range that carries it.
fn strip_stability_flag(constraint: &str) -> &str {
    match constraint.rsplit_once('@') {
        Some((range, flag))
            if STABILITY_FLAGS
                .iter()
                .any(|known| flag.eq_ignore_ascii_case(known)) =>
        {
            range.trim()
        }
        _ => constraint,
    }
}

/// Translate a range written in the npm / Composer / Dart / Cargo dialect into a
/// `semver::VersionReq`-compatible string, returning the input unchanged when there
/// is nothing to translate.
///
/// The `semver` crate parses Cargo's spelling of a range and only Cargo's, so the
/// ordinary forms the other three ecosystems document — a `||` union, comparators
/// separated by spaces rather than commas, npm's hyphen range, a Composer stability
/// flag, Dart's `any` — all reached `VersionReq::parse` verbatim and failed. Those are
/// *valid* constraints this crate simply had no front-end for, and treating them as
/// unreadable input made a dependency the manifest declares correctly the reason a
/// whole run could not answer its gate.
///
/// Only a translation that itself parses is adopted. Anything else is handed back
/// untouched for [`check_version`](crate::semver::check_version) to classify, which is
/// what keeps a dist-tag (`latest`, `next`) and genuine garbage (`^^^bogus`)
/// distinguishable from each other downstream.
#[must_use]
pub fn normalize_range_constraint(constraint: &str) -> String {
    let trimmed = constraint.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // A dist-tag names a channel rather than a range. `check_version` resolves the one
    // that tracks the newest release; the rest have no range reading at all.
    if trimmed == "latest" {
        return trimmed.to_owned();
    }
    let core = strip_stability_flag(trimmed);
    // A bare `@dev` is "any version, dev stability" — the stability half is not a
    // version constraint, and what is left constrains nothing.
    if core.is_empty() {
        return "*".to_owned();
    }
    // Dart spells "no constraint" as `any`, and `pubspec.yaml` accepts it deliberately.
    // `*` is the same statement in a spelling `VersionReq` reads.
    if core.eq_ignore_ascii_case("any") || core == "x" || core == "X" {
        return "*".to_owned();
    }
    translate_union(core).unwrap_or_else(|| normalize_constraint(constraint))
}

/// Pick one branch of a `||` union: the one admitting the highest versions.
///
/// `VersionReq` has no union, so a branch has to be chosen. The highest lower bound
/// is the same choice [`hex_constraint_to_semver`](crate::semver::elixir::hex_constraint_to_semver)
/// and [`maven_constraint_to_semver`](crate::semver::maven::maven_constraint_to_semver)
/// already make, and for the reason they give: a union is written to widen what is
/// accepted, so resolving it to the oldest branch reports every release above that
/// branch as out of range.
fn translate_union(core: &str) -> Option<String> {
    let mut best: Option<((u64, u64, u64), String)> = None;
    for branch in core.split("||") {
        let branch = branch.trim();
        if branch.is_empty() {
            continue;
        }
        let Some(translated) = translate_conjunction(branch) else {
            continue;
        };
        let Ok(req) = ::semver::VersionReq::parse(&translated) else {
            continue;
        };
        let bound = lower_bound(&req);
        if best
            .as_ref()
            .is_none_or(|(best_bound, _)| bound > *best_bound)
        {
            best = Some((bound, translated));
        }
    }
    best.map(|(_, translated)| translated)
}

/// The lowest version a requirement admits, used only to rank union branches.
fn lower_bound(req: &::semver::VersionReq) -> (u64, u64, u64) {
    use ::semver::Op;
    req.comparators
        .iter()
        .filter(|c| {
            matches!(
                c.op,
                Op::Greater | Op::GreaterEq | Op::Exact | Op::Caret | Op::Tilde
            )
        })
        .map(|c| (c.major, c.minor.unwrap_or(0), c.patch.unwrap_or(0)))
        .max()
        .unwrap_or((0, 0, 0))
}

/// Translate one branch of a union: an intersection of comparators, which npm and
/// Composer separate with spaces and Cargo with commas, or npm's hyphen range.
fn translate_conjunction(branch: &str) -> Option<String> {
    if let Some((low, high)) = branch.split_once(" - ") {
        return hyphen_range(low.trim(), high.trim());
    }
    let mut parts: Vec<String> = Vec::new();
    let mut pending_op: Option<&str> = None;
    for token in branch.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
        // `>= 1.2.3` writes the operator and the version as two tokens.
        if token
            .chars()
            .all(|c| matches!(c, '>' | '<' | '=' | '^' | '~' | '!'))
        {
            pending_op = Some(token);
            continue;
        }
        let version = normalize_constraint(token);
        parts.push(match pending_op.take() {
            Some(op) => format!("{op}{version}"),
            None => version,
        });
    }
    (!parts.is_empty() && pending_op.is_none()).then(|| parts.join(", "))
}

/// npm's hyphen range: `1.2.3 - 2.3.4` admits both endpoints.
///
/// A partial upper bound bounds the segment it stops at rather than padding with
/// zeros — npm reads `1.2.3 - 2.3` as every `2.3.x`, so padding it to `<=2.3.0`
/// would exclude releases the author accepted.
fn hyphen_range(low: &str, high: &str) -> Option<String> {
    if high.contains(char::is_whitespace) {
        return None;
    }
    let low = normalize_version(low);
    ::semver::Version::parse(&low).ok()?;
    let high = high.strip_prefix(['v', 'V']).unwrap_or(high);
    let nums: Vec<u64> = high
        .split('.')
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    let upper = match nums.as_slice() {
        [major] => format!("<{}.0.0", major.checked_add(1)?),
        [major, minor] => format!("<{major}.{}.0", minor.checked_add(1)?),
        [major, minor, patch] => format!("<={major}.{minor}.{patch}"),
        _ => return None,
    };
    Some(format!(">={low}, {upper}"))
}

/// Whether `constraint` names something — a channel, a branch alias — rather than
/// stating a range badly.
///
/// The two have to be told apart because they call for opposite answers. `^^^bogus`
/// is not a constraint at all and the run should say so; npm's `next`, Composer's
/// `dev-master`, and a Git branch alias are ordinary declarations in dialects this
/// crate has no front-end for, and failing a build over one punishes the user for a
/// gap that is ours. A name is spelled the way a name is spelled: it opens with a
/// letter and carries no comparison operator anywhere.
#[must_use]
pub fn is_dialect_tag(constraint: &str) -> bool {
    let c = constraint.trim();
    c.starts_with(|ch: char| ch.is_ascii_alphabetic())
        && c.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/'))
}

/// Convert a constraint into a `semver::VersionReq`-compatible string for the
/// given ecosystem. Python, NuGet, Hex and Maven translate in dedicated modules;
/// every other ecosystem writes a dialect close enough to Cargo's that
/// [`normalize_range_constraint`] covers it.
#[must_use]
pub fn to_semver_constraint(constraint: &str, ecosystem: Ecosystem) -> String {
    match ecosystem {
        Ecosystem::Python => crate::semver::python::pep440_constraint_to_semver(constraint),
        Ecosystem::CSharp => crate::semver::nuget::nuget_constraint_to_semver(constraint),
        Ecosystem::Elixir => crate::semver::elixir::hex_constraint_to_semver(constraint),
        Ecosystem::Jvm => crate::semver::maven::maven_constraint_to_semver(constraint),
        _ => normalize_range_constraint(constraint),
    }
}

/// Convert a constraint for `semver`, or `None` when the ecosystem's dialect could
/// not be expressed as a `semver::VersionReq`.
///
/// All four dedicated translators signal failure the same way — by returning an empty
/// string. [`maven_constraint_to_semver`](crate::semver::maven::maven_constraint_to_semver)
/// and [`nuget_constraint_to_semver`](crate::semver::nuget::nuget_constraint_to_semver)
/// do so for an unreadable version, a malformed interval, or a wildcard shape they do
/// not recognise; [`pep440_constraint_to_semver`](crate::semver::python::pep440_constraint_to_semver)
/// does so once every clause has been dropped; and
/// [`hex_constraint_to_semver`](crate::semver::elixir::hex_constraint_to_semver) does so
/// when no union branch converted. An empty result is therefore ambiguous on its own:
/// it means "the author declared no constraint" *and* "we could not read the constraint
/// the author declared", and the checker treating the second as the first turned it
/// into `*` — which resolves to the newest release and reports `up to date`, the one
/// answer a constraint that was never understood must not give.
///
/// The two are told apart by what went in: an empty result from a **non-empty** input
/// is a failed translation. That reading is only sound because every translator's
/// failure path is spelled this one way — three of them used to widen to `"*"` or echo
/// their input verbatim instead, which is a failure this guard cannot see and which
/// produces exactly the confident `up to date` it exists to prevent.
///
/// The remaining ecosystems have no dedicated translator and never signal failure here:
/// [`normalize_range_constraint`] hands an untranslatable range back unchanged, and
/// [`check_version`](crate::semver::check_version) classifies it.
#[must_use]
pub fn try_to_semver_constraint(constraint: &str, ecosystem: Ecosystem) -> Option<String> {
    let translated = to_semver_constraint(constraint, ecosystem);
    if translated.trim().is_empty() && !constraint.trim().is_empty() {
        return None;
    }
    Some(translated)
}

/// Normalize a concrete version string: strip a leading `v`/`V` and pad partial
/// versions (`1` → `1.0.0`, `1.2` → `1.2.0`) so they parse as `semver::Version`.
#[must_use]
pub fn normalize_version(version: &str) -> String {
    let trimmed = version.trim();
    let stripped = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    let core = stripped.split(['-', '+']).next().unwrap_or(stripped);
    let suffix = &stripped[core.len()..];
    match core.bytes().filter(|&b| b == b'.').count() {
        0 => format!("{core}.0.0{suffix}"),
        1 => format!("{core}.0{suffix}"),
        _ => stripped.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_partial_versions() {
        assert_eq!(normalize_version("1"), "1.0.0");
        assert_eq!(normalize_version("1.2"), "1.2.0");
        assert_eq!(normalize_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn strips_v_prefix() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("V2.0"), "2.0.0");
    }

    #[test]
    fn trims_constraint() {
        assert_eq!(normalize_constraint("  ^1.0 "), "^1.0");
    }

    #[test]
    fn strips_leading_v_from_constraint() {
        assert_eq!(normalize_constraint("v1.2.3"), "1.2.3");
        assert_eq!(normalize_constraint("V2.0"), "2.0");
        // A `v` not before a digit (or part of an operator constraint) is kept.
        assert_eq!(normalize_constraint("^1.0"), "^1.0");
        assert_eq!(normalize_constraint(">=1, <2"), ">=1, <2");
    }

    fn vers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// Assert that `constraint` translates to something `VersionReq` actually accepts.
    ///
    /// `is_some()` alone was the false assurance that let this whole class of defect
    /// ship: a translation is only a translation if the result parses, and every witness
    /// below returned `Some` while failing `VersionReq::parse` downstream.
    fn assert_translates(constraint: &str, ecosystem: Ecosystem) -> ::semver::VersionReq {
        let translated = try_to_semver_constraint(constraint, ecosystem)
            .unwrap_or_else(|| panic!("{ecosystem:?} `{constraint}` translated to nothing"));
        ::semver::VersionReq::parse(&translated).unwrap_or_else(|e| {
            panic!("{ecosystem:?} `{constraint}` translated to `{translated}`, which is not a requirement: {e}")
        })
    }

    /// Every ecosystem's spelling of "any version", plus the ordinary forms around it.
    /// A translator that drops one of these hands the checker an empty string, which
    /// [`try_to_semver_constraint`] then reports as a constraint it could not read —
    /// which is how `requests = "*"` became `undetermined` for every Poetry project
    /// with an unpinned dependency.
    #[test]
    fn a_constraint_that_states_something_never_translates_to_nothing() {
        let cases: &[(Ecosystem, &str)] = &[
            (Ecosystem::Python, "*"),
            (Ecosystem::Python, ">=1.0"),
            (Ecosystem::Python, "==1.2.3"),
            (Ecosystem::Python, "~=1.4"),
            (Ecosystem::Python, "==1.0.*"),
            (Ecosystem::Python, "^1.2"),
            (Ecosystem::Python, "~1.2"),
            (Ecosystem::Python, ">=1.0,<2.0"),
            (Ecosystem::Python, "1.2.3"),
            (Ecosystem::Python, "===1.0"),
            (Ecosystem::CSharp, "*"),
            (Ecosystem::CSharp, "1.0.0"),
            (Ecosystem::CSharp, "[1.0,2.0)"),
            (Ecosystem::CSharp, "1.*"),
            (Ecosystem::Jvm, "+"),
            (Ecosystem::Jvm, "latest.release"),
            (Ecosystem::Jvm, "1.+"),
            (Ecosystem::Jvm, "[1.0,2.0)"),
            (Ecosystem::Elixir, "~> 1.0"),
            (Ecosystem::Elixir, ">= 1.0.0"),
            (Ecosystem::Rust, "*"),
            (Ecosystem::Npm, "*"),
            (Ecosystem::Npm, "1.x"),
            (Ecosystem::Php, "*"),
            (Ecosystem::Dart, "any"),
        ];
        for (ecosystem, constraint) in cases {
            assert_translates(constraint, *ecosystem);
        }
    }

    /// The ranges npm, Composer and Dart document, none of which the `semver` crate
    /// parses on its own.
    ///
    /// Every one of these used to reach `VersionReq::parse` verbatim and fail, which the
    /// checker recorded as a dependency the run could not evaluate — and a single one of
    /// those makes the whole repository unanswerable under the shipped Action's default
    /// `fail-on: vulnerable`. They are valid constraints; the gap was ours.
    #[test]
    fn the_documented_range_dialects_translate_into_something_that_parses() {
        let v = |s: &str| ::semver::Version::parse(s).expect(s);
        // (ecosystem, constraint, versions it must admit, versions it must not)
        let cases: &[(Ecosystem, &str, &[&str], &[&str])] = &[
            (
                Ecosystem::Npm,
                ">=16.8.0 <19.0.0",
                &["16.8.0", "18.3.1"],
                &["16.7.0", "19.0.0"],
            ),
            (
                Ecosystem::Npm,
                "^15.0.0 || ^16.0.0",
                &["16.8.0"],
                &["17.0.0"],
            ),
            (
                Ecosystem::Npm,
                "1.2.3 - 2.3.4",
                &["1.2.3", "2.0.0", "2.3.4"],
                &["1.2.2", "2.3.5"],
            ),
            // A partial upper bound bounds the segment it stops at: `2.3` is every 2.3.x.
            (
                Ecosystem::Npm,
                "1.2.3 - 2.3",
                &["2.3.9"],
                &["1.2.2", "2.4.0"],
            ),
            (Ecosystem::Npm, ">= 1.2.3", &["1.2.3", "9.0.0"], &["1.2.2"]),
            // Dart's `any` is "no constraint", which is what `*` says.
            (Ecosystem::Dart, "any", &["0.0.1", "9.9.9"], &[]),
            // A Composer stability flag qualifies stability, not versions.
            (Ecosystem::Php, "2.8.*@dev", &["2.8.0", "2.8.9"], &["2.9.0"]),
            (Ecosystem::Php, "@dev", &["0.1.0", "9.9.9"], &[]),
            (
                Ecosystem::Php,
                "^1.0 || ^2.0",
                &["2.4.0"],
                &["3.0.0", "0.9.0"],
            ),
        ];
        for (ecosystem, constraint, admits, rejects) in cases {
            let req = assert_translates(constraint, *ecosystem);
            for version in *admits {
                assert!(
                    req.matches(&v(version)),
                    "`{constraint}` rejected {version}"
                );
            }
            for version in *rejects {
                assert!(
                    !req.matches(&v(version)),
                    "`{constraint}` admitted {version}"
                );
            }
        }
    }

    /// A dialect this crate cannot express must reach the checker as a failed
    /// translation — an empty result — or as a name the checker recognises as a name.
    /// Either way the dependency is `undetermined`, which claims nothing; what it must
    /// never be is a range that silently means something else.
    #[test]
    fn a_dialect_with_no_front_end_is_never_mistaken_for_a_range() {
        // Failed translations: the translator drops everything it could not read.
        for (ecosystem, constraint) in [
            (Ecosystem::Elixir, "!= 1.0.0"),
            (Ecosystem::Python, "!=2.31.0"),
        ] {
            assert_eq!(
                try_to_semver_constraint(constraint, ecosystem),
                None,
                "{ecosystem:?} `{constraint}`"
            );
        }
        // Names: handed back untouched, and recognised as names rather than as ranges
        // somebody got wrong.
        for (ecosystem, constraint) in [
            (Ecosystem::Npm, "next"),
            (Ecosystem::Npm, "beta"),
            (Ecosystem::Npm, "canary"),
            (Ecosystem::Php, "dev-master"),
        ] {
            let translated = try_to_semver_constraint(constraint, ecosystem)
                .expect("a name is handed back, not dropped");
            assert!(
                ::semver::VersionReq::parse(&translated).is_err(),
                "{ecosystem:?} `{constraint}` must not be read as a range"
            );
            assert!(is_dialect_tag(&translated), "{ecosystem:?} `{constraint}`");
        }
        // `latest` is the one name with a range reading, and the checker owns it.
        assert_eq!(
            try_to_semver_constraint("latest", Ecosystem::Npm).as_deref(),
            Some("latest")
        );
    }

    /// The other side of [`is_dialect_tag`]: operators that announce a range and then do
    /// not spell one are not names, and must stay a hard error.
    #[test]
    fn garbage_wearing_range_operators_is_not_a_name() {
        for constraint in ["^^^bogus", ">=<1.0.0", "~~", "1.2.3", "*", "@dev"] {
            assert!(!is_dialect_tag(constraint), "{constraint}");
        }
        for constraint in ["next", "dev-master", "latest", "release/2.x"] {
            assert!(is_dialect_tag(constraint), "{constraint}");
        }
    }

    /// The other side of the same coin: a dialect semver genuinely cannot express must
    /// keep coming back as a failed translation, or the checker resolves it to `*` and
    /// reports `up to date` for a constraint nobody read.
    #[test]
    fn a_constraint_semver_cannot_express_stays_a_failed_translation() {
        // Exclusion has no semver spelling; `$(Version)` is an MSBuild property, not a
        // version; `LATEST`/`RELEASE` are Maven's server-resolved tags.
        for (ecosystem, constraint) in [
            (Ecosystem::Python, "!=1.5"),
            (Ecosystem::CSharp, "$(Version)"),
            (Ecosystem::Jvm, "LATEST"),
            (Ecosystem::Jvm, "RELEASE"),
        ] {
            assert_eq!(
                try_to_semver_constraint(constraint, ecosystem),
                None,
                "{ecosystem:?} `{constraint}`"
            );
        }
    }

    #[test]
    fn universal_prerelease_markers() {
        for v in ["1.0.0-alpha", "1.0.0-RC1", "2.0.0-beta.3", "1.0.0-SNAPSHOT"] {
            assert!(is_prerelease(v, Ecosystem::Rust), "{v}");
        }
        assert!(!is_prerelease("1.0.0", Ecosystem::Rust));
        assert!(!is_prerelease("1.2.3+build.5", Ecosystem::Rust));
    }

    #[test]
    fn python_specific_prereleases() {
        for v in ["1.0a1", "1.0b2", "1.0rc1", "1.0.dev3"] {
            assert!(is_prerelease(v, Ecosystem::Python), "{v}");
        }
        // The `[ab]\d` rule must not fire on non-Python ecosystems.
        assert!(!is_prerelease("1.0a1", Ecosystem::Rust));
        // A bare stable version is never a pre-release.
        assert!(!is_prerelease("1.0.0", Ecosystem::Python));
    }

    /// PEP 440 orders `1.0 < 1.0.post1`: a post-release is a *later* release of the same
    /// version, not a preview of it. Treating it as unstable hid it from the default
    /// filter, so a project on `1.0` was told it was current.
    #[test]
    fn a_python_post_release_is_not_a_prerelease() {
        for v in ["1.0.post1", "1.0.post2", "2.1.post0"] {
            assert!(!is_prerelease(v, Ecosystem::Python), "{v}");
        }
        // A post-release of a pre-release is still a pre-release.
        assert!(is_prerelease("1.0rc1.post1", Ecosystem::Python));
    }

    /// The old substring test was wrong in both directions, and each direction cost
    /// something: a missed pre-release is recommended as an upgrade, and a stable
    /// release whose build metadata happens to read `-rc` is hidden from one.
    #[test]
    fn semver_versions_are_classified_by_parsing_not_by_substring() {
        for v in [
            "1.0.0-M1",
            "1.0.0-CR2",
            "1.0.0-unstable.3",
            "1.0.0-0",
            "4.0.0-insiders",
        ] {
            assert!(is_prerelease(v, Ecosystem::Rust), "{v}");
        }
        for v in ["1.2.3+build-rc", "1.2.3+alpha", "1.0.0", "10.20.30"] {
            assert!(!is_prerelease(v, Ecosystem::Rust), "{v}");
        }
    }

    /// The marker list is hyphen-prefixed; Maven's qualifiers are not. Under the
    /// default `Exclude` filter this offered `8.0.0.Beta1` as Hibernate's latest
    /// release and `7.1.0.M1` as Spring's.
    #[test]
    fn jvm_specific_prereleases() {
        for v in ["6.0.0.M1", "8.0.0.Beta1", "5.3.0.RC1", "2.0-M1", "2.0-a1"] {
            assert!(is_prerelease(v, Ecosystem::Jvm), "{v}");
            // Nothing in the universal list matches these, which is the defect.
            assert!(!is_prerelease(v, Ecosystem::Rust), "{v}");
        }
        // `-SNAPSHOT` is the one form the universal list already covered.
        assert!(is_prerelease("1.0-SNAPSHOT", Ecosystem::Jvm));
        for v in [
            "6.4.4.Final",
            "5.3.9.RELEASE",
            "9.4.51.v20230217",
            "32.1.3-android",
        ] {
            assert!(!is_prerelease(v, Ecosystem::Jvm), "{v}");
        }
    }

    /// Under the default filter, the newest *release* is what a JVM project is
    /// offered — the whole list is not thrown away just because a beta tops it.
    #[test]
    fn the_default_filter_keeps_a_jvm_release_over_a_beta() {
        let out = UnstableFilter::Exclude.filter(
            &vers(&["8.0.0.Beta1", "6.6.0.Final", "6.4.4.Final"]),
            Some("6.4.4.Final"),
            Ecosystem::Jvm,
        );
        assert_eq!(out, vers(&["6.6.0.Final", "6.4.4.Final"]));
    }

    #[test]
    fn filter_exclude_drops_prereleases() {
        let out = UnstableFilter::Exclude.filter(
            &vers(&["1.0.0", "1.1.0-rc1", "1.2.0"]),
            None,
            Ecosystem::Rust,
        );
        assert_eq!(out, vers(&["1.0.0", "1.2.0"]));
    }

    #[test]
    fn filter_include_always_keeps_everything() {
        let input = vers(&["1.0.0", "1.1.0-rc1"]);
        let out = UnstableFilter::IncludeAlways.filter(&input, None, Ecosystem::Rust);
        assert_eq!(out, input);
    }

    #[test]
    fn filter_if_current_depends_on_current() {
        let input = vers(&["1.0.0", "1.1.0-rc1"]);
        // Stable current → drop pre-releases.
        let stable =
            UnstableFilter::IncludeIfCurrent.filter(&input, Some("1.0.0"), Ecosystem::Rust);
        assert_eq!(stable, vers(&["1.0.0"]));
        // Pre-release current → keep them.
        let pre =
            UnstableFilter::IncludeIfCurrent.filter(&input, Some("1.0.0-rc1"), Ecosystem::Rust);
        assert_eq!(pre, input);
    }

    #[test]
    fn filter_falls_back_when_only_prereleases() {
        let input = vers(&["1.0.0-rc1", "1.0.0-rc2"]);
        let out = UnstableFilter::Exclude.filter(&input, None, Ecosystem::Rust);
        assert_eq!(out, input);
    }
}
