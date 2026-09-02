//! Recognizing a constraint that names exactly one release.
//!
//! Most constraints are ranges: they say which releases a project would accept,
//! not which one it uses. A few name a single release outright — Cargo's
//! `=1.2.3`, PEP 440's `==2.28.1`, NuGet's `[1.2.3]`, a bare Maven or Hex
//! version — and for those the manifest has already answered the question a
//! lockfile would otherwise have to. [`exact_pin`] is how a caller with only a
//! manifest in hand tells the two apart.
//!
//! The decision is made by *translation*, not by a per-ecosystem table of
//! spellings: the constraint goes through the same
//! [`to_semver_constraint`](crate::semver::to_semver_constraint) every version
//! check already uses, and it is a pin exactly when that translation is a single
//! `=` comparator at full precision. Nothing here invents a reading an ecosystem's
//! translator does not already make, so a package this reports a version for is a
//! package [`check_version`](crate::semver::check_version) would call satisfied by
//! that same version and no other.

use ::semver::{Op, Version, VersionReq};

use crate::ecosystem::Ecosystem;
use crate::semver::normalize::{normalize_version, to_semver_constraint};

/// Characters that cannot appear inside a single published version, and whose
/// presence means the extracted literal is still part of a range, a union, or a
/// build-system expression rather than a version.
///
/// `-` and `+` are deliberately absent: they open semver's pre-release and build
/// metadata (`32.1.3-jre`, `1.2.3+sha.5114f85`), which are part of the version.
const NOT_IN_A_VERSION: &[char] = &[
    ',', '[', ']', '(', ')', '=', '<', '>', '~', '^', '!', '*', '|', '$', '"', '\'',
];

/// The single version a constraint names, or `None` when it names anything else.
///
/// Returns a slice of `constraint` itself — the version **as the manifest spells
/// it**, with only surrounding whitespace, an enclosing single-version interval
/// (`[1.2.3]`), and a leading exact-match operator (`=`, `==`, `===`) removed. It
/// is never the translated form. `to_semver_constraint` pads, truncates, and
/// rewrites to produce a string the comparison engine accepts: a Maven or NuGet
/// `1.0` becomes `1.0.0`, a Maven `6.4.4.Final` becomes `6.4.4`, a NuGet `1.0.0.4`
/// becomes `1.0.0`, and none of those names the artifact the manifest asked for. A
/// version reported to a user has to be one the registry actually publishes, so the
/// declared spelling is what comes back and the translation is used only to decide.
///
/// `None` for everything that admits more than one release: a range
/// (`^1.2`, `>=1, <2`, `[1.0,2.0)`), a union, a wildcard or floating selector
/// (`1.2.+`, `1.*`), a dist-tag (`latest`, `latest.release`), a partial-precision
/// exact requirement whose ecosystem leaves the rest free (Cargo `=1.2`), an
/// unparseable string, and an unexpanded build-system property
/// (`$(SerilogVersion)`).
///
/// It is also `None` for a pin whose spelling the comparison engine cannot parse —
/// a four-segment NuGet `1.2.3.4`, a Maven `6.4.4.Final`. Such a version is exact
/// beyond doubt, but every consumer of it compares with `semver::Version`, and one
/// that fails to parse is silently treated as *no* version at all: the comparison
/// falls back to the newest compatible release and reports the dependency as up to
/// date. Reporting nothing is honest; reporting a version that turns into a false
/// "ok" downstream is not.
///
/// Note that "exact" is the ecosystem's reading, not the string's shape. A bare
/// `1.2.3` is an exact version in Maven and Hex, a caret range in Cargo, npm, and
/// Python, and an open lower bound in NuGet — this reports a pin only where that
/// ecosystem's own translator already says so.
///
/// Pure: consults no registry, filesystem, or network.
///
/// # Examples
/// ```
/// use dependable_core::{Ecosystem, exact_pin};
///
/// assert_eq!(exact_pin("=1.2.3", Ecosystem::Rust), Some("1.2.3"));
/// assert_eq!(exact_pin("1.2.3", Ecosystem::Rust), None);
/// assert_eq!(exact_pin("==2.28.1", Ecosystem::Python), Some("2.28.1"));
/// // The declared spelling, never the translation (`1.0.0` names no artifact here).
/// assert_eq!(exact_pin("1.0", Ecosystem::Jvm), Some("1.0"));
/// ```
#[must_use]
pub fn exact_pin(constraint: &str, ecosystem: Ecosystem) -> Option<&str> {
    let literal = pin_literal(constraint)?;

    // The ecosystem's own translation decides. One comparator, `=`, at full
    // precision: anything else names a set, however exact it looks.
    let req = VersionReq::parse(&to_semver_constraint(constraint, ecosystem)).ok()?;
    let [only] = req.comparators.as_slice() else {
        return None;
    };
    if only.op != Op::Exact || only.minor.is_none() || only.patch.is_none() {
        return None;
    }

    // And the literal has to survive the trip every consumer makes with it.
    Version::parse(&normalize_version(literal)).ok()?;
    Some(literal)
}

/// Strip a constraint down to the version literal it is built around, without
/// interpreting it. Returns `None` when what is left could not be a version.
fn pin_literal(constraint: &str) -> Option<&str> {
    let mut c = constraint.trim();
    // An interval naming one version rather than a range: `[1.2.3]`.
    if let Some(inner) = c.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        c = inner.trim();
    }
    // Cargo's `=`, PEP 440's `==` and `===`, Hex's `==`.
    c = c.trim_start_matches('=').trim_start();
    if c.is_empty() || c.contains(NOT_IN_A_VERSION) || c.contains(char::is_whitespace) {
        return None;
    }
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One table over every ecosystem whose translator this consults, so a change
    /// to any of them shows up here rather than in a graph test.
    #[test]
    fn recognizes_exactly_the_constraints_that_name_one_release() {
        let cases: &[(&str, Ecosystem, Option<&str>)] = &[
            // -- C# / NuGet ------------------------------------------------
            // A bare `Version` is an inclusive *minimum* in NuGet, so it names a
            // set. See `semver::nuget`; #113 tracks whether that reading is right.
            ("13.0.1", Ecosystem::CSharp, None),
            ("[2.10.0,3.0.0)", Ecosystem::CSharp, None),
            ("[1.2.3]", Ecosystem::CSharp, Some("1.2.3")),
            ("1.*", Ecosystem::CSharp, None),
            // An unexpanded MSBuild property is not a version.
            ("$(SerilogVersion)", Ecosystem::CSharp, None),
            // Exact, but four segments: `semver::Version` cannot read it, so a
            // consumer would compare against nothing at all.
            ("[1.2.3.4]", Ecosystem::CSharp, None),
            // -- JVM / Maven + Gradle --------------------------------------
            ("4.12.0", Ecosystem::Jvm, Some("4.12.0")),
            ("1.9.24", Ecosystem::Jvm, Some("1.9.24")),
            ("3.14.0", Ecosystem::Jvm, Some("3.14.0")),
            // The declared spelling, not the translation: `maven_to_semver`
            // makes this `32.1.3`, which names no artifact on Maven Central.
            ("32.1.3-jre", Ecosystem::Jvm, Some("32.1.3-jre")),
            ("[1.0,2.0)", Ecosystem::Jvm, None),
            ("1.2.+", Ecosystem::Jvm, None),
            ("latest.release", Ecosystem::Jvm, None),
            // Exact in Maven, unreadable to `semver::Version`.
            ("6.4.4.Final", Ecosystem::Jvm, None),
            // -- Rust / Cargo ----------------------------------------------
            ("=1.2.3", Ecosystem::Rust, Some("1.2.3")),
            ("= 1.2.3", Ecosystem::Rust, Some("1.2.3")),
            ("1.2.3", Ecosystem::Rust, None),
            ("=1.2", Ecosystem::Rust, None),
            ("^1.2", Ecosystem::Rust, None),
            ("*", Ecosystem::Rust, None),
            (">=1, <2", Ecosystem::Rust, None),
            ("=1.2.3-alpha.1", Ecosystem::Rust, Some("1.2.3-alpha.1")),
            // -- npm --------------------------------------------------------
            ("^18.0.0", Ecosystem::Npm, None),
            ("latest", Ecosystem::Npm, None),
            ("1.2.3", Ecosystem::Npm, None),
            ("=1.3.0", Ecosystem::Npm, Some("1.3.0")),
            // -- Python -----------------------------------------------------
            ("==2.28.1", Ecosystem::Python, Some("2.28.1")),
            ("==0.20", Ecosystem::Python, Some("0.20")),
            (">=2.0", Ecosystem::Python, None),
            ("==1.0.*", Ecosystem::Python, None),
            ("~=1.4.2", Ecosystem::Python, None),
            (">=1.0,<2.0", Ecosystem::Python, None),
            // -- Elixir / Hex -----------------------------------------------
            ("3.10.3", Ecosystem::Elixir, Some("3.10.3")),
            ("== 3.10.3", Ecosystem::Elixir, Some("3.10.3")),
            ("~> 3.10", Ecosystem::Elixir, None),
            (">= 3.0.0", Ecosystem::Elixir, None),
            // -- Dart, Go, PHP ----------------------------------------------
            ("6.0.5", Ecosystem::Dart, None),
            ("^1.1.0", Ecosystem::Dart, None),
            ("v1.6.0", Ecosystem::Go, None),
            ("^2.0", Ecosystem::Php, None),
            // -- Nothing at all ---------------------------------------------
            ("", Ecosystem::Rust, None),
            ("   ", Ecosystem::Jvm, None),
            ("workspace:*", Ecosystem::Npm, None),
        ];

        for &(constraint, ecosystem, want) in cases {
            assert_eq!(
                exact_pin(constraint, ecosystem),
                want,
                "{constraint:?} ({ecosystem:?})"
            );
        }
    }

    /// The reported version has to exist on the registry, so it is a slice of what
    /// the manifest wrote. Every row here is one the translation *rewrites*, which
    /// is what makes returning the translated string a live hazard rather than a
    /// theoretical one.
    #[test]
    fn reports_the_declared_spelling_and_never_the_translation() {
        for (constraint, ecosystem) in [
            ("1.0", Ecosystem::Jvm),
            ("[1.0]", Ecosystem::CSharp),
            ("==0.20", Ecosystem::Python),
        ] {
            let pin = exact_pin(constraint, ecosystem).expect("a pin");
            assert!(
                constraint.contains(pin),
                "{pin:?} must be a slice of {constraint:?}"
            );
            assert_ne!(
                pin,
                to_semver_constraint(constraint, ecosystem).trim_start_matches('='),
                "{constraint:?} must not be reported in its translated form"
            );
        }
    }

    /// Whatever comes back is a version, not the empty string and not a fragment
    /// of the range it was cut out of — the invariant every caller relies on when
    /// it puts the result straight into a graph node.
    #[test]
    fn a_reported_pin_is_always_a_usable_version() {
        let probes = [
            "",
            " ",
            "=",
            "==",
            "===",
            "[]",
            "[,]",
            "[1.0,2.0]",
            "[1.0],[2.0]",
            "(,1.0],[1.2,)",
            ">=1",
            "1.x",
            "*",
            "+",
            "1.+",
            "latest",
            "^",
            "~>",
            "$(Prop)",
            "==1.0.*",
            "=1.2.3.4",
            "git+https://example.com/x#v1.2.3",
            "workspace:^1.0.0",
            "1.2.3 || 2.0.0",
            "=1.2.3, =1.2.3",
        ];
        for ecosystem in [
            Ecosystem::Rust,
            Ecosystem::Go,
            Ecosystem::Npm,
            Ecosystem::Python,
            Ecosystem::Php,
            Ecosystem::Dart,
            Ecosystem::CSharp,
            Ecosystem::Elixir,
            Ecosystem::Jvm,
        ] {
            for probe in probes {
                let Some(pin) = exact_pin(probe, ecosystem) else {
                    continue;
                };
                assert!(!pin.is_empty(), "{probe:?} ({ecosystem:?})");
                assert!(
                    Version::parse(&normalize_version(pin)).is_ok(),
                    "{probe:?} ({ecosystem:?}) yielded {pin:?}"
                );
            }
        }
    }
}
