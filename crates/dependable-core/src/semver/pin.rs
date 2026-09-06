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
//! `=` comparator at full precision *and* the declared literal is itself a
//! `semver::Version`. Nothing here invents a reading an ecosystem's translator does
//! not already make, so a package this reports a version for is a package
//! [`check_version`](crate::semver::check_version) would call satisfied by that
//! same version and no other.
//!
//! The two conditions answer different questions and neither implies the other.
//! The translation says what the ecosystem *means*; the parse of the raw literal
//! says whether the string that comes back is one a consumer can compare with. A
//! Maven `4.12` passes the first and fails the second: it means exactly `4.12`, but
//! every consumer reads `Node::version` as written, and `Version::parse("4.12")`
//! fails — which `check_version` treats as no locked version at all and answers
//! with a green `ok` against a registry offering `4.13.2`.

use ::semver::{Op, Version, VersionReq};

use crate::ecosystem::Ecosystem;
use crate::semver::normalize::to_semver_constraint;

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
/// (`$(SerilogVersion)`). A union of intervals (`[1.0],[2.0]`) is a set too, and
/// is rejected before translation: `maven::interval_range` keeps the last interval
/// of a union, so the translated form would look like a pin.
///
/// It is also `None` for a pin whose spelling the comparison engine cannot parse
/// **as written** — a four-segment NuGet `1.2.3.4`, a Maven `6.4.4.Final`, and
/// equally a two-segment Maven `4.12`, a NuGet `[1.0]`, or a PEP 440 `==0.20`.
/// Such a version is exact beyond doubt, but every consumer of it compares with
/// `semver::Version` on the declared string, and one that fails to parse is
/// silently treated as *no* version at all: the comparison falls back to the
/// newest compatible release and reports the dependency as up to date. A
/// `junit:junit` pinned at `4.12` would render a green `ok` against a registry
/// offering `4.13.2`. Reporting nothing is honest; reporting a version that turns
/// into a false "ok" downstream is not.
///
/// Padding the literal to make it parse is not available: `4.12.0` is a different
/// artifact from `4.12` and the registry may publish neither, so the only string
/// that can be reported is the declared one, and the only test that means anything
/// is whether *that* string parses.
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
/// // The declared spelling, never the translation (Maven reads a release alias as
/// // contributing nothing, so the translated `1.0.0` names a different artifact).
/// assert_eq!(exact_pin("1.0.0-RELEASE", Ecosystem::Jvm), Some("1.0.0-RELEASE"));
/// // Exact, but not a `semver::Version` as written, so no consumer could use it.
/// assert_eq!(exact_pin("4.12", Ecosystem::Jvm), None);
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

    // And the literal has to survive the trip every consumer makes with it, which
    // is `Version::parse` on the string exactly as written. Nothing downstream
    // pads: `declared_pin` puts this straight into a `Node::version`, and the
    // renderers, the JSON and DOT emitters, the OSV query, and the TUI's lookup
    // all read that field raw. Normalizing here would prove a claim about a string
    // no consumer ever constructs.
    Version::parse(literal).ok()?;
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
            // Exact, but two segments, and unreadable for the same reason. The
            // translation pads to `=1.0.0`; nothing downstream pads, so reporting
            // `1.0` would hand every consumer a string it reads as no version.
            ("[1.0]", Ecosystem::CSharp, None),
            // A union of intervals names a set. `nuget::interval_range` cannot read
            // one, but the Maven translator deliberately keeps the *last* interval,
            // so both are asserted rather than left to the character screen.
            ("[1.0],[2.0]", Ecosystem::CSharp, None),
            // -- JVM / Maven + Gradle --------------------------------------
            ("4.12.0", Ecosystem::Jvm, Some("4.12.0")),
            ("1.9.24", Ecosystem::Jvm, Some("1.9.24")),
            ("3.14.0", Ecosystem::Jvm, Some("3.14.0")),
            // A build variant, which `semver::Version` reads as a pre-release and
            // Maven keeps: reported as declared, because `32.1.3-android` is a
            // different artifact and Maven Central publishes no bare `32.1.3`.
            ("32.1.3-jre", Ecosystem::Jvm, Some("32.1.3-jre")),
            // A release alias the translation drops (`=1.0.0`). The declared
            // spelling is what the repository serves, so it is what comes back.
            ("1.0.0-RELEASE", Ecosystem::Jvm, Some("1.0.0-RELEASE")),
            ("[1.0,2.0)", Ecosystem::Jvm, None),
            ("1.2.+", Ecosystem::Jvm, None),
            ("latest.release", Ecosystem::Jvm, None),
            // Exact in Maven, unreadable to `semver::Version`.
            ("6.4.4.Final", Ecosystem::Jvm, None),
            // Exact in Maven and unreadable for the same reason: `junit:junit` is
            // published as `4.12`, not `4.12.0`, so the padded form names no
            // artifact and the declared form no consumer can parse. Reporting it
            // rendered a green `ok` against Maven Central's `4.13.2`.
            ("4.12", Ecosystem::Jvm, None),
            ("1.0", Ecosystem::Jvm, None),
            // `maven::interval_range` uses `rfind`, so it reads a union as its last
            // interval and would translate this to a single full-precision `=`. It
            // is a set, and stays one.
            ("[1.0],[2.0]", Ecosystem::Jvm, None),
            ("(,1.0],[1.2,)", Ecosystem::Jvm, None),
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
            // Exact under PEP 440, but `0.20` is not a `semver::Version`.
            ("==0.20", Ecosystem::Python, None),
            // A local version identifier is part of the distribution's version and
            // parses, so it survives even though the translation drops it.
            ("==1.2.3+local", Ecosystem::Python, Some("1.2.3+local")),
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
    ///
    /// The rewrites here are all *lossy* ones the guard permits — a Maven build
    /// variant, a Maven release alias, a PEP 440 local segment — never a padding of
    /// partial precision. Padding is how the translation used to differ, and those
    /// inputs are `None` now, so a witness that padded would prove the rule on a
    /// case the rule rejects.
    #[test]
    fn reports_the_declared_spelling_and_never_the_translation() {
        for (constraint, ecosystem) in [
            // Maven reads a release alias as contributing nothing, so this
            // translates to a bare `=1.0.0` the repository does not publish.
            ("1.0.0-RELEASE", Ecosystem::Jvm),
            // PEP 440 local segments are dropped by the translation but are part of
            // the version the index serves.
            ("==1.2.3+local", Ecosystem::Python),
            // The translation re-spells a pre-release into semver's dotted form;
            // `1.2.3-rc.1` is not what the index has.
            ("==1.2.3-rc1", Ecosystem::Python),
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
                // Parsed exactly as written — the trip every consumer of a
                // `Node::version` makes. Normalizing here would test a string
                // nothing downstream ever builds.
                assert!(
                    Version::parse(pin).is_ok(),
                    "{probe:?} ({ecosystem:?}) yielded {pin:?}"
                );
            }
        }
    }
}
