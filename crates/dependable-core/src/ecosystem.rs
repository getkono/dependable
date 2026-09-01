//! The package ecosystems dependable understands.

use serde::{Deserialize, Serialize};

/// How an ecosystem's resolver reads a version written with **no operator**.
///
/// The distinction is what makes a rewrite safe or unsafe. `dependable fix`
/// replaces a constraint's version span and keeps its operator prefix, so a
/// constraint that carried no operator is written back as a bare version — and
/// what a bare version *means* decides whether the rewrite preserved the
/// author's constraint or quietly replaced it with a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BareVersion {
    /// One release and no other: `1.9.0` matches `1.9.0` alone.
    Exact,
    /// A caret range: at least this release, below the next major —
    /// `1.9.0` is `>=1.9.0, <2.0.0`.
    Caret,
    /// An inclusive minimum with no upper bound: `1.9.0` is `>=1.9.0`.
    Minimum,
}

/// A package ecosystem.
///
/// Every variant is wired end-to-end: a parser, a registry fetcher, and an OSV
/// mapping. Which languages that adds up to is a wider question than this enum —
/// `deno.json` and `pnpm-workspace.yaml` are both [`Ecosystem::Npm`] — so the
/// **Supported languages** table in `README.md` is authoritative for status, and
/// `docs/ECOSYSTEM-CANDIDATES.md` records what a new variant has to clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Ecosystem {
    Rust,
    Go,
    Npm,
    Python,
    Php,
    Dart,
    CSharp,
    Elixir,
    Jvm,
}

impl Ecosystem {
    /// The `package.ecosystem` string used in OSV vulnerability queries.
    #[must_use]
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Rust => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Npm => "npm",
            Ecosystem::Python => "PyPI",
            Ecosystem::Php => "Packagist",
            Ecosystem::Dart => "Pub",
            Ecosystem::CSharp => "NuGet",
            Ecosystem::Elixir => "Hex",
            Ecosystem::Jvm => "Maven",
        }
    }

    /// A human-readable name for display.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Ecosystem::Rust => "Rust",
            Ecosystem::Go => "Go",
            Ecosystem::Npm => "npm",
            Ecosystem::Python => "Python",
            Ecosystem::Php => "PHP",
            Ecosystem::Dart => "Dart",
            Ecosystem::CSharp => "C#",
            Ecosystem::Elixir => "Elixir",
            Ecosystem::Jvm => "JVM",
        }
    }

    /// The default registry base URL for the ecosystem.
    #[must_use]
    pub fn default_registry(self) -> &'static str {
        match self {
            Ecosystem::Rust => "https://index.crates.io",
            Ecosystem::Go => "https://proxy.golang.org",
            Ecosystem::Npm => "https://registry.npmjs.org",
            Ecosystem::Python => "https://pypi.org/pypi",
            Ecosystem::Php => "https://repo.packagist.org",
            Ecosystem::Dart => "https://pub.dev",
            Ecosystem::CSharp => "https://api.nuget.org",
            Ecosystem::Elixir => "https://hex.pm",
            Ecosystem::Jvm => "https://repo1.maven.org/maven2",
        }
    }

    /// How this ecosystem's resolver reads a version written with no operator.
    ///
    /// A wrong answer rewrites someone's manifest into a constraint they did not
    /// write, so every variant is settled from the resolver's own documentation
    /// rather than by family resemblance — the three ecosystems that look alike
    /// here (Go, NuGet, Gradle) all read a bare version as a minimum, while three
    /// that look like Cargo (npm, Composer, pub) do not.
    ///
    /// | Ecosystem | Reading | Why |
    /// | --- | --- | --- |
    /// | Rust | [`Caret`](BareVersion::Caret) | The Cargo book: "Specifying only the version number is equivalent to a caret requirement" — `serde = "1.0"` *is* `^1.0`. |
    /// | Go | [`Minimum`](BareVersion::Minimum) | A `require` line states the lowest version the module needs; minimal version selection then builds with the highest such requirement in the graph. |
    /// | Npm | [`Exact`](BareVersion::Exact) | node-semver: a fully specified version is a comparator with an implicit `=`. A *partial* bare version is an X-range instead (`"16"` is `16.x`), which is why a caller must not treat `Exact` as "every bare string names one release". |
    /// | Python | [`Exact`](BareVersion::Exact) | PEP 508 has no bare form at all — an operator is mandatory — so the only reading that occurs is Poetry's, whose "exact requirements" are written bare and install "this version and this version only". |
    /// | Php | [`Exact`](BareVersion::Exact) | Composer's exact version constraint is the bare form: "install this version and this version only". A range needs the wildcard spelled out (`1.0.*`). |
    /// | Dart | [`Exact`](BareVersion::Exact) | pub's traditional-syntax table reads `1.2.3` as "only the given version", and the docs steer authors to `^1.2.3` precisely because the bare form is that restrictive. |
    /// | CSharp | [`Minimum`](BareVersion::Minimum) | NuGet's range table: `1.0` is `x ≥ 1.0`, "minimum version, inclusive". `[1.0]` is how an exact match is written. |
    /// | Elixir | [`Exact`](BareVersion::Exact) | A Hex requirement with no operator is an equality requirement: `Version.match?("2.0.1", "2.0.0")` is false. Floating needs `~>`. |
    /// | Jvm | [`Minimum`](BareVersion::Minimum) | A plain Gradle version string is a *required* version — the minimum, "optimistically upgraded" by conflict resolution — not a pin; `strictly` is the pinning form. Maven's plain `<version>` is likewise a soft requirement that mediation may override. |
    #[must_use]
    pub fn bare_version(self) -> BareVersion {
        match self {
            Ecosystem::Rust => BareVersion::Caret,
            Ecosystem::Go | Ecosystem::CSharp | Ecosystem::Jvm => BareVersion::Minimum,
            Ecosystem::Npm
            | Ecosystem::Python
            | Ecosystem::Php
            | Ecosystem::Dart
            | Ecosystem::Elixir => BareVersion::Exact,
        }
    }

    /// Whether a version written with no operator pins exactly one release.
    ///
    /// The question a rewriter asks most often, and the one with the sharpest
    /// consequence: where a bare version is an exact pin, replacing a floating
    /// constraint with a concrete release destroys the range the author asked
    /// for. Shorthand for [`Self::bare_version`], which carries the full reading
    /// and the reasoning behind it.
    #[must_use]
    pub fn bare_version_is_exact(self) -> bool {
        matches!(self.bare_version(), BareVersion::Exact)
    }

    /// The page a person would open to read about `name`.
    ///
    /// Distinct from [`Self::default_registry`], which is the API this tool
    /// fetches from: nobody reads `index.crates.io`. This is the page a link in
    /// a UI should point at, and it is derived rather than fetched, so it is
    /// available for a package nothing has been looked up for yet.
    ///
    /// `name` is used verbatim. Every registry here accepts the names its own
    /// ecosystem produces — npm's `@scope/name` and Go's module paths included —
    /// in the path position, and a name that is not one of those was not going
    /// to resolve to a page anyway.
    ///
    /// The default registry is assumed. A package from an alternate registry has
    /// a page elsewhere, which this cannot know about.
    #[must_use]
    pub fn package_url(self, name: &str) -> String {
        match self {
            Ecosystem::Rust => format!("https://crates.io/crates/{name}"),
            Ecosystem::Go => format!("https://pkg.go.dev/{name}"),
            Ecosystem::Npm => format!("https://www.npmjs.com/package/{name}"),
            Ecosystem::Python => format!("https://pypi.org/project/{name}/"),
            Ecosystem::Php => format!("https://packagist.org/packages/{name}"),
            Ecosystem::Dart => format!("https://pub.dev/packages/{name}"),
            Ecosystem::CSharp => format!("https://www.nuget.org/packages/{name}"),
            Ecosystem::Elixir => format!("https://hex.pm/packages/{name}"),
            // The one name that is not a path segment: a Maven coordinate is
            // `groupId:artifactId`, and Central spells the two as directories.
            Ecosystem::Jvm => format!(
                "https://central.sonatype.com/artifact/{}",
                name.replace(':', "/")
            ),
        }
    }

    /// The page for one specific published version of `name`.
    ///
    /// The version a project actually resolved is the one worth linking: the
    /// package page shows the newest release, which is a different package's
    /// worth of facts when the project is several releases behind.
    ///
    /// Falls back to [`Self::package_url`] where the registry publishes no
    /// per-version page, so a caller always has somewhere to send the reader.
    #[must_use]
    pub fn version_url(self, name: &str, version: &str) -> String {
        match self {
            Ecosystem::Rust => format!("https://crates.io/crates/{name}/{version}"),
            Ecosystem::Go => format!("https://pkg.go.dev/{name}@{version}"),
            Ecosystem::Npm => format!("https://www.npmjs.com/package/{name}/v/{version}"),
            Ecosystem::Python => format!("https://pypi.org/project/{name}/{version}/"),
            Ecosystem::Dart => format!("https://pub.dev/packages/{name}/versions/{version}"),
            Ecosystem::CSharp => format!("https://www.nuget.org/packages/{name}/{version}"),
            Ecosystem::Elixir => format!("https://hex.pm/packages/{name}/{version}"),
            Ecosystem::Jvm => format!(
                "https://central.sonatype.com/artifact/{}/{version}",
                name.replace(':', "/")
            ),
            // Packagist renders every version on the package page itself.
            Ecosystem::Php => self.package_url(name),
        }
    }

    /// Where this ecosystem builds documentation for every package it publishes.
    ///
    /// A fact about the ecosystem, not a claim about what a registry recorded:
    /// docs.rs, HexDocs, and pub.dev build and host documentation for every
    /// release, so the page exists whether or not the package declared a
    /// `documentation` URL. That is what makes it safe to offer where the
    /// registry published nothing.
    ///
    /// `None` for the ecosystems with no such convention, where a package's
    /// documentation is wherever its author chose to put it.
    #[must_use]
    pub fn docs_url(self, name: &str, version: &str) -> Option<String> {
        match self {
            Ecosystem::Rust => Some(format!("https://docs.rs/{name}/{version}")),
            Ecosystem::Elixir => Some(format!("https://hexdocs.pm/{name}/{version}")),
            Ecosystem::Dart => Some(format!("https://pub.dev/documentation/{name}/{version}/")),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, so a new ecosystem cannot be added without being given
    /// its pages.
    const ALL: [Ecosystem; 9] = [
        Ecosystem::Rust,
        Ecosystem::Go,
        Ecosystem::Npm,
        Ecosystem::Python,
        Ecosystem::Php,
        Ecosystem::Dart,
        Ecosystem::CSharp,
        Ecosystem::Elixir,
        Ecosystem::Jvm,
    ];

    #[test]
    fn every_ecosystem_can_name_a_page_for_a_package() {
        for ecosystem in ALL {
            let url = ecosystem.package_url("serde");
            assert!(url.starts_with("https://"), "{ecosystem:?}: {url}");
            assert!(url.contains("serde"), "{ecosystem:?}: {url}");

            let versioned = ecosystem.version_url("serde", "1.0.219");
            assert!(versioned.starts_with("https://"), "{ecosystem:?}");
            assert!(versioned.contains("serde"), "{ecosystem:?}");
        }
    }

    #[test]
    fn a_package_page_is_the_readable_one_not_the_api() {
        // `default_registry` is what we fetch from; nobody reads index.crates.io.
        assert_eq!(
            Ecosystem::Rust.package_url("serde"),
            "https://crates.io/crates/serde"
        );
        assert_eq!(
            Ecosystem::Npm.package_url("@types/node"),
            "https://www.npmjs.com/package/@types/node",
            "a scoped name goes in whole"
        );
        assert_eq!(
            Ecosystem::Go.package_url("github.com/spf13/cobra"),
            "https://pkg.go.dev/github.com/spf13/cobra",
            "a module path is the name"
        );
        assert_eq!(
            Ecosystem::Jvm.package_url("com.google.guava:guava"),
            "https://central.sonatype.com/artifact/com.google.guava/guava",
            "a Maven coordinate is one name spelled with a colon"
        );
        assert_eq!(
            Ecosystem::Jvm.version_url("com.google.guava:guava", "33.0.0-jre"),
            "https://central.sonatype.com/artifact/com.google.guava/guava/33.0.0-jre"
        );
    }

    #[test]
    fn a_version_without_a_page_of_its_own_falls_back_to_the_package() {
        // Packagist lists every version on the package page itself, so there is
        // nowhere more specific to send the reader.
        assert_eq!(
            Ecosystem::Php.version_url("monolog/monolog", "3.5.0"),
            Ecosystem::Php.package_url("monolog/monolog")
        );
        assert_eq!(
            Ecosystem::Rust.version_url("serde", "1.0.219"),
            "https://crates.io/crates/serde/1.0.219"
        );
    }

    #[test]
    fn only_the_ecosystems_that_build_docs_offer_a_docs_page() {
        assert_eq!(
            Ecosystem::Rust.docs_url("serde", "1.0.219").as_deref(),
            Some("https://docs.rs/serde/1.0.219")
        );
        assert_eq!(
            Ecosystem::Elixir.docs_url("phoenix", "1.7.0").as_deref(),
            Some("https://hexdocs.pm/phoenix/1.7.0")
        );
        // npm has no convention: a package's docs are wherever its author put
        // them, so claiming a page would be inventing one.
        for ecosystem in [
            Ecosystem::Go,
            Ecosystem::Npm,
            Ecosystem::Python,
            Ecosystem::Php,
            Ecosystem::CSharp,
            Ecosystem::Jvm,
        ] {
            assert_eq!(ecosystem.docs_url("a", "1.0.0"), None, "{ecosystem:?}");
        }
    }

    /// Every variant states how its resolver reads a bare version, so adding an
    /// ecosystem forces the decision rather than inheriting a default. The
    /// expected value is spelled out per variant on purpose: a loop asserting
    /// only "it returns something" would pass with every answer wrong, and a
    /// wrong answer here silently rewrites a manifest into a different
    /// constraint.
    #[test]
    fn every_ecosystem_states_how_it_reads_a_bare_version() {
        let expected = [
            // `serde = "1.0"` is `^1.0` — the Cargo book says so outright.
            (Ecosystem::Rust, BareVersion::Caret),
            // A `require` line is the lowest version the module needs; MVS takes
            // the highest such requirement across the graph.
            (Ecosystem::Go, BareVersion::Minimum),
            // node-semver: a full version is a comparator with an implicit `=`.
            (Ecosystem::Npm, BareVersion::Exact),
            // Poetry's "exact requirements" are the bare form; PEP 508 has none.
            (Ecosystem::Python, BareVersion::Exact),
            // Composer: "this version and this version only".
            (Ecosystem::Php, BareVersion::Exact),
            // pub's traditional syntax: `1.2.3` is "only the given version".
            (Ecosystem::Dart, BareVersion::Exact),
            // NuGet's range table: `1.0` is `x >= 1.0`, minimum inclusive.
            (Ecosystem::CSharp, BareVersion::Minimum),
            // A Hex requirement with no operator is an equality requirement.
            (Ecosystem::Elixir, BareVersion::Exact),
            // A plain Gradle version is `require`: a minimum, upgradable by
            // conflict resolution.
            (Ecosystem::Jvm, BareVersion::Minimum),
        ];
        assert_eq!(expected.len(), ALL.len(), "every variant must be listed");
        for (ecosystem, reading) in expected {
            assert_eq!(ecosystem.bare_version(), reading, "{ecosystem:?}");
        }
    }

    /// The shorthand and the full reading cannot drift apart: one is defined in
    /// terms of the other, and this pins that they stay that way.
    #[test]
    fn the_exactness_shorthand_agrees_with_the_full_reading() {
        for ecosystem in ALL {
            assert_eq!(
                ecosystem.bare_version_is_exact(),
                ecosystem.bare_version() == BareVersion::Exact,
                "{ecosystem:?}"
            );
        }
        // The two ecosystems the distinction was drawn for: Cargo reads a bare
        // version as a range, npm as one release.
        assert!(!Ecosystem::Rust.bare_version_is_exact());
        assert!(Ecosystem::Npm.bare_version_is_exact());
        // And the one that is neither: a bare NuGet version floats upward, but
        // without an upper bound, so it is not a pin either.
        assert!(!Ecosystem::CSharp.bare_version_is_exact());
        assert_eq!(Ecosystem::CSharp.bare_version(), BareVersion::Minimum);
    }

    #[test]
    fn rust_maps_to_crates_io_for_osv() {
        assert_eq!(Ecosystem::Rust.osv_name(), "crates.io");
        assert_eq!(
            Ecosystem::Rust.default_registry(),
            "https://index.crates.io"
        );
    }
}
