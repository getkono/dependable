//! The package ecosystems dependable understands.

use serde::{Deserialize, Serialize};

/// A package ecosystem.
///
/// Most variants are wired end-to-end: a parser, a registry fetcher, and an OSV
/// mapping. [`Ecosystem::has_registry`] names the exception — an ecosystem that
/// publishes no registry has an OSV mapping and nothing to compare a version
/// against. Which languages that adds up to is a wider question than this enum —
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
    /// Swift packages, identified by their git URL.
    ///
    /// The one ecosystem here with no registry: SwiftPM discovers versions by
    /// enumerating a repository's git tags, and while SE-0292 defines a registry
    /// API, no dominant public instance operates one. [`Ecosystem::has_registry`]
    /// is `false`, and a check reports currency as
    /// [`Undetermined`](crate::result::DependencyStatus::Undetermined) rather than
    /// guessing.
    Swift,
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
            // OSV keys its Swift advisories by repository URL, not by a package
            // name any registry issued — which is why the name we send is the URL
            // with its scheme stripped (`dependable_core::swift_package_name`).
            Ecosystem::Swift => "SwiftURL",
        }
    }

    /// Whether this ecosystem publishes a registry a version can be compared
    /// against.
    ///
    /// `false` for exactly one ecosystem, [`Swift`](Self::Swift), and it is a fact
    /// about the ecosystem rather than about this tool's configuration — which is
    /// the whole reason it is a method here and not the absence of a fetcher. A
    /// caller with no fetcher registered for an ecosystem cannot otherwise tell "the
    /// user turned this off" from "there is nothing to turn on", and the two want
    /// opposite behaviour: the first should skip the manifest, the second should
    /// carry on and scan it for vulnerabilities.
    ///
    /// A `false` here means [`default_registry`](Self::default_registry) is empty and
    /// nothing will ever be fetched, so currency is unknowable rather than merely
    /// unread.
    #[must_use]
    pub fn has_registry(self) -> bool {
        !matches!(self, Ecosystem::Swift)
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
            Ecosystem::Swift => "Swift",
        }
    }

    /// The default registry base URL for the ecosystem, or `""` for an ecosystem
    /// that has none.
    ///
    /// Empty is the honest answer for Swift and the only one: inventing a URL here
    /// would hand a fetcher somewhere to send requests that cannot be answered.
    /// [`has_registry`](Self::has_registry) is the predicate to branch on; this is
    /// the value to configure a fetcher with once it says `true`.
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
            Ecosystem::Swift => "",
        }
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
            // A Swift package name *is* its repository URL with the scheme taken
            // off, so the page is that URL put back together. There is no registry
            // page to link to instead, and inventing one would send the reader to a
            // site that has never heard of this package.
            Ecosystem::Swift => format!("https://{name}"),
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
            // A Swift version is a git tag, and the tag's spelling is not derivable
            // from the version: `2.65.0` and `v2.65.0` are both common, and a link
            // to the wrong one 404s. The repository is what we can name truthfully.
            Ecosystem::Swift => self.package_url(name),
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
    const ALL: [Ecosystem; 10] = [
        Ecosystem::Rust,
        Ecosystem::Go,
        Ecosystem::Npm,
        Ecosystem::Python,
        Ecosystem::Php,
        Ecosystem::Dart,
        Ecosystem::CSharp,
        Ecosystem::Elixir,
        Ecosystem::Jvm,
        Ecosystem::Swift,
    ];

    /// Exactly one ecosystem has no registry, and the rest must not drift into
    /// claiming they have none — a `false` here routes a manifest past the
    /// registry entirely.
    #[test]
    fn swift_is_the_only_ecosystem_without_a_registry() {
        for ecosystem in ALL {
            let expected = ecosystem != Ecosystem::Swift;
            assert_eq!(ecosystem.has_registry(), expected, "{ecosystem:?}");
            assert_eq!(
                !ecosystem.default_registry().is_empty(),
                expected,
                "{ecosystem:?}: a registry URL and `has_registry` must agree"
            );
        }
    }

    /// The OSV ecosystem strings are what a query is keyed on; a wrong one matches
    /// nothing and reports a vulnerable package as clean.
    #[test]
    fn swift_advisories_are_keyed_by_repository_url() {
        assert_eq!(Ecosystem::Swift.osv_name(), "SwiftURL");
        assert_eq!(
            Ecosystem::Swift.package_url("github.com/vapor/vapor"),
            "https://github.com/vapor/vapor"
        );
        // No per-version page: a git tag's spelling is not derivable from the
        // version, so the repository is all that can be named truthfully.
        assert_eq!(
            Ecosystem::Swift.version_url("github.com/vapor/vapor", "4.92.1"),
            Ecosystem::Swift.package_url("github.com/vapor/vapor")
        );
        assert_eq!(
            Ecosystem::Swift.docs_url("github.com/vapor/vapor", "4.92.1"),
            None
        );
    }

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

    #[test]
    fn rust_maps_to_crates_io_for_osv() {
        assert_eq!(Ecosystem::Rust.osv_name(), "crates.io");
        assert_eq!(
            Ecosystem::Rust.default_registry(),
            "https://index.crates.io"
        );
    }
}
