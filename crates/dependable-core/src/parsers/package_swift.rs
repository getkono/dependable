//! Reader for `Package.swift` — which reads nothing, on purpose.
//!
//! `Package.swift` is not a manifest format. It is a Swift program whose output
//! happens to be a package description: dependencies are routinely assembled in
//! loops, appended behind `#if` conditionals, and built from variables and
//! functions defined elsewhere in the file. Extracting them with a regex does not
//! produce an *incomplete* list, it produces a *wrong* one — the entries it
//! happens to match, presented as the whole set — and `mix.exs`'s literal
//! `deps` list, which this crate does read, is not the same shape of file.
//!
//! So the parser declines. The dependency list comes from `Package.resolved`
//! instead ([`crate::lockfiles::swift_package_resolved_items`]), which is plain
//! JSON and records the full flattened pin set. That is the reason
//! [`crate::manifest::LockfileKind::is_dependency_source`] exists: a lockfile
//! that is the only honest record of what a project depends on has to be able to
//! *supply* items, not merely annotate them.

use crate::error::ParseError;
use crate::manifest::ManifestKind;
use crate::manifest::ParsedManifest;
use crate::parsers::Parser;

/// Reads a `Package.swift` and returns no dependencies, deliberately.
pub struct PackageSwiftParser;

impl Parser for PackageSwiftParser {
    /// Always succeeds with an empty item list.
    ///
    /// Not an error: the file is a legitimate, correctly-formed Swift manifest, and
    /// failing here would be reported as "this file is broken" rather than "this
    /// file is a program". The dependencies arrive from `Package.resolved`, and the
    /// check that runs afterwards says what could not be established about them.
    fn parse(&self, _content: &str) -> Result<ParsedManifest, ParseError> {
        Ok(ParsedManifest {
            kind: ManifestKind::PackageSwift,
            items: Vec::new(),
            alternate_registries: Vec::new(),
            notices: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The motivating case: a loop and a conditional. Any text-level reader
    /// produces a confidently wrong answer here, which is worse than none.
    const MANIFEST: &str = r#"// swift-tools-version:5.9
import PackageDescription

var deps: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
]
for extra in extraPackages {
    deps.append(.package(url: extra.url, from: extra.version))
}
#if canImport(Darwin)
deps.append(.package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"))
#endif

let package = Package(name: "demo", dependencies: deps)
"#;

    #[test]
    fn reads_no_dependencies_from_an_executable_manifest() {
        let parsed = PackageSwiftParser.parse(MANIFEST).expect("never fails");
        assert!(
            parsed.items.is_empty(),
            "Package.swift must not be read as text"
        );
        assert_eq!(parsed.kind, ManifestKind::PackageSwift);
        // No notice here: the manifest-level statement a Swift run owes its reader
        // is about currency, and it is emitted per check rather than per parse, so
        // it reaches a caller that never had a `Package.swift` in hand.
        assert!(parsed.notices.is_empty());
    }

    #[test]
    fn even_nonsense_parses_rather_than_failing() {
        assert!(PackageSwiftParser.parse("").is_ok());
        assert!(PackageSwiftParser.parse("{{{ not swift").is_ok());
    }
}
