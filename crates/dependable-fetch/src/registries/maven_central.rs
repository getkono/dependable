//! The Maven Central fetcher for the JVM (`maven-metadata.xml`).
//!
//! Central publishes one metadata document per artifact, at the path its
//! coordinate spells out — `com.google.guava:guava` lives under
//! `com/google/guava/guava/` — and that document lists **every** published version.
//! One request per package, complete answer, which is what
//! [`RegistryFetcher`] assumes.
//!
//! There is no metadata endpoint here: a package's description and license live in
//! its POM, which is a separate document per version and inherits through a parent
//! chain, so [`RegistryFetcher::fetch_metadata`] keeps its default and
//! `publishes_metadata(Ecosystem::Jvm)` is `false`.

use ::semver::Version;
use dependable_core::semver::maven::maven_to_semver;
use futures::FutureExt;
use futures::future::BoxFuture;

use super::{FetchedVersions, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://repo1.maven.org/maven2";

/// Fetches artifact versions from a Maven repository.
#[derive(Clone)]
pub struct MavenCentralFetcher {
    client: reqwest::Client,
    base_url: String,
}

impl MavenCentralFetcher {
    /// A fetcher against Maven Central.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate Maven repository (Artifactory, Nexus, a
    /// mirror), which serves the same `maven-metadata.xml` layout.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

impl RegistryFetcher for MavenCentralFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let Some(path) = metadata_path(name) else {
                // Without both halves there is no directory to ask for. Reported as
                // "not found" rather than as a transport failure, because nothing
                // was ever going to be there.
                return Err(FetchError::NotFound(name.to_string()));
            };
            let url = format!("{}/{path}/maven-metadata.xml", self.base_url);
            let resp = self.client.get(&url).send().await?;
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(FetchError::NotFound(name.to_string()));
            }
            if !status.is_success() {
                return Err(FetchError::Status {
                    code: status.as_u16(),
                    package: name.to_string(),
                });
            }
            let body = resp.text().await?;
            parse_metadata(&body, name)
        }
        .boxed()
    }
}

/// The repository path for a coordinate: `com.google.guava:guava` →
/// `com/google/guava/guava`.
///
/// `None` when the name is not a `groupId:artifactId` pair, or when either half
/// carries a path separator — a coordinate cannot, and one that does would be
/// asking for a different directory than it names.
fn metadata_path(name: &str) -> Option<String> {
    let (group, artifact) = name.split_once(':')?;
    if group.is_empty() || artifact.is_empty() || artifact.contains(':') {
        return None;
    }
    if name.contains(['/', '\\']) || group.split('.').any(str::is_empty) {
        return None;
    }
    Some(format!("{}/{artifact}", group.replace('.', "/")))
}

/// Read `<versioning><versions><version>` out of a `maven-metadata.xml`, newest
/// first.
///
/// `<release>` is preferred as the latest tag where the document names one: it is
/// the newest version the repository considers released, which `<versions>` alone
/// cannot distinguish from a snapshot sitting above it.
fn parse_metadata(body: &str, package: &str) -> Result<FetchedVersions, FetchError> {
    let doc = roxmltree::Document::parse(body).map_err(|e| FetchError::Decode {
        package: package.to_string(),
        detail: e.to_string(),
    })?;
    let versioning = doc
        .descendants()
        .find(|n| n.has_tag_name("versioning"))
        .ok_or_else(|| FetchError::Decode {
            package: package.to_string(),
            detail: "no <versioning> element".to_string(),
        })?;

    let mut versions: Vec<String> = versioning
        .descendants()
        .filter(|n| n.has_tag_name("version"))
        .filter_map(|n| n.text())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect();
    if versions.is_empty() {
        return Err(FetchError::NotFound(package.to_string()));
    }
    sort_desc(&mut versions);

    let fetched = FetchedVersions::new(versions);
    let release = versioning
        .children()
        .find(|n| n.has_tag_name("release"))
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    Ok(match release {
        Some(tag) => fetched.with_latest_tag(tag),
        None => fetched,
    })
}

/// Sort raw Maven versions newest-first by their semver interpretation.
///
/// The comparison is **total**: versions that compare equal are ordered by their
/// own strings, so a list built in a nondeterministic order (a `HashMap`'s
/// iteration, pages appended as their fetches complete) cannot come out of here in
/// a nondeterministic one.
fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| {
        let va = maven_to_semver(a).and_then(|s| Version::parse(&s).ok());
        let vb = maven_to_semver(b).and_then(|s| Version::parse(&s).ok());
        match (va, vb) {
            (Some(va), Some(vb)) => vb.cmp(&va).then_with(|| b.cmp(a)),
            _ => b.cmp(a),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_becomes_a_directory_chain() {
        assert_eq!(
            metadata_path("com.google.guava:guava").as_deref(),
            Some("com/google/guava/guava")
        );
        assert_eq!(
            metadata_path("org.jetbrains.kotlin:kotlin-stdlib").as_deref(),
            Some("org/jetbrains/kotlin/kotlin-stdlib")
        );
    }

    /// A name that is not a coordinate names no directory, and one carrying a
    /// separator would name a directory other than the one it spells.
    #[test]
    fn a_name_that_is_not_a_coordinate_has_no_path() {
        for name in [
            "guava",
            ":guava",
            "com.google.guava:",
            "a:b:c",
            "../etc:passwd",
            "com..google:guava",
        ] {
            assert_eq!(metadata_path(name), None, "{name}");
        }
    }

    #[test]
    fn versions_come_back_newest_first_by_maven_order() {
        let body = r#"<metadata>
  <groupId>org.example</groupId>
  <artifactId>demo</artifactId>
  <versioning>
    <latest>2.0.0-SNAPSHOT</latest>
    <release>1.10.0</release>
    <versions>
      <version>1.2.0</version>
      <version>1.9.0</version>
      <version>1.10.0</version>
      <version>2.0.0-SNAPSHOT</version>
    </versions>
  </versioning>
</metadata>"#;
        let fetched = parse_metadata(body, "org.example:demo").expect("parses");
        assert_eq!(
            fetched.versions,
            vec!["2.0.0-SNAPSHOT", "1.10.0", "1.9.0", "1.2.0"],
            "1.10.0 is newer than 1.9.0, which a string sort would reverse"
        );
        assert_eq!(
            fetched.latest_tag.as_deref(),
            Some("1.10.0"),
            "`<release>` names the newest release, not the newest snapshot"
        );
    }

    #[test]
    fn a_document_with_no_versions_is_the_same_as_no_package() {
        let body = "<metadata><versioning><versions/></versioning></metadata>";
        assert!(matches!(
            parse_metadata(body, "org.example:demo"),
            Err(FetchError::NotFound(_))
        ));
    }

    #[test]
    fn malformed_xml_is_a_decode_error() {
        assert!(matches!(
            parse_metadata("<metadata>", "org.example:demo"),
            Err(FetchError::Decode { .. })
        ));
        assert!(matches!(
            parse_metadata("<metadata/>", "org.example:demo"),
            Err(FetchError::Decode { .. })
        ));
    }
}
