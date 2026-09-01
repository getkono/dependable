//! Reader for a manifest's **project identity** — the name and version the manifest
//! declares for itself, as opposed to the dependencies it declares on others.
//!
//! Dependency checking never needs this: a check is keyed on the manifest path. Taking
//! inventory of a repository does, because "which projects live here" is unanswerable
//! from paths alone, and because a manifest that declares *only* central dependency
//! versions (a virtual Cargo workspace root, `pnpm-workspace.yaml`,
//! `Directory.Packages.props`) is not a project at all.
//!
//! Like the rest of `dependable-core` this is IO-free, which bounds what it can answer.
//! A Cargo member writing `version.workspace = true` is reported as
//! [`PackageField::Workspace`] for the caller to resolve against the workspace root, and
//! a `*.csproj` — whose project name is its file name — reports no name, since the file
//! name is not part of the content.

use toml_edit::{ImDocument, Item as TomlItem, TableLike};

use super::cargo_package::{PackageField, parse_package_manifest};
use super::cargo_workspace::parse_workspace;
use super::json_scan::scan_strings;
use crate::manifest::ManifestKind;

/// What a manifest is, as far as an inventory is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ProjectRole {
    /// A named package: it declares an identity and (normally) its own dependencies.
    #[default]
    Package,
    /// A workspace or central-version manifest that declares no package of its own —
    /// a virtual Cargo root, `pnpm-workspace.yaml`, `Directory.Packages.props`. Its
    /// dependency entries are declarations members opt into, not its own dependencies.
    Workspace,
    /// A dependency list with no declared identity: `requirements.txt`, a `*.csproj`
    /// (named by its file), a `package.json` without a `name`.
    Unnamed,
}

/// A manifest's declared identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ProjectMeta {
    /// The declared package name, or `None` when the manifest declares none.
    pub name: Option<String>,
    /// The declared version, possibly inherited from a workspace root (Cargo only).
    pub version: Option<PackageField>,
    /// What kind of manifest this is.
    pub role: ProjectRole,
}

impl ProjectMeta {
    /// The literal version, or `None` when absent or inherited. Callers with
    /// filesystem access resolve an inherited version with
    /// [`PackageField::resolve`].
    #[must_use]
    pub fn literal_version(&self) -> Option<&str> {
        self.version.as_ref().and_then(PackageField::literal)
    }
}

/// Read the identity a manifest declares for itself.
///
/// Never fails: a manifest that declares no identity — or one that does not parse —
/// yields a [`ProjectMeta`] with no name, which is what an inventory should report
/// rather than an error that hides the rest of the repository.
#[must_use]
pub fn parse_project(kind: ManifestKind, content: &str) -> ProjectMeta {
    match kind {
        ManifestKind::CargoToml => cargo(content),
        ManifestKind::PackageJson | ManifestKind::DenoJson | ManifestKind::ComposerJson => {
            json_identity(content)
        }
        ManifestKind::PyprojectToml => pyproject(content),
        ManifestKind::GoMod => go_module(content),
        ManifestKind::PubspecYaml => pubspec(content),
        ManifestKind::MixExs => mix(content),
        ManifestKind::PomXml => pom(content),
        // A `pnpm-workspace.yaml` exists to hold catalogs; `Directory.Packages.props`
        // exists to hold central versions. A Gradle version catalog is the same shape
        // again — the project it serves is described by a build script. None names a
        // project.
        ManifestKind::PnpmWorkspaceYaml | ManifestKind::GradleVersionCatalog => workspace_meta(),
        // A `*.csproj` is named by its file and `requirements.txt` names nothing; both
        // are identified by path, which this reader cannot see.
        ManifestKind::Csproj | ManifestKind::RequirementsTxt => unnamed(),
    }
}

/// `Cargo.toml`: `[package]`, else a `[workspace]` table with no package (virtual root).
fn cargo(content: &str) -> ProjectMeta {
    let Ok(manifest) = parse_package_manifest(content) else {
        return unnamed();
    };
    if manifest.name.is_none() && parse_workspace(content).is_some() {
        return workspace_meta();
    }
    ProjectMeta {
        role: role_for(manifest.name.as_deref()),
        name: manifest.name,
        version: manifest.version,
    }
}

/// `package.json` / `deno.json` / `composer.json`: top-level `name` and `version`.
fn json_identity(content: &str) -> ProjectMeta {
    let values = scan_strings(content);
    let top = |key: &str| {
        values
            .iter()
            .find(|v| v.path.len() == 1 && v.path[0] == key)
            .map(|v| v.value.clone())
    };
    let name = top("name");
    ProjectMeta {
        role: role_for(name.as_deref()),
        name,
        version: top("version").map(PackageField::Literal),
    }
}

/// `pyproject.toml`: PEP 621 `[project]`, else `[tool.poetry]`.
fn pyproject(content: &str) -> ProjectMeta {
    let Ok(doc) = ImDocument::parse(content.to_owned()) else {
        return unnamed();
    };
    let root = doc.as_table();
    let table = |path: &[&str]| -> Option<&dyn TableLike> {
        let mut item = root.get(path[0])?;
        for key in &path[1..] {
            item = item.as_table_like()?.get(key)?;
        }
        item.as_table_like()
    };
    let section = table(&["project"]).or_else(|| table(&["tool", "poetry"]));
    let field = |key: &str| {
        section
            .and_then(|t| t.get(key))
            .and_then(TomlItem::as_str)
            .map(str::to_owned)
    };
    let name = field("name");
    ProjectMeta {
        role: role_for(name.as_deref()),
        name,
        version: field("version").map(PackageField::Literal),
    }
}

/// `go.mod`: the `module` directive. A module path is its identity; there is no version.
fn go_module(content: &str) -> ProjectMeta {
    let name = content.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("module")?;
        let path = rest
            .split("//")
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        (!path.is_empty()).then(|| path.to_owned())
    });
    ProjectMeta {
        role: role_for(name.as_deref()),
        name,
        version: None,
    }
}

/// `pubspec.yaml`: the top-level `name:` and `version:` scalars.
fn pubspec(content: &str) -> ProjectMeta {
    let scalar = |key: &str| {
        content.lines().find_map(|line| {
            // Only an indent-0 key is the package's own; anything indented belongs to a
            // nested map (a dependency's `version:`, for instance).
            if line.starts_with(char::is_whitespace) {
                return None;
            }
            let value = line.strip_prefix(key)?.strip_prefix(':')?;
            let value = value
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            (!value.is_empty()).then(|| value.to_owned())
        })
    };
    let name = scalar("name");
    ProjectMeta {
        role: role_for(name.as_deref()),
        name,
        version: scalar("version").map(PackageField::Literal),
    }
}

/// `mix.exs`: `app: :name` and `version: "…"` from the `project` function.
///
/// Best-effort, matching [`mix_exs`](super::mix_exs): the file is Elixir source, so the
/// keywords are read positionally rather than parsed.
fn mix(content: &str) -> ProjectMeta {
    let after = |needle: &str| content.split_once(needle).map(|(_, rest)| rest);
    let name = after("app: :").map(|rest| {
        rest.chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>()
    });
    let name = name.filter(|n| !n.is_empty());
    let version = after("version: \"").and_then(|rest| {
        rest.split_once('"')
            .map(|(value, _)| value.to_owned())
            .filter(|v| !v.is_empty())
    });
    ProjectMeta {
        role: role_for(name.as_deref()),
        name,
        version: version.map(PackageField::Literal),
    }
}

/// `pom.xml`: the `<artifactId>`, `<groupId>`, and `<version>` directly under
/// `<project>`.
///
/// The coordinate is the identity, and it is spelled `groupId:artifactId` — the same
/// way the POM parser names the dependencies it reads, so a project and a dependency
/// on it are the same string. A POM that states no `<groupId>` of its own inherits it
/// from its `<parent>`, which is out of reach here (see
/// [`pom_xml`](super::pom_xml)); the bare `artifactId` is reported rather than a
/// coordinate that would be half guessed. A `<version>` that is a property
/// (`${revision}`) is likewise not a literal this file states.
fn pom(content: &str) -> ProjectMeta {
    let Ok(doc) = roxmltree::Document::parse(content) else {
        return unnamed();
    };
    let project = doc.root_element();
    let field = |tag: &str| {
        project
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == tag)
            .and_then(|child| child.text())
            .map(str::trim)
            .filter(|text| !text.is_empty() && !text.contains('$'))
            .map(str::to_owned)
    };
    let name = field("artifactId").map(|artifact| match field("groupId") {
        Some(group) => format!("{group}:{artifact}"),
        None => artifact,
    });
    ProjectMeta {
        role: role_for(name.as_deref()),
        name,
        version: field("version").map(PackageField::Literal),
    }
}

/// A manifest that declares dependency versions for others but no package of its own.
fn workspace_meta() -> ProjectMeta {
    ProjectMeta {
        name: None,
        version: None,
        role: ProjectRole::Workspace,
    }
}

/// A dependency list with no declared identity.
fn unnamed() -> ProjectMeta {
    ProjectMeta {
        name: None,
        version: None,
        role: ProjectRole::Unnamed,
    }
}

/// [`ProjectRole::Package`] when a name was found, [`ProjectRole::Unnamed`] otherwise.
fn role_for(name: Option<&str>) -> ProjectRole {
    if name.is_some() {
        ProjectRole::Package
    } else {
        ProjectRole::Unnamed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(kind: ManifestKind, content: &str) -> ProjectMeta {
        parse_project(kind, content)
    }

    #[test]
    fn cargo_package_reports_name_and_version() {
        let m = meta(
            ManifestKind::CargoToml,
            "[package]\nname = \"my-crate\"\nversion = \"1.2.3\"\n",
        );
        assert_eq!(m.name.as_deref(), Some("my-crate"));
        assert_eq!(m.literal_version(), Some("1.2.3"));
        assert_eq!(m.role, ProjectRole::Package);
    }

    /// An inherited version cannot be resolved without the workspace root, so it is
    /// reported as inherited rather than guessed at or dropped.
    #[test]
    fn cargo_inherited_version_is_reported_as_inherited() {
        let m = meta(
            ManifestKind::CargoToml,
            "[package]\nname = \"member\"\nversion.workspace = true\n",
        );
        assert_eq!(m.version, Some(PackageField::Workspace));
        assert_eq!(m.literal_version(), None);
    }

    /// A virtual root holds `[workspace.dependencies]` but is not itself a project.
    #[test]
    fn virtual_cargo_workspace_root_is_a_workspace() {
        let m = meta(
            ManifestKind::CargoToml,
            "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nserde = \"1\"\n",
        );
        assert_eq!(m.role, ProjectRole::Workspace);
        assert_eq!(m.name, None);
    }

    /// A root that is both a workspace and a package keeps its package identity.
    #[test]
    fn cargo_root_package_with_workspace_is_a_package() {
        let m = meta(
            ManifestKind::CargoToml,
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\n[workspace]\nmembers = []\n",
        );
        assert_eq!(m.role, ProjectRole::Package);
        assert_eq!(m.name.as_deref(), Some("root"));
    }

    #[test]
    fn json_manifests_report_top_level_identity() {
        let m = meta(
            ManifestKind::PackageJson,
            r#"{"name": "@scope/app", "version": "2.0.0", "dependencies": {"react": "^18"}}"#,
        );
        assert_eq!(m.name.as_deref(), Some("@scope/app"));
        assert_eq!(m.literal_version(), Some("2.0.0"));

        // A dependency's own name/version keys are nested, never top level.
        let nested = meta(
            ManifestKind::PackageJson,
            r#"{"dependencies": {"react": "^18"}, "engines": {"name": "nope"}}"#,
        );
        assert_eq!(nested.name, None);
        assert_eq!(nested.role, ProjectRole::Unnamed);
    }

    #[test]
    fn composer_and_deno_identity() {
        let composer = meta(
            ManifestKind::ComposerJson,
            r#"{"name": "vendor/pkg", "require": {"monolog/monolog": "^3.0"}}"#,
        );
        assert_eq!(composer.name.as_deref(), Some("vendor/pkg"));
        assert_eq!(composer.literal_version(), None);

        let deno = meta(
            ManifestKind::DenoJson,
            r#"{"name": "@scope/mod", "version": "0.3.0", "imports": {"x": "jsr:@std/fs@^1"}}"#,
        );
        assert_eq!(deno.name.as_deref(), Some("@scope/mod"));
        assert_eq!(deno.literal_version(), Some("0.3.0"));
    }

    #[test]
    fn pyproject_prefers_pep621_then_poetry() {
        let pep621 = meta(
            ManifestKind::PyprojectToml,
            "[project]\nname = \"app\"\nversion = \"1.0.0\"\n",
        );
        assert_eq!(pep621.name.as_deref(), Some("app"));
        assert_eq!(pep621.literal_version(), Some("1.0.0"));

        let poetry = meta(
            ManifestKind::PyprojectToml,
            "[tool.poetry]\nname = \"legacy\"\nversion = \"0.9.0\"\n",
        );
        assert_eq!(poetry.name.as_deref(), Some("legacy"));
        assert_eq!(poetry.literal_version(), Some("0.9.0"));
    }

    #[test]
    fn go_module_path_is_the_name() {
        let m = meta(
            ManifestKind::GoMod,
            "module example.com/m/v2 // comment\n\ngo 1.21\n",
        );
        assert_eq!(m.name.as_deref(), Some("example.com/m/v2"));
        assert_eq!(m.version, None);
    }

    #[test]
    fn pubspec_reads_only_top_level_scalars() {
        let m = meta(
            ManifestKind::PubspecYaml,
            "name: my_app\nversion: 1.0.0+3\n\ndependencies:\n  http: ^1.1.0\n",
        );
        assert_eq!(m.name.as_deref(), Some("my_app"));
        assert_eq!(m.literal_version(), Some("1.0.0+3"));
    }

    #[test]
    fn mix_reads_app_and_version() {
        let content = "defmodule Sample.MixProject do\n  use Mix.Project\n  def project do\n    [app: :sample_app, version: \"0.4.2\"]\n  end\nend\n";
        let m = meta(ManifestKind::MixExs, content);
        assert_eq!(m.name.as_deref(), Some("sample_app"));
        assert_eq!(m.literal_version(), Some("0.4.2"));
    }

    #[test]
    fn central_version_manifests_are_workspaces() {
        let m = meta(
            ManifestKind::PnpmWorkspaceYaml,
            "catalog:\n  react: ^18.0.0\n",
        );
        assert_eq!(m.role, ProjectRole::Workspace);
        assert_eq!(
            meta(
                ManifestKind::GradleVersionCatalog,
                "[versions]\nkotlin = \"1.9.24\"\n",
            )
            .role,
            ProjectRole::Workspace
        );
    }

    /// A POM names itself by coordinate — the same string a dependency on it would
    /// use. Anything it leaves to its `<parent>` is left unstated rather than guessed.
    #[test]
    fn a_pom_is_named_by_its_coordinate() {
        let meta = parse_project(
            ManifestKind::PomXml,
            "<project>\n  <groupId>org.example</groupId>\n  \
             <artifactId>demo</artifactId>\n  <version>1.4.0</version>\n</project>\n",
        );
        assert_eq!(meta.name.as_deref(), Some("org.example:demo"));
        assert_eq!(meta.literal_version(), Some("1.4.0"));
        assert_eq!(meta.role, ProjectRole::Package);

        // Group and version both inherited from a parent, and a `<parent>` of its own
        // whose fields must not be mistaken for the project's.
        let inheriting = parse_project(
            ManifestKind::PomXml,
            "<project>\n  <parent>\n    <groupId>org.parent</groupId>\n    \
             <artifactId>parent</artifactId>\n    <version>9.9.9</version>\n  \
             </parent>\n  <artifactId>child</artifactId>\n</project>\n",
        );
        assert_eq!(inheriting.name.as_deref(), Some("child"));
        assert_eq!(inheriting.literal_version(), None);

        // `${revision}` is CI-friendly versioning, not a version.
        let templated = parse_project(
            ManifestKind::PomXml,
            "<project>\n  <artifactId>demo</artifactId>\n  \
             <version>${revision}</version>\n</project>\n",
        );
        assert_eq!(templated.literal_version(), None);

        assert_eq!(
            parse_project(ManifestKind::PomXml, "<not xml").role,
            ProjectRole::Unnamed
        );
    }

    #[test]
    fn manifests_named_by_their_file_are_unnamed() {
        assert_eq!(
            meta(ManifestKind::RequirementsTxt, "flask>=2.0\n").role,
            ProjectRole::Unnamed
        );
        assert_eq!(
            meta(ManifestKind::Csproj, "<Project></Project>\n").role,
            ProjectRole::Unnamed
        );
    }

    /// Unparseable content yields an anonymous project, never an error that would hide
    /// the rest of the repository.
    #[test]
    fn malformed_content_is_unnamed() {
        assert_eq!(
            meta(ManifestKind::CargoToml, "[package\nname = ").role,
            ProjectRole::Unnamed
        );
        assert_eq!(
            meta(ManifestKind::PyprojectToml, "[[[").role,
            ProjectRole::Unnamed
        );
    }
}
