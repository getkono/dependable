//! Hermetic tests for the ecosystem-aware project graph builder (no network).
//!
//! These cover the non-Cargo ecosystems: npm, Composer, and Mix get a full resolved
//! transitive graph, while ecosystems whose lockfile cannot express edges fall back
//! to the project's direct dependencies and say so.

use std::fs;
use std::path::{Path, PathBuf};

use dependable_fetch::{
    DependencyGraph, GraphSource, NodeKind, TreeOptions, WorkspaceGraphOptions, build_project_graph,
};
use tempfile::TempDir;

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, content).expect("write");
}

/// Depth-first flatten of the rendered tree into `name` order, following edges.
fn flatten(graph: &DependencyGraph) -> Vec<String> {
    fn walk(graph: &DependencyGraph, node: &dependable_fetch::TreeNode, out: &mut Vec<String>) {
        out.push(graph.nodes()[node.node].name.clone());
        for child in &node.children {
            walk(graph, child, out);
        }
    }
    let tree = graph.tree(&TreeOptions::default());
    let mut out = Vec::new();
    for root in &tree.roots {
        walk(graph, root, &mut out);
    }
    out
}

/// The committed fixtures, shared with the CLI's integration tests.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dependable/tests/fixtures")
        .join(name)
}

#[test]
fn npm_graph_is_transitive() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0", "dependencies": { "a": "^1.0.0" } }"#,
    );
    write(
        &dir.path().join("package-lock.json"),
        r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "a": "^1.0.0" } },
    "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "^2.0.0" } },
    "node_modules/b": { "version": "2.0.0" }
  }
}"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(built.source, GraphSource::Lockfile);
    assert_eq!(
        flatten(&built.graph),
        vec!["app", "a", "b"],
        "the graph must reach the transitive dependency"
    );
}

#[test]
fn a_lockfile_root_without_edges_falls_back_to_the_manifest() {
    // npm names the project in its `""` entry but does not always record what it
    // depends on there; the manifest still does, and a root with no edges would
    // render as a project with no dependencies at all.
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0",
             "dependencies": { "react": "^18.0.0" },
             "devDependencies": { "typescript": "^5.0.0" } }"#,
    );
    write(
        &dir.path().join("package-lock.json"),
        r#"{ "lockfileVersion": 3, "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/react": { "version": "18.2.0" },
    "node_modules/typescript": { "version": "5.4.2" } } }"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    let mut names = flatten(&built.graph);
    names.sort();
    assert_eq!(names, vec!["app", "react", "typescript"]);
}

#[test]
fn npm_root_is_local_and_installed_packages_are_external() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0", "dependencies": { "a": "^1.0.0" } }"#,
    );
    write(
        &dir.path().join("package-lock.json"),
        r#"{ "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "a": "^1.0.0" } },
    "node_modules/a": { "version": "1.0.0" } } }"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    let kind = |name: &str| {
        built
            .graph
            .nodes()
            .iter()
            .find(|n| n.name == name)
            .map(|n| n.kind)
    };
    assert_eq!(kind("app"), Some(NodeKind::Workspace));
    assert_eq!(kind("a"), Some(NodeKind::Registry));
}

#[test]
fn composer_graph_synthesizes_the_root_and_follows_requires() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("composer.json"),
        r#"{ "name": "vendor/app", "require": { "php": ">=8.1", "monolog/monolog": "^2.0" } }"#,
    );
    write(
        &dir.path().join("composer.lock"),
        r#"{
  "packages": [
    { "name": "monolog/monolog", "version": "2.1.0",
      "require": { "php": ">=7.2", "psr/log": "^1.0" } },
    { "name": "psr/log", "version": "1.1.4" }
  ]
}"#,
    );

    let built = build_project_graph(
        &dir.path().join("composer.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(built.source, GraphSource::Lockfile);
    assert_eq!(
        flatten(&built.graph),
        vec!["vendor/app", "monolog/monolog", "psr/log"],
        "composer.lock has no root entry, so it must be synthesized"
    );
    assert!(
        !built.graph.nodes().iter().any(|n| n.name == "php"),
        "a platform requirement is not a package"
    );
}

#[test]
fn mix_graph_follows_the_dependency_element() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("mix.exs"),
        "defmodule App.MixProject do\n  use Mix.Project\n  def project do\n    [app: :app, version: \"0.1.0\", deps: deps()]\n  end\n  defp deps do\n    [{:ecto, \"~> 3.10\"}]\n  end\nend\n",
    );
    write(
        &dir.path().join("mix.lock"),
        concat!(
            "%{\n",
            r#"  "ecto": {:hex, :ecto, "3.10.3", "a", [:mix], [{:decimal, "~> 2.0", [hex: :decimal, repo: "hexpm", optional: false]}], "hexpm", "b"},"#,
            "\n",
            r#"  "decimal": {:hex, :decimal, "2.1.1", "c", [:mix], [], "hexpm", "d"},"#,
            "\n}\n",
        ),
    );

    let built = build_project_graph(
        &dir.path().join("mix.exs"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(built.source, GraphSource::Lockfile);
    assert_eq!(flatten(&built.graph), vec!["app", "ecto", "decimal"]);
}

#[test]
fn an_ecosystem_without_edge_data_reports_unsupported() {
    // `pubspec.lock` records resolved versions but never which package required
    // which, so the builder must say so rather than imply a flat dependency set.
    let built = build_project_graph(
        &fixture("sample-dart").join("pubspec.yaml"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(built.source, GraphSource::Unsupported);
    let names = flatten(&built.graph);
    assert!(names.len() > 1, "the direct dependencies are still shown");
}

/// Every version in the graph, by node name, so a change to any one of them has
/// to be stated rather than absorbed.
fn versions(graph: &DependencyGraph) -> Vec<(&str, Option<&str>)> {
    graph
        .nodes()
        .iter()
        .map(|n| (n.name.as_str(), n.version.as_deref()))
        .collect()
}

/// The version of one node, panicking if there is no such node — so an assertion
/// about a node cannot silently pass because the node is missing.
fn version_of<'g>(graph: &'g DependencyGraph, name: &str) -> Option<&'g str> {
    graph
        .nodes()
        .iter()
        .find(|n| n.name == name)
        .unwrap_or_else(|| panic!("a node for {name}"))
        .version
        .as_deref()
}

/// A manifest names its dependencies and usually only constrains them — but a
/// Gradle catalog states a version outright, and a constraint that admits exactly
/// one release has already resolved it. Reporting `unknown` for these understated
/// what the file plainly said.
///
/// Asserted per node, with the exact spelling of each, because the two facts worth
/// protecting are both about *which* string comes back:
///
/// - `guava` must be `32.1.3-jre` and never the translated `32.1.3`. Maven Central
///   publishes `32.1.3-jre` and `32.1.3-android` and nothing called `32.1.3`, so
///   the translation names no artifact at all.
/// - `kotlin-stdlib` and `kotlin-reflect` share one `[versions]` alias, which
///   reaches them as a *resolved* `Inherited` item. Those are checkable and so
///   report the alias's version; an alias no `[versions]` entry defines would not.
#[test]
fn a_manifest_only_graph_reports_the_versions_the_manifest_settled() {
    let built = build_project_graph(
        &fixture("sample-kotlin").join("gradle/libs.versions.toml"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(
        versions(&built.graph),
        vec![
            // The catalog declares no project of its own; the root is its directory.
            ("gradle", None),
            ("org.jetbrains.kotlin:kotlin-stdlib", Some("1.9.24")),
            ("org.jetbrains.kotlin:kotlin-reflect", Some("1.9.24")),
            ("com.squareup.okhttp3:okhttp", Some("4.12.0")),
            ("org.junit.jupiter:junit-jupiter", Some("5.10.2")),
            // The declared spelling, not `maven_to_semver`'s `32.1.3`.
            ("com.google.guava:guava", Some("32.1.3-jre")),
            ("org.apache.commons:commons-lang3", Some("3.14.0")),
        ],
    );
    assert!(
        built
            .graph
            .nodes()
            .iter()
            .all(|n| n.version.as_deref() != Some("")),
        "an unknown version is `None`, never an empty string"
    );
    // A catalog entry stating no version at all — a BOM supplies it at build time
    // — is not a dependency this file resolved, and is not in the graph.
    assert!(
        !built
            .graph
            .nodes()
            .iter()
            .any(|n| n.name.contains("jackson-databind")),
    );
}

/// The case #107 opened with, and the one this change does **not** close. NuGet
/// reads a bare `Version` as an inclusive *minimum* (`>=13.0.1`), not a pin — see
/// `nuget_constraint_to_semver`, "A bare version is an inclusive minimum in NuGet"
/// — so `Newtonsoft.Json` still reports no version.
///
/// Admitting it here would make `tree` claim a resolution for a line `check`
/// reports as satisfied by every later release, which is a disagreement about one
/// line of one file. The reading itself is the defect, and it is filed as #113;
/// this test is the record of what today's translation says, and is expected to
/// change with it.
#[test]
fn a_bare_nuget_version_is_a_minimum_and_so_resolves_nothing() {
    let built = build_project_graph(
        &fixture("sample-csharp").join("App.csproj"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(version_of(&built.graph, "Newtonsoft.Json"), None);
    // An interval spanning two majors names a set by anyone's reading.
    assert_eq!(version_of(&built.graph, "Serilog"), None);
    // A reference whose version is an unexpanded MSBuild property, and one with no
    // `Version` at all, state nothing to resolve — the parser drops both, so they
    // are absent from the graph rather than present with a version of `None`.
    for absent in ["FromProperty", "Microsoft.Extensions.Hosting"] {
        assert!(
            !built.graph.nodes().iter().any(|n| n.name == absent),
            "{absent} states no version and is not a dependency this file resolved"
        );
    }
}

/// npm reads a bare `1.3.0` as a caret range, exactly as Cargo does, so neither of
/// these is a pin. The rule is about what the *constraint* admits, not about how
/// concrete it looks: `"left-pad": "1.3.0"` accepts every 1.x release npm ever
/// publishes.
#[test]
fn a_concrete_looking_npm_constraint_is_still_a_range() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0",
             "dependencies": { "react": "^18.0.0", "left-pad": "1.3.0", "pinned": "=4.17.21" } }"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(built.source, GraphSource::Manifests);
    assert_eq!(version_of(&built.graph, "react"), None);
    assert_eq!(version_of(&built.graph, "left-pad"), None);
    // npm's explicit `=` is the one form that does name a single release.
    assert_eq!(version_of(&built.graph, "pinned"), Some("4.17.21"));
}

/// Candidacy is `Item::is_checkable()`, the existing predicate for "there is a
/// version string here worth asking a registry about". A git or link spec fails it
/// however much of a version the spec has written into it, so no second rule is
/// needed to keep those unknown — and no such rule can drift from the first.
#[test]
fn a_git_or_local_dependency_stays_unknown_however_it_is_spelled() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0",
             "dependencies": {
               "fromgit": "git+https://example.com/x.git#1.2.3",
               "linked": "link:../linked" } }"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(version_of(&built.graph, "fromgit"), None);
    assert_eq!(version_of(&built.graph, "linked"), None);
}

/// Two declarations of one name collapse into one node, so a version may only be
/// carried when they agree on it. Taking the first would make the graph depend on
/// the order the sections happen to be listed in — which is not a resolution of
/// anything, and would report a version half the file contradicts.
#[test]
fn two_declarations_that_disagree_resolve_to_nothing() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0",
             "dependencies": { "split": "=1.0.0", "agreed": "=2.0.0" },
             "peerDependencies": { "split": "=2.0.0", "agreed": "=2.0.0" } }"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(version_of(&built.graph, "split"), None);
    // Agreement is not ambiguity: two declarations naming the same release still
    // name it.
    assert_eq!(version_of(&built.graph, "agreed"), Some("2.0.0"));
}

#[test]
fn a_missing_lockfile_falls_back_to_direct_dependencies() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir.path().join("package.json"),
        r#"{ "name": "app", "version": "1.0.0", "dependencies": { "react": "^18.0.0" } }"#,
    );

    let built = build_project_graph(
        &dir.path().join("package.json"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(
        built.source,
        GraphSource::Manifests,
        "a lockfile would have helped and simply was not there"
    );
    assert_eq!(flatten(&built.graph), vec!["app", "react"]);
}

#[test]
fn builds_the_committed_fixtures_end_to_end() {
    for (dir, manifest, root) in [
        ("sample-npm", "package.json", "sample-app"),
        ("sample-php", "composer.json", "vendor/app"),
        ("sample-elixir", "mix.exs", "sample"),
    ] {
        let built = build_project_graph(
            &fixture(dir).join(manifest),
            &WorkspaceGraphOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{dir}: {e}"));

        assert_eq!(built.source, GraphSource::Lockfile, "{dir}");
        let names = flatten(&built.graph);
        assert_eq!(
            names.first().map(String::as_str),
            Some(root),
            "{dir}: {names:?}"
        );
    }
}

#[test]
fn a_cargo_manifest_is_delegated_to_the_workspace_builder() {
    let built = build_project_graph(
        &fixture("sample-workspace").join("Cargo.toml"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    assert_eq!(built.source, GraphSource::Lockfile);
    assert!(
        built
            .graph
            .nodes()
            .iter()
            .any(|n| n.kind == NodeKind::Workspace),
        "the Cargo path must still classify workspace members"
    );
}

#[test]
fn an_unrecognized_file_is_not_a_manifest() {
    let dir = TempDir::new().expect("tempdir");
    write(&dir.path().join("notes.txt"), "hello");
    assert!(
        build_project_graph(
            &dir.path().join("notes.txt"),
            &WorkspaceGraphOptions::default()
        )
        .is_err()
    );
}
