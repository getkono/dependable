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

/// A manifest names its dependencies; it does not resolve them. The graph must
/// say the version is *unknown* rather than record it as the empty string, which
/// downstream reads as a version and evaluates as though it were one.
#[test]
fn a_manifest_only_graph_leaves_every_dependency_version_unknown() {
    let built = build_project_graph(
        &fixture("sample-kotlin").join("gradle/libs.versions.toml"),
        &WorkspaceGraphOptions::default(),
    )
    .expect("graph");

    let unresolved: Vec<&str> = built
        .graph
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Registry)
        .filter(|n| n.version.is_some())
        .map(|n| n.name.as_str())
        .collect();
    assert!(
        !built.graph.nodes().is_empty(),
        "the fixture must produce a graph to assert about"
    );
    assert_eq!(
        unresolved,
        Vec::<&str>::new(),
        "nothing read a version for these, so none may claim one"
    );
    assert!(
        built
            .graph
            .nodes()
            .iter()
            .all(|n| n.version.as_deref() != Some("")),
        "an unknown version is `None`, never an empty string"
    );
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
