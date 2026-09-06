//! What the TUI asks a registry about a version the *manifest* pinned.
//!
//! The other `unknown` tests in this crate build their graph by hand with
//! `DependencyGraph::from_resolved`, so none of them can reach `exact_pin` at all.
//! These start from a real Gradle catalog, build the project exactly as
//! `data::discover_projects` does, walk the row through `App::selected_key`, and
//! then make the same `check_version` call `data::lookup` makes with the key that
//! comes out. That is the whole path a version travels from a manifest to a badge.

use std::fs;

use dependable_fetch::core::check_version;
use dependable_fetch::{
    DependencyStatus, Ecosystem, ManifestKind, WorkspaceGraphOptions, build_project_graph,
};
use dependable_tui::app::{Action, App, End};
use dependable_tui::model::{Project, key};
use tempfile::TempDir;

/// A catalog holding one three-segment version and one two-segment one. Both are
/// exact under Maven's reading; only one of them is a `semver::Version` as written.
const CATALOG: &str = r#"
[versions]
okhttp = "4.12.0"
junit = "4.12"

[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
junit = { module = "junit:junit", version.ref = "junit" }
"#;

/// Build the project the way `data::discover_projects` does: from the file on
/// disk, through `build_project_graph`, with the ecosystem the manifest's own kind
/// reports.
fn catalog_project() -> (TempDir, Project) {
    let dir = TempDir::new().expect("tempdir");
    let manifest = dir.path().join("gradle/libs.versions.toml");
    fs::create_dir_all(manifest.parent().expect("parent")).expect("mkdir");
    fs::write(&manifest, CATALOG).expect("write");

    let kind = ManifestKind::detect(&manifest).expect("a known manifest kind");
    let built = build_project_graph(&manifest, &WorkspaceGraphOptions::default()).expect("graph");
    let project = Project {
        label: "gradle/libs.versions.toml".to_owned(),
        manifest,
        ecosystem: kind.ecosystem(),
        graph: built.graph,
        source: built.source,
    };
    (dir, project)
}

/// Move the selection onto the row for `name`, expanding as it goes, so the test
/// exercises the same navigation a user performs rather than reaching into state.
fn select_named(app: &mut App, name: &str) {
    app.apply(Action::JumpTo(End::Top));
    for _ in 0..64 {
        if app.selected().is_some_and(|row| row.name == name) {
            return;
        }
        app.apply(Action::Expand);
        app.apply(Action::Move(1));
    }
    panic!("no row named {name} in {:?}", rows_of(app));
}

fn rows_of(app: &App) -> Vec<String> {
    app.rows().iter().map(|row| row.name.clone()).collect()
}

/// The version a catalog states outright is the version the detail pane asks
/// about — no lockfile involved, and no fallback to "whatever is newest".
#[test]
fn a_pinned_dependency_is_looked_up_at_the_version_the_manifest_named() {
    let (_dir, project) = catalog_project();
    assert_eq!(project.ecosystem, Ecosystem::Jvm);
    let mut app = App::new(vec![project]);

    select_named(&mut app, "com.squareup.okhttp3:okhttp");
    assert_eq!(
        app.selected_key(),
        Some(key(Ecosystem::Jvm, "com.squareup.okhttp3:okhttp", "4.12.0")),
        "the catalog settled this version, so it is what the lookup is about"
    );

    // The call `data::lookup` makes with that key, against what the registry
    // publishes. `4.12.0` is behind `5.0.0`, and the pipeline says so.
    let published = ["4.12.0".to_owned(), "5.0.0".to_owned()];
    let evaluation = check_version("*", &published, Some("4.12.0"));
    assert_eq!(evaluation.status, DependencyStatus::UpdateAvailable);
    assert_eq!(evaluation.latest_available.as_deref(), Some("5.0.0"));
}

/// The regression this file exists for. `junit:junit` is published as `4.12` —
/// exact beyond doubt, and not a `semver::Version`. Carrying it into the graph put
/// a string into `Node::version` that `check_version` reads as *no* version at
/// all, so the comparison fell back to the newest release and the row rendered a
/// green `ok` for a dependency three releases behind.
///
/// The second half of the test is that failure, run directly: it is what the
/// pipeline would answer if the version were ever carried, which is why the graph
/// must not carry it and why no lookup is spawned.
#[test]
fn a_pin_the_comparison_engine_cannot_read_is_never_looked_up() {
    let (_dir, project) = catalog_project();
    let mut app = App::new(vec![project]);

    select_named(&mut app, "junit:junit");
    assert_eq!(
        app.selected().and_then(|row| row.version.clone()),
        None,
        "a version no consumer can parse is not a version this graph reports"
    );
    assert_eq!(
        app.selected_key(),
        None,
        "with nothing to ask about there is no lookup to make"
    );

    let published = ["4.11", "4.12", "4.13", "4.13.1", "4.13.2"].map(str::to_owned);
    let evaluation = check_version("*", &published, Some("4.12"));
    assert_eq!(
        evaluation.status,
        DependencyStatus::UpToDate,
        "the answer the pipeline gives for an unparseable current version — a \
         false `ok`, which is why the version must never reach here"
    );
    assert_eq!(evaluation.latest_available.as_deref(), Some("4.13.2"));
}
