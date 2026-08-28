//! Render tests using ratatui's `TestBackend`.
//!
//! No real terminal is involved, so these run identically on Linux, macOS, and
//! Windows in CI. They assert on what the user can actually read.

use std::path::PathBuf;

use dependable_fetch::core::{LockedPackage, ResolvedLockfile};
use dependable_fetch::{
    DependencyGraph, DependencyStatus, Ecosystem, GraphSource, PackageMetadata,
};
use dependable_tui::app::{Action, App};
use dependable_tui::model::{PackageData, PackageFacts, Project, key};
use dependable_tui::ui;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

/// `PackageMetadata` is `#[non_exhaustive]`, so it is built by assignment.
fn metadata() -> PackageMetadata {
    let mut meta = PackageMetadata::default();
    meta.description = Some("Serialization framework".to_owned());
    meta.repository = Some("https://github.com/serde-rs/serde".to_owned());
    meta.license = Some("MIT OR Apache-2.0".to_owned());
    meta.authors = vec!["David Tolnay".to_owned()];
    meta.downloads = Some(5_000_000);
    meta
}

fn project(source: GraphSource) -> Project {
    let packages = vec![
        LockedPackage::new("app".into(), "0.1.0".into(), None, vec!["serde".into()]),
        LockedPackage::new(
            "serde".into(),
            "1.0.0".into(),
            Some("registry+https://example.com".into()),
            Vec::new(),
        ),
    ];
    let resolved = ResolvedLockfile::from_packages(packages);
    let names = std::iter::once("app".to_owned()).collect();
    Project {
        manifest: PathBuf::from("Cargo.toml"),
        label: "Cargo.toml".to_owned(),
        ecosystem: Ecosystem::Rust,
        graph: DependencyGraph::from_resolved(&resolved, &names, &["app".to_owned()]),
        source,
    }
}

/// Render `app` into an 100x30 buffer and return it as plain text.
fn render(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
    terminal
        .draw(|frame| ui::draw(frame, app))
        .expect("draw succeeds");
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(100)
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_tree_and_detail_panes_both_render() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    let screen = render(&mut app);
    assert!(screen.contains("dependencies"), "{screen}");
    assert!(screen.contains("details"), "{screen}");
    assert!(screen.contains("Cargo.toml"), "{screen}");
    assert!(screen.contains("app"), "{screen}");
}

#[test]
fn expanding_shows_the_dependency_and_its_version() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    let screen = render(&mut app);
    assert!(screen.contains("serde"), "{screen}");
    assert!(screen.contains("1.0.0"), "{screen}");
}

#[test]
fn a_shallow_graph_says_why_it_is_shallow() {
    // The user must never read "no dependencies" where we mean "we cannot tell".
    let mut app = App::new(vec![project(GraphSource::Unsupported)]);
    let screen = render(&mut app);
    assert!(
        screen.contains("records no dependency edges"),
        "the caveat must be visible: {screen}"
    );
}

#[test]
fn a_missing_lockfile_is_reported_differently_from_an_unsupported_one() {
    let mut app = App::new(vec![project(GraphSource::Manifests)]);
    let screen = render(&mut app);
    assert!(screen.contains("no lockfile found"), "{screen}");
}

#[test]
fn metadata_is_rendered_when_it_arrives() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1)); // select serde

    app.set_data(
        key(Ecosystem::Rust, "serde", "1.0.0"),
        PackageData::Ready(Box::new(PackageFacts {
            metadata: Some(metadata()),
            latest: Some("1.0.9".to_owned()),
            status: Some(DependencyStatus::UpdateAvailable),
            vulnerabilities: vec!["RUSTSEC-2020-0001".to_owned()],
            warnings: Vec::new(),
        })),
    );

    let screen = render(&mut app);
    assert!(screen.contains("serde-rs/serde"), "repository: {screen}");
    assert!(screen.contains("MIT OR Apache-2.0"), "license: {screen}");
    assert!(screen.contains("David Tolnay"), "owners: {screen}");
    assert!(screen.contains("5.0M"), "downloads: {screen}");
    assert!(screen.contains("RUSTSEC-2020-0001"), "advisory: {screen}");
    assert!(screen.contains("update available"), "status: {screen}");
}

#[test]
fn an_unpublished_field_says_so_rather_than_rendering_blank() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1));
    app.set_data(
        key(Ecosystem::Rust, "serde", "1.0.0"),
        PackageData::Ready(Box::new(PackageFacts {
            metadata: Some(PackageMetadata::default()),
            ..PackageFacts::default()
        })),
    );
    let screen = render(&mut app);
    assert!(screen.contains("not published"), "{screen}");
}

#[test]
fn a_failed_lookup_is_shown_with_a_way_to_retry() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1));
    app.set_data(
        key(Ecosystem::Rust, "serde", "1.0.0"),
        PackageData::Failed("connection refused".to_owned()),
    );
    let screen = render(&mut app);
    assert!(screen.contains("could not load"), "{screen}");
    assert!(screen.contains("connection refused"), "{screen}");
    assert!(screen.contains("press r to try again"), "{screen}");
}

#[test]
fn the_help_overlay_lists_the_keys() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::ToggleHelp);
    let screen = render(&mut app);
    assert!(screen.contains("keys"), "{screen}");
    assert!(screen.contains("quit"), "{screen}");
    assert!(screen.contains("search by glob"), "{screen}");
}

#[test]
fn the_search_line_shows_the_query_being_typed() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::BeginSearch);
    for c in "serde".chars() {
        app.apply(Action::SearchInput(c));
    }
    let screen = render(&mut app);
    assert!(screen.contains("/serde"), "{screen}");
}

#[test]
fn an_empty_workspace_renders_without_panicking() {
    let mut app = App::new(Vec::new());
    let screen = render(&mut app);
    assert!(screen.contains("nothing to show"), "{screen}");
}

#[test]
fn a_tiny_terminal_does_not_panic() {
    // Users resize to absurd sizes; a panic here leaves the terminal broken.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    for (w, h) in [(1, 1), (4, 3), (20, 5), (200, 60)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("terminal");
        terminal
            .draw(|frame| ui::draw(frame, &mut app))
            .unwrap_or_else(|e| panic!("{w}x{h} failed: {e}"));
    }
}

#[test]
fn a_workspace_member_is_never_shown_registry_data() {
    // Regression: `app 0.1.0` is this repository's own crate. crates.io has an
    // unrelated crate called `app`, and showing its description, license and
    // "update available" here would be actively misleading.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1)); // the workspace member
    let screen = render(&mut app);
    // Asserted on a fragment short enough not to wrap in the test pane.
    assert!(
        screen.contains("member of this workspace"),
        "it must say why nothing is shown: {screen}"
    );
    assert!(
        !screen.contains("loading"),
        "and must not sit there pretending to fetch: {screen}"
    );
}
