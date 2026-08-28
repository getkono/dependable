//! Render tests using ratatui's `TestBackend`.
//!
//! No real terminal is involved, so these run identically on Linux, macOS, and
//! Windows in CI. They assert on what the user can actually read.

use std::path::PathBuf;

use dependable_fetch::core::{LockedPackage, ResolvedLockfile};
use dependable_fetch::{
    DependencyGraph, DependencyStatus, Ecosystem, GraphSource, Owner, OwnerKind, PackageMetadata,
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
    meta.owners = vec![
        {
            let mut owner = Owner::named("David Tolnay");
            owner.login = Some("dtolnay".to_owned());
            owner.url = Some("https://github.com/dtolnay".to_owned());
            owner
        },
        {
            let mut owner = Owner::default();
            owner.login = Some("oli-obk".to_owned());
            owner
        },
        {
            let mut owner = Owner::named("libs");
            owner.kind = OwnerKind::Team;
            owner
        },
    ];
    meta.published = std::collections::BTreeMap::from([
        ("1.0.0".to_owned(), "2021-03-04T00:00:00Z".to_owned()),
        ("2.0.0".to_owned(), "2025-11-12T00:00:00Z".to_owned()),
    ]);
    meta.latest_published = Some("2025-11-12T00:00:00Z".to_owned());
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
        .draw(|frame| {
            ui::draw(frame, app);
        })
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

/// Render `app` and return the styled cells of the row at `y`.
fn styled_row(app: &mut App, y: u16) -> Vec<ratatui::buffer::Cell> {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
    terminal
        .draw(|frame| {
            ui::draw(frame, app);
        })
        .expect("draw succeeds");
    let buffer = terminal.backend().buffer();
    (0..100).map(|x| buffer[(x, y)].clone()).collect()
}

#[test]
fn the_selected_row_is_never_marked_by_a_background_alone() {
    // The regression this guards: selection set only a background and left the
    // row's own foreground on top of it, so on a light terminal the selected
    // row was dark text on a dark bar. Whichever tier is in force, the row must
    // be distinguished, and never by a background with no foreground to match.
    use ratatui::style::{Color, Modifier};

    let mut app = App::new(vec![project(GraphSource::Lockfile)]);

    // Row 0 of the tree pane sits just inside the block's top border.
    let cells = styled_row(&mut app, 1);
    let marked = cells
        .iter()
        .find(|c| c.bg != Color::Reset || c.modifier.contains(Modifier::REVERSED))
        .expect("the selected row is distinguished somehow");

    if marked.bg == Color::Reset {
        // The 16-colour tier reverses, which is legible by construction.
        assert!(marked.modifier.contains(Modifier::REVERSED));
        return;
    }
    assert_ne!(
        marked.fg,
        Color::Reset,
        "a selection background with no foreground is the illegible case"
    );
    assert_ne!(
        marked.fg, marked.bg,
        "selected text must not match the bar it sits on"
    );
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

/// Select `serde` and hand it a completed lookup, as the metadata test does.
fn app_with_serde_metadata() -> App {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1));
    app.set_data(
        key(Ecosystem::Rust, "serde", "1.0.0"),
        PackageData::Ready(Box::new(PackageFacts {
            metadata: Some(metadata()),
            latest: Some("2.0.0".to_owned()),
            status: Some(DependencyStatus::UpdateAvailable),
            vulnerabilities: Vec::new(),
            warnings: Vec::new(),
        })),
    );
    app
}

#[test]
fn each_owner_is_shown_with_the_identifiers_the_registry_published() {
    let mut app = app_with_serde_metadata();
    let screen = render(&mut app);

    assert!(
        screen.contains("David Tolnay (@dtolnay)"),
        "a name and a login are both shown: {screen}"
    );
    assert!(
        screen.contains("@oli-obk"),
        "an owner known only by login is shown by it: {screen}"
    );
    assert!(
        screen.contains("[team]"),
        "a team owner is marked as one: {screen}"
    );
}

#[test]
fn the_publish_date_describes_the_resolved_version_not_the_newest() {
    // The bug this guards: `published` printed the newest release's date
    // directly beneath `resolved`, so a project pinned to 1.0.0 was shown
    // 2.0.0's release date as its own.
    let mut app = app_with_serde_metadata();
    let screen = render(&mut app);

    assert!(
        screen.contains("2021-03-04"),
        "1.0.0's own publish date: {screen}"
    );
    assert!(
        screen.contains("2025-11-12"),
        "2.0.0's release date, labelled separately: {screen}"
    );
    assert!(
        screen.contains("ago)"),
        "each date carries its age in parentheses: {screen}"
    );
}

#[test]
fn the_latest_release_is_not_repeated_when_it_is_the_resolved_one() {
    // Nothing is learned from the same date twice under two labels.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1));

    let mut meta = metadata();
    meta.published =
        std::collections::BTreeMap::from([("1.0.0".to_owned(), "2021-03-04T00:00:00Z".to_owned())]);
    meta.latest_published = Some("2021-03-04T00:00:00Z".to_owned());
    app.set_data(
        key(Ecosystem::Rust, "serde", "1.0.0"),
        PackageData::Ready(Box::new(PackageFacts {
            metadata: Some(meta),
            latest: Some("1.0.0".to_owned()),
            status: Some(DependencyStatus::UpToDate),
            vulnerabilities: Vec::new(),
            warnings: Vec::new(),
        })),
    );

    let screen = render(&mut app);
    assert!(screen.contains("published"), "{screen}");
    assert!(
        !screen.contains("released"),
        "the latest release is the resolved one, so it is not repeated: {screen}"
    );
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
            .draw(|frame| {
                ui::draw(frame, &mut app);
            })
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

#[test]
fn a_url_is_written_as_a_clickable_link_showing_its_readable_form() {
    use ratatui::buffer::CellWidth;

    let mut app = app_with_serde_metadata();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
    terminal
        .draw(|frame| {
            ui::draw(frame, &mut app);
        })
        .expect("draw succeeds");
    let buffer = terminal.backend().buffer();

    let link = buffer
        .content()
        .iter()
        .find(|cell| cell.symbol().contains("\u{1b}]8;;"))
        .expect("a hyperlink was written");

    assert!(
        link.symbol()
            .contains("\u{1b}]8;;https://github.com/serde-rs/serde\u{1b}\\"),
        "the full URL is the target: {:?}",
        link.symbol()
    );
    assert!(
        link.symbol().contains("github.com/serde-rs/serde"),
        "the readable form is the visible text: {:?}",
        link.symbol()
    );
    assert!(
        link.symbol().ends_with("\u{1b}]8;;\u{1b}\\"),
        "the link is terminated: {:?}",
        link.symbol()
    );
    assert_eq!(
        link.cell_width(),
        "github.com/serde-rs/serde".len() as u16,
        "the cell occupies the columns of the visible text, not of the escapes"
    );
}

#[test]
fn a_link_does_not_change_how_many_columns_the_pane_uses() {
    // The escapes live inside one cell's symbol, which declares the width of
    // its visible text. Walking a row the way the diff does -- stepping over
    // the columns a forced-width cell covers -- must still total the terminal
    // width. If the accounting were wrong, everything after a link on that line
    // would be shifted.
    use ratatui::buffer::CellWidth;

    let mut app = app_with_serde_metadata();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
    terminal
        .draw(|frame| {
            ui::draw(frame, &mut app);
        })
        .expect("draw succeeds");
    let buffer = terminal.backend().buffer();

    let mut rows_with_links = 0;
    for y in 0..30u16 {
        let mut columns = 0u16;
        let mut x = 0u16;
        let mut linked = false;
        while x < 100 {
            let cell = &buffer[(x, y)];
            linked |= cell.symbol().contains("\u{1b}]8;;");
            let width = cell.cell_width().max(1);
            columns += width;
            x += width;
        }
        assert_eq!(columns, 100, "row {y} does not total the terminal width");
        rows_with_links += u32::from(linked);
    }
    assert!(rows_with_links > 0, "the fixture renders at least one link");
}

#[test]
fn pressing_o_asks_for_the_packages_repository() {
    let mut app = app_with_serde_metadata();
    assert_eq!(
        app.selected_url(),
        Some("https://github.com/serde-rs/serde"),
        "the repository is the link a reader most likely wants"
    );

    app.apply(Action::OpenLink);
    assert_eq!(
        app.take_open_request().as_deref(),
        Some("https://github.com/serde-rs/serde")
    );
    assert_eq!(
        app.take_open_request(),
        None,
        "the request is taken once, not repeated every frame"
    );
}

#[test]
fn pressing_o_on_a_package_with_no_link_says_so() {
    // A key that silently does nothing reads as broken.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::OpenLink);
    assert_eq!(app.take_open_request(), None);
    assert!(app.message.is_some(), "the user is told why nothing opened");
}
