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

/// Render `app` and return the screen as lines, with the geometry that frame
/// reported for resolving pointer positions.
fn render_with_geometry(app: &mut App) -> (Vec<String>, ui::Geometry) {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
    let mut geometry = ui::Geometry::default();
    terminal
        .draw(|frame| {
            geometry = ui::draw(frame, app);
        })
        .expect("draw succeeds");
    let lines = terminal
        .backend()
        .buffer()
        .content()
        .chunks(100)
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        })
        .collect();
    (lines, geometry)
}

/// Render `app` and return every styled cell on screen.
fn styled_cells(app: &mut App) -> Vec<ratatui::buffer::Cell> {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
    terminal
        .draw(|frame| {
            ui::draw(frame, app);
        })
        .expect("draw succeeds");
    terminal.backend().buffer().content().to_vec()
}

#[test]
fn the_selected_row_is_never_marked_by_a_background_alone() {
    // The regression this guards: selection set only a background and left the
    // row's own foreground on top of it, so on a light terminal the selected
    // row was dark text on a dark bar. Whichever tier is in force, the row must
    // be distinguished, and never by a background with no foreground to match.
    use ratatui::style::{Color, Modifier};

    let mut app = App::new(vec![project(GraphSource::Lockfile)]);

    // Found rather than indexed by position, so adding chrome above the panes
    // does not silently turn this into an assertion about a different row.
    let cells = styled_cells(&mut app);
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

    // By its URL, not by position: the pane writes several links, and this is
    // an assertion about how one of them is built.
    let link = buffer
        .content()
        .iter()
        .find(|cell| {
            cell.symbol()
                .contains("\u{1b}]8;;https://github.com/serde-rs/serde")
        })
        .expect("the repository was written as a hyperlink");

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
        link.symbol().contains("\u{1b}]8;;\u{1b}\\"),
        "the link is terminated: {:?}",
        link.symbol()
    );
    // The cell claims the rest of its row so a shorter link cannot leave the
    // tail of a longer one behind; the label itself is what is visible.
    assert!(
        link.cell_width() >= "github.com/serde-rs/serde".len() as u16,
        "the cell reports screen columns, not the length of its escapes"
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
        app.selected_url().as_deref(),
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

#[test]
fn the_header_names_the_product_and_what_was_scanned() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.root = Some(PathBuf::from("/home/dev/acme"));

    let screen = render(&mut app);
    let header = screen.lines().next().expect("a header row");

    assert!(
        header.starts_with("dependable"),
        "the wordmark is hard left: {header:?}"
    );
    assert!(header.contains("/home/dev/acme"), "{header:?}");
    assert!(header.contains("packages"), "{header:?}");
}

#[test]
fn the_wordmark_is_the_only_thing_in_the_brand_colour() {
    // The brand colour identifies the product; spending it on ordinary labels
    // would stop it doing that.
    use dependable_tui::theme::{self, Token};

    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.root = Some(PathBuf::from("/home/dev/acme"));
    let cells = styled_cells(&mut app);

    let brand = theme::fg(Token::Brand).fg.expect("the brand has a colour");
    let painted: String = cells
        .iter()
        .filter(|cell| cell.fg == brand)
        .map(ratatui::buffer::Cell::symbol)
        .collect();
    assert_eq!(painted, "dependable", "brand-coloured cells: {painted:?}");
}

#[test]
fn the_header_omits_a_path_it_was_never_given() {
    // Before discovery reports back there is nothing to name, and inventing a
    // path would be worse than leaving the space empty.
    let mut app = App::new(Vec::new());
    let screen = render(&mut app);
    let header = screen.lines().next().expect("a header row");
    assert_eq!(header.trim(), "dependable", "{header:?}");
}

/// The character column a substring starts at.
///
/// Not the byte offset: the panes are drawn with box-drawing characters, which
/// are three bytes each, so byte offsets do not line up with screen columns.
fn column_of(line: &str, needle: &str) -> Option<usize> {
    let byte = line.find(needle)?;
    Some(line[..byte].chars().count())
}

/// The tree pane's share of a rendered line, as characters.
fn tree_part(line: &str, width: usize) -> String {
    line.chars().take(width).collect()
}

#[test]
fn the_tree_is_laid_out_in_aligned_columns() {
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);

    let screen = render(&mut app);
    let heading = screen
        .lines()
        .find(|line| line.contains("NAME"))
        .expect("a column heading row");

    let name = column_of(heading, "NAME").expect("NAME");
    let version = column_of(heading, "VERSION").expect("VERSION");
    let age = column_of(heading, "AGE").expect("AGE");
    let status = column_of(heading, "STATUS").expect("STATUS");
    assert!(
        name < version && version < age && age < status,
        "columns are ordered left to right: {heading:?}"
    );

    // Every version sits under the VERSION heading, which is the whole point of
    // the layout: a reader scans one column instead of hunting along each row.
    // Only the tree pane is searched -- the detail pane prints versions too.
    let tree_width = status + "STATUS".len();
    let versions: Vec<usize> = screen
        .lines()
        .map(|line| tree_part(line, tree_width))
        .filter_map(|line| column_of(&line, "0.1.0").or_else(|| column_of(&line, "1.0.0")))
        .collect();
    assert!(!versions.is_empty(), "some versions render: {screen}");
    for column in versions {
        assert_eq!(column, version, "a version is out of its column: {screen}");
    }
}

#[test]
fn a_local_package_reports_its_origin_in_the_status_column() {
    // The freshness badge and the origin never apply to the same row, so they
    // share a column rather than the origin crowding out the name.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);

    let screen = render(&mut app);
    let heading = screen
        .lines()
        .find(|line| line.contains("NAME"))
        .expect("a column heading row");
    let status = column_of(heading, "STATUS").expect("STATUS");

    let row = screen
        .lines()
        // Wide enough to include the whole status column, not just its heading.
        .map(|line| tree_part(line, status + "workspace".len()))
        .find(|line| line.contains("workspace"))
        .expect("the workspace member");
    assert_eq!(
        column_of(&row, "workspace"),
        Some(status),
        "the origin sits in the status column: {row:?}"
    );
}

#[test]
fn switching_to_a_package_with_less_to_say_leaves_nothing_behind() {
    // Redrawing is a diff against the previous frame, and a forced-width cell
    // makes the diff step over columns it never compares. A package with long
    // values must not leave fragments of them behind the next one's short ones.
    let mut app = app_with_serde_metadata();
    let _ = render(&mut app);

    let mut sparse = PackageMetadata::default();
    sparse.description = Some("tiny".to_owned());
    sparse.repository = Some("https://ex.io/a".to_owned());
    app.set_data(
        key(Ecosystem::Rust, "serde", "1.0.0"),
        PackageData::Ready(Box::new(PackageFacts {
            metadata: Some(sparse),
            latest: Some("1.0.0".to_owned()),
            status: Some(DependencyStatus::UpToDate),
            vulnerabilities: Vec::new(),
            warnings: Vec::new(),
        })),
    );

    let screen = render(&mut app);
    for fragment in [
        "serde-rs",
        "dtolnay",
        "oli-obk",
        "team",
        "5.0M",
        "2021-03-04",
        "Serialization",
    ] {
        assert!(
            !screen.contains(fragment),
            "{fragment:?} survived from the previous package:\n{screen}"
        );
    }
}

#[test]
fn a_click_lands_on_the_row_the_frame_actually_drew() {
    // The regression this guards: the pointer mapping was written before the
    // tree grew a column header, and only the table learned about it. Every
    // click and hover then resolved one row too high, so clicking a parent
    // selected the child underneath it.
    //
    // Asserted against the buffer rather than against a second guess at the
    // layout: the only claim `Geometry` makes is about where this frame put
    // things, so the frame is what has to be asked.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);

    let names: Vec<String> = app.rows().iter().map(|row| row.name.clone()).collect();
    assert_eq!(names, ["Cargo.toml", "app", "serde"], "the fixture");

    let (lines, geometry) = render_with_geometry(&mut app);
    // Only the tree's half of each line: the detail pane names the selection
    // too, and a row must be found by where it was drawn, not by its text.
    let tree_of = |line: &str| line.chars().take(50).collect::<String>();

    for (index, name) in names.iter().enumerate() {
        let y = lines
            .iter()
            .position(|line| tree_of(line).contains(name.as_str()))
            .unwrap_or_else(|| panic!("{name} is on screen:\n{}", lines.join("\n")));
        assert_eq!(
            geometry.row_at(3, u16::try_from(y).expect("in range")),
            Some(index),
            "clicking the line {name} was drawn on selects {name}"
        );
    }

    let header = lines
        .iter()
        .position(|line| tree_of(line).contains("NAME"))
        .expect("the column header is on screen");
    assert_eq!(
        geometry.row_at(3, u16::try_from(header).expect("in range")),
        None,
        "the column header is not a row"
    );
}

/// Every hyperlink target on screen for `app`.
fn link_targets(app: &mut App) -> Vec<String> {
    styled_cells(app)
        .iter()
        .filter_map(|cell| {
            let symbol = cell.symbol();
            let rest = symbol.strip_prefix("\u{1b}]8;;")?;
            Some(rest.split('\u{1b}').next()?.to_owned())
        })
        .filter(|url| !url.is_empty())
        .collect()
}

#[test]
fn a_package_links_to_its_own_page_on_the_registry() {
    // The one URL that always exists. It is derived from the name rather than
    // fetched, so it is on screen before anything has been looked up.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1)); // serde, with no metadata loaded

    let screen = render(&mut app);
    assert!(screen.contains("registry"), "{screen}");
    assert!(screen.contains("crates.io/crates/serde"), "{screen}");
    assert!(
        link_targets(&mut app).contains(&"https://crates.io/crates/serde".to_owned()),
        "and it is clickable"
    );
}

#[test]
fn the_resolved_version_links_to_that_versions_page() {
    // The package page describes the newest release, which is a different set
    // of facts when the project is several versions behind.
    let mut app = app_with_serde_metadata();
    assert!(
        link_targets(&mut app).contains(&"https://crates.io/crates/serde/1.0.0".to_owned()),
        "the resolved version, not the latest one"
    );
}

#[test]
fn a_package_that_published_no_docs_url_still_links_to_docs_rs() {
    // docs.rs builds documentation for every crate it hosts, so the page is a
    // fact about the ecosystem rather than a claim about the registry record.
    let mut app = app_with_serde_metadata();
    assert_eq!(
        metadata().documentation,
        None,
        "the fixture publishes no documentation URL"
    );

    let screen = render(&mut app);
    assert!(screen.contains("docs.rs/serde/1.0.0"), "{screen}");
    assert!(
        link_targets(&mut app).contains(&"https://docs.rs/serde/1.0.0".to_owned()),
        "and the ecosystem's own docs host is what it points at"
    );
}

#[test]
fn a_workspace_member_is_never_linked_to_a_registry_page() {
    // `app 0.1.0` is this repository's own crate; crates.io has an unrelated
    // crate called `app`, and linking to it would send the reader somewhere
    // actively wrong.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));

    let screen = render(&mut app);
    assert!(!screen.contains("crates.io"), "{screen}");
    assert!(
        link_targets(&mut app).is_empty(),
        "and nothing is clickable"
    );

    app.apply(Action::OpenLink);
    assert_eq!(app.take_open_request(), None, "and `o` opens nothing");
}

#[test]
fn pressing_o_falls_back_to_the_registry_page() {
    // A package the registry published no links for, and one nothing has been
    // looked up for yet, both still have somewhere to send the reader.
    let mut app = App::new(vec![project(GraphSource::Lockfile)]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Move(1)); // serde, unfetched

    app.apply(Action::OpenLink);
    assert_eq!(
        app.take_open_request().as_deref(),
        Some("https://crates.io/crates/serde")
    );
}
