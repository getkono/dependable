//! Tests for the state machine: navigation, expansion, cycles, and search.
//!
//! No terminal and no network — the whole point of keeping `App` free of both.

use std::path::PathBuf;

use dependable_fetch::core::{LockedPackage, ResolvedLockfile};
use dependable_fetch::{DependencyGraph, Ecosystem, GraphSource};
use dependable_tui::app::{Action, App, Direction, End, Mode};
use dependable_tui::model::Project;
use dependable_tui::rows::RowKind;

/// Build a project from `(name, version, deps)` triples; the first is the root.
fn project(label: &str, packages: &[(&str, &str, &[&str])]) -> Project {
    let root = packages[0].0.to_owned();
    let locked: Vec<LockedPackage> = packages
        .iter()
        .enumerate()
        .map(|(i, (name, version, deps))| {
            LockedPackage::new(
                (*name).to_owned(),
                (*version).to_owned(),
                // The first package is the project itself; the rest are external.
                (i > 0).then(|| "registry+https://example.com".to_owned()),
                deps.iter().map(|d| (*d).to_owned()).collect(),
            )
        })
        .collect();
    let resolved = ResolvedLockfile::from_packages(locked);
    let names = std::iter::once(root.clone()).collect();
    Project {
        manifest: PathBuf::from(label),
        label: label.to_owned(),
        ecosystem: Ecosystem::Rust,
        graph: DependencyGraph::from_resolved(&resolved, &names, &[root]),
        source: GraphSource::Lockfile,
    }
}

/// A three-level project: app -> tokio -> mio, plus app -> serde.
fn sample() -> App {
    App::new(vec![project(
        "Cargo.toml",
        &[
            ("app", "0.1.0", &["tokio", "serde"]),
            ("tokio", "1.0.0", &["mio"]),
            ("serde", "1.0.0", &[]),
            ("mio", "0.8.0", &[]),
        ],
    )])
}

fn names(app: &App) -> Vec<&str> {
    app.rows().iter().map(|r| r.name.as_str()).collect()
}

#[test]
fn a_project_starts_expanded_to_its_roots() {
    let app = sample();
    assert_eq!(names(&app), vec!["Cargo.toml", "app"]);
    assert_eq!(app.rows()[0].kind, RowKind::Project);
}

#[test]
fn expanding_descends_one_level_at_a_time() {
    let mut app = sample();
    app.apply(Action::Move(1)); // select "app"
    app.apply(Action::Expand);
    assert_eq!(names(&app), vec!["Cargo.toml", "app", "tokio", "serde"]);

    app.apply(Action::Move(1)); // select "tokio"
    app.apply(Action::Expand);
    assert_eq!(
        names(&app),
        vec!["Cargo.toml", "app", "tokio", "mio", "serde"],
        "the sub-dependency appears beneath its parent"
    );
}

#[test]
fn collapsing_hides_the_subtree_then_steps_out() {
    let mut app = sample();
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Collapse);
    assert_eq!(names(&app), vec!["Cargo.toml", "app"]);

    // Already collapsed: collapsing again moves to the parent row.
    app.apply(Action::Collapse);
    assert_eq!(app.selected().map(|r| r.name.as_str()), Some("Cargo.toml"));
}

#[test]
fn expanding_an_open_row_steps_into_it() {
    let mut app = sample();
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::Expand);
    assert_eq!(app.selected().map(|r| r.name.as_str()), Some("tokio"));
}

#[test]
fn the_same_package_expands_independently_in_two_places() {
    // `shared` sits under both `a` and `b`; opening one must not open the other.
    let mut app = App::new(vec![project(
        "Cargo.toml",
        &[
            ("app", "0.1.0", &["a", "b"]),
            ("a", "1.0.0", &["shared"]),
            ("b", "1.0.0", &["shared"]),
            ("shared", "1.0.0", &["leaf"]),
            ("leaf", "1.0.0", &[]),
        ],
    )]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand); // app -> a, b
    app.apply(Action::Move(1));
    app.apply(Action::Expand); // a -> shared
    app.apply(Action::Move(1));
    app.apply(Action::Expand); // that shared -> leaf

    assert_eq!(
        names(&app),
        vec!["Cargo.toml", "app", "a", "shared", "leaf", "b"],
        "only the `shared` under `a` opened"
    );
}

#[test]
fn a_cycle_is_marked_and_refuses_to_expand() {
    let mut app = App::new(vec![project(
        "Cargo.toml",
        &[
            ("app", "0.1.0", &["a"]),
            ("a", "1.0.0", &["b"]),
            ("b", "1.0.0", &["a"]),
        ],
    )]);
    app.apply(Action::Move(1));
    app.apply(Action::Expand); // app -> a
    app.apply(Action::Move(1));
    app.apply(Action::Expand); // a -> b
    app.apply(Action::Move(1)); // select b
    app.apply(Action::Expand); // b -> a, which is already on the path

    // Project row 0, `app` 1, `a` 2, `b` 3 — so the repeat of `a` sits at 4.
    let a_again = app
        .rows()
        .iter()
        .find(|r| r.name == "a" && r.depth == 4)
        .expect("the repeat of `a` is shown");
    assert!(a_again.cyclic, "it must be marked as a cycle");
    assert!(!a_again.has_children, "and must not offer to expand");
}

#[test]
fn selection_stays_within_the_list() {
    let mut app = sample();
    app.apply(Action::Move(-5));
    assert_eq!(app.selected_index(), 0);
    app.apply(Action::Move(500));
    assert_eq!(app.selected_index(), app.rows().len() - 1);
    app.apply(Action::JumpTo(End::Top));
    assert_eq!(app.selected_index(), 0);
    app.apply(Action::JumpTo(End::Bottom));
    assert_eq!(app.selected_index(), app.rows().len() - 1);
}

#[test]
fn a_search_opens_the_path_to_a_deep_match() {
    let mut app = sample();
    // `mio` is two levels below anything currently expanded.
    for c in "mio".chars() {
        app.apply(Action::SearchInput(c));
    }
    assert_eq!(
        names(&app),
        vec!["Cargo.toml", "app", "tokio", "mio"],
        "the tree opens along the path to the match and hides the rest"
    );
    assert!(
        app.rows().iter().find(|r| r.name == "mio").unwrap().matched,
        "the match itself is flagged"
    );
    assert!(
        !app.rows()
            .iter()
            .find(|r| r.name == "tokio")
            .unwrap()
            .matched,
        "an ancestor is shown but is not itself a match"
    );
}

#[test]
fn a_glob_search_filters_by_pattern() {
    let mut app = sample();
    for c in "s*".chars() {
        app.apply(Action::SearchInput(c));
    }
    assert!(names(&app).contains(&"serde"));
    assert!(!names(&app).contains(&"mio"));
}

#[test]
fn clearing_the_search_restores_the_tree() {
    let mut app = sample();
    for c in "mio".chars() {
        app.apply(Action::SearchInput(c));
    }
    app.apply(Action::ClearSearch);
    assert_eq!(names(&app), vec!["Cargo.toml", "app"]);
    assert_eq!(app.mode, Mode::Browse);
    assert!(app.query.is_empty());
}

#[test]
fn backspacing_re_widens_the_search() {
    let mut app = sample();
    for c in "serde".chars() {
        app.apply(Action::SearchInput(c));
    }
    assert!(!names(&app).contains(&"tokio"));
    for _ in 0..5 {
        app.apply(Action::SearchBackspace);
    }
    assert_eq!(names(&app), vec!["Cargo.toml", "app"], "back to no filter");
}

#[test]
fn cycling_moves_between_matches_and_wraps() {
    let mut app = App::new(vec![project(
        "Cargo.toml",
        &[
            ("app", "0.1.0", &["serde", "serde_json"]),
            ("serde", "1.0.0", &[]),
            ("serde_json", "1.0.0", &[]),
        ],
    )]);
    for c in "serde*".chars() {
        app.apply(Action::SearchInput(c));
    }
    app.apply(Action::CycleMatch(Direction::Forward));
    assert_eq!(app.selected().map(|r| r.name.as_str()), Some("serde"));
    app.apply(Action::CycleMatch(Direction::Forward));
    assert_eq!(app.selected().map(|r| r.name.as_str()), Some("serde_json"));
    app.apply(Action::CycleMatch(Direction::Forward));
    assert_eq!(
        app.selected().map(|r| r.name.as_str()),
        Some("serde"),
        "cycling wraps around"
    );
}

#[test]
fn a_search_with_no_matches_says_so() {
    let mut app = sample();
    for c in "nonexistent".chars() {
        app.apply(Action::SearchInput(c));
    }
    app.apply(Action::CycleMatch(Direction::Forward));
    assert_eq!(app.message.as_deref(), Some("no matches"));
}

#[test]
fn inverting_shows_what_depends_on_a_package() {
    let mut app = sample();
    app.apply(Action::ToggleInvert);
    assert!(app.inverted);
    // Inverting reverses the edges, so `app` no longer depends on anything.
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    assert_eq!(names(&app), vec!["Cargo.toml", "app"]);
    app.apply(Action::ToggleInvert);
    assert!(!app.inverted);
}

#[test]
fn only_a_registry_package_is_worth_looking_up() {
    let mut app = sample();
    assert_eq!(
        app.selected_key(),
        None,
        "a project row has nothing to fetch"
    );

    app.apply(Action::Move(1)); // `app` — a workspace member, not a registry package
    assert_eq!(
        app.selected_key(),
        None,
        "a workspace member must never be looked up: the registry may hold an \
         unrelated package of the same name, whose description, license and \
         versions would then be shown as if they were this one's"
    );

    app.apply(Action::Expand);
    app.apply(Action::Move(1)); // `tokio` — actually resolved from the registry
    assert_eq!(
        app.selected_key(),
        Some((Ecosystem::Rust, "tokio".to_owned(), "1.0.0".to_owned()))
    );
}

#[test]
fn the_viewport_follows_the_selection() {
    let mut app = sample();
    app.apply(Action::Move(1));
    app.apply(Action::Expand);
    app.apply(Action::JumpTo(End::Bottom));
    app.scroll_into_view(2);
    assert_eq!(app.offset, app.rows().len() - 2);
    app.apply(Action::JumpTo(End::Top));
    app.scroll_into_view(2);
    assert_eq!(app.offset, 0);
}

#[test]
fn help_toggles_on_and_off() {
    let mut app = sample();
    app.apply(Action::ToggleHelp);
    assert_eq!(app.mode, Mode::Help);
    app.apply(Action::ToggleHelp);
    assert_eq!(app.mode, Mode::Browse);
}

#[test]
fn an_empty_project_list_is_navigable_without_panicking() {
    let mut app = App::new(Vec::new());
    for action in [
        Action::Move(1),
        Action::Move(-1),
        Action::Expand,
        Action::Collapse,
        Action::Toggle,
        Action::JumpTo(End::Bottom),
        Action::Refresh,
    ] {
        app.apply(action);
    }
    assert!(app.rows().is_empty());
    assert!(app.selected().is_none());
}
