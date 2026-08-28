//! The application state machine.
//!
//! Deliberately free of IO and of ratatui: every navigation, expansion, search and
//! loading transition is decided here, so all of it is unit-testable without a
//! terminal or a network. The event loop feeds it actions; the renderer reads it.

use std::collections::HashSet;

use dependable_fetch::Ecosystem;

use crate::filter::Filter;
use crate::model::{PackageData, PackageKey, PackageStore, Project, key};
use crate::rows::{Row, RowKind, RowPath, visible};

/// What the user is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Navigating the tree.
    Browse,
    /// Typing in the search box.
    Search,
    /// Reading the help overlay.
    Help,
}

/// One thing the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Move the selection by a number of rows (negative moves up).
    Move(isize),
    /// Jump to the first or last row.
    JumpTo(End),
    /// Expand the selected row, or step into it if already expanded.
    Expand,
    /// Collapse the selected row, or step out to its parent.
    Collapse,
    /// Expand if collapsed, collapse if expanded.
    Toggle,
    /// Start typing a search.
    BeginSearch,
    /// Append a character to the search query.
    SearchInput(char),
    /// Delete the last character of the search query.
    SearchBackspace,
    /// Leave the search box, keeping the query.
    CommitSearch,
    /// Clear the search entirely.
    ClearSearch,
    /// Move to the next or previous search match.
    CycleMatch(Direction),
    /// Invert every project's graph, showing what depends on each package.
    ToggleInvert,
    /// Re-request data for the selected package.
    Refresh,
    /// Show or hide the help overlay.
    ToggleHelp,
    /// Leave the application.
    Quit,
}

/// Which end of the list to jump to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The first row.
    Top,
    /// The last row.
    Bottom,
}

/// Which way to cycle through matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Towards the end of the list.
    Forward,
    /// Towards the start of the list.
    Backward,
}

/// The whole UI state.
pub struct App {
    /// Discovered projects and their graphs.
    pub projects: Vec<Project>,
    /// Whether the graphs are currently inverted.
    pub inverted: bool,
    /// Expanded row paths.
    expanded: HashSet<RowPath>,
    /// The flattened visible rows, rebuilt whenever the tree changes.
    rows: Vec<Row>,
    /// Index of the selected row within [`Self::rows`].
    selected: usize,
    /// First visible row, tracked so the selection stays on screen.
    pub offset: usize,
    /// The current search text.
    pub query: String,
    /// The compiled search, when the query is not blank.
    filter: Option<Filter>,
    /// What the user is doing.
    pub mode: Mode,
    /// Per-package lookups.
    pub packages: PackageStore,
    /// Whether the user asked to quit.
    pub quit: bool,
    /// A transient message shown in the status bar.
    pub message: Option<String>,
}

impl App {
    /// Build the state for a set of discovered projects.
    ///
    /// Every project starts expanded: a tree whose first interaction must be
    /// "open the only thing on screen" wastes the user's time.
    #[must_use]
    pub fn new(projects: Vec<Project>) -> Self {
        let expanded = (0..projects.len()).map(|i| vec![i]).collect();
        let mut app = Self {
            projects,
            inverted: false,
            expanded,
            rows: Vec::new(),
            selected: 0,
            offset: 0,
            query: String::new(),
            filter: None,
            mode: Mode::Browse,
            packages: PackageStore::new(),
            quit: false,
            message: None,
        };
        app.rebuild();
        app
    }

    /// The visible rows.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The index of the selected row.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// The selected row, if any row is visible.
    #[must_use]
    pub fn selected(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// The package the selection identifies, for a package row with a version.
    ///
    /// A project row, or a node whose version is unknown (a shallow graph), has
    /// nothing to look up.
    #[must_use]
    pub fn selected_key(&self) -> Option<PackageKey> {
        let row = self.selected()?;
        if row.kind != RowKind::Package || row.version.is_empty() {
            return None;
        }
        Some(key(self.ecosystem_of(row), &row.name, &row.version))
    }

    /// The ecosystem a row belongs to.
    #[must_use]
    pub fn ecosystem_of(&self, row: &Row) -> Ecosystem {
        self.projects[row.project].ecosystem
    }

    /// What is known about the selected package.
    #[must_use]
    pub fn selected_data(&self) -> Option<&PackageData> {
        self.packages.get(&self.selected_key()?)
    }

    /// Record the outcome of a lookup.
    pub fn set_data(&mut self, package: PackageKey, data: PackageData) {
        self.packages.insert(package, data);
    }

    /// Apply an action.
    pub fn apply(&mut self, action: Action) {
        self.message = None;
        match action {
            Action::Move(delta) => self.move_selection(delta),
            Action::JumpTo(End::Top) => self.select(0),
            Action::JumpTo(End::Bottom) => self.select(self.rows.len().saturating_sub(1)),
            Action::Expand => self.expand(),
            Action::Collapse => self.collapse(),
            Action::Toggle => self.toggle(),
            Action::BeginSearch => self.mode = Mode::Search,
            Action::SearchInput(c) => {
                self.query.push(c);
                self.refilter();
            }
            Action::SearchBackspace => {
                self.query.pop();
                self.refilter();
            }
            Action::CommitSearch => self.mode = Mode::Browse,
            Action::ClearSearch => {
                self.query.clear();
                self.mode = Mode::Browse;
                self.refilter();
            }
            Action::CycleMatch(direction) => self.cycle_match(direction),
            Action::ToggleInvert => self.invert(),
            Action::Refresh => self.refresh(),
            Action::ToggleHelp => {
                self.mode = if self.mode == Mode::Help {
                    Mode::Browse
                } else {
                    Mode::Help
                };
            }
            Action::Quit => self.quit = true,
        }
    }

    /// Move the selection, clamped to the list.
    fn move_selection(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() - 1;
        let target = self.selected.saturating_add_signed(delta).min(last);
        self.select(target);
    }

    fn select(&mut self, index: usize) {
        self.selected = index.min(self.rows.len().saturating_sub(1));
    }

    /// Open the selected row, or move into it when it is already open.
    fn expand(&mut self) {
        let Some(row) = self.rows.get(self.selected) else {
            return;
        };
        if row.cyclic {
            self.message = Some(format!(
                "{} already appears higher in this path (cycle)",
                row.name
            ));
            return;
        }
        if !row.has_children {
            return;
        }
        if row.expanded {
            self.move_selection(1);
            return;
        }
        let path = row.path.clone();
        self.expanded.insert(path);
        self.rebuild_keeping_selection();
    }

    /// Close the selected row, or move to its parent when it is already closed.
    fn collapse(&mut self) {
        let Some(row) = self.rows.get(self.selected) else {
            return;
        };
        if row.expanded {
            let path = row.path.clone();
            self.expanded.remove(&path);
            self.rebuild_keeping_selection();
            return;
        }
        if row.path.len() > 1 {
            let parent = row.path[..row.path.len() - 1].to_vec();
            self.rebuild();
            if let Some(index) = self.rows.iter().position(|r| r.path == parent) {
                self.selected = index;
            }
        }
    }

    fn toggle(&mut self) {
        let Some(row) = self.rows.get(self.selected) else {
            return;
        };
        if row.expanded {
            self.collapse();
        } else {
            self.expand();
        }
    }

    /// Recompile the query and rebuild, keeping the selection where possible.
    fn refilter(&mut self) {
        self.filter = Filter::new(&self.query);
        self.rebuild_keeping_selection();
    }

    /// Move to the next or previous matching row.
    fn cycle_match(&mut self, direction: Direction) {
        let matches: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.matched)
            .map(|(i, _)| i)
            .collect();
        if matches.is_empty() {
            self.message = Some("no matches".to_owned());
            return;
        }
        let next = match direction {
            Direction::Forward => matches
                .iter()
                .find(|&&i| i > self.selected)
                .or_else(|| matches.first()),
            Direction::Backward => matches
                .iter()
                .rev()
                .find(|&&i| i < self.selected)
                .or_else(|| matches.last()),
        };
        if let Some(&index) = next {
            self.selected = index;
        }
    }

    /// Flip every graph between "what this depends on" and "what depends on this".
    fn invert(&mut self) {
        for project in &mut self.projects {
            project.graph = project.graph.inverted();
        }
        self.inverted = !self.inverted;
        // Paths index into children lists that just changed meaning entirely.
        self.expanded = (0..self.projects.len()).map(|i| vec![i]).collect();
        self.selected = 0;
        self.rebuild();
        self.message = Some(if self.inverted {
            "showing what depends on each package".to_owned()
        } else {
            "showing what each package depends on".to_owned()
        });
    }

    /// Drop what is known about the selected package so it is fetched again.
    fn refresh(&mut self) {
        if let Some(package) = self.selected_key() {
            self.packages.remove(&package);
        }
    }

    fn rebuild(&mut self) {
        self.rows = visible(&self.projects, &self.expanded, self.filter.as_ref());
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
    }

    /// Rebuild while keeping the same row selected, where it still exists.
    fn rebuild_keeping_selection(&mut self) {
        let previous = self.selected().map(|r| r.path.clone());
        self.rebuild();
        if let Some(path) = previous
            && let Some(index) = self.rows.iter().position(|r| r.path == path)
        {
            self.selected = index;
        }
    }

    /// Keep the selection within a viewport `height` rows tall.
    pub fn scroll_into_view(&mut self, height: usize) {
        if height == 0 {
            return;
        }
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + height {
            self.offset = self.selected - height + 1;
        }
    }
}
