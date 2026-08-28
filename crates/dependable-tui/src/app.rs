//! The application state machine.
//!
//! Deliberately free of IO and of ratatui: every navigation, expansion, search and
//! loading transition is decided here, so all of it is unit-testable without a
//! terminal or a network. The event loop feeds it actions; the renderer reads it.

use std::collections::HashSet;

use dependable_fetch::{Ecosystem, NodeKind};

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
    /// Open the selected package's primary URL in a browser.
    OpenLink,
    /// Select the row at this index, as a click does.
    Select(usize),
    /// Select the row at this index and expand or collapse it.
    ToggleAt(usize),
    /// Start dragging the divider between the panes.
    BeginDrag,
    /// Stop dragging.
    EndDrag,
    /// Set the tree pane's share of the width, as a percentage.
    SetSplit(u16),
    /// The row the pointer is over, or `None` when it is over nothing.
    Hover(Option<usize>),
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
    /// The tree pane's share of the width, as a percentage.
    ///
    /// Held here rather than fixed in the layout so the divider between the
    /// panes can be dragged; clamped to [`App::SPLIT_RANGE`] so neither pane can
    /// be dragged away entirely.
    pub split: u16,
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
    /// The directory that was scanned, shown in the header.
    ///
    /// `None` in tests and before discovery reports back; the header simply
    /// omits it rather than inventing a path.
    pub root: Option<std::path::PathBuf>,
    /// The row the pointer is resting on.
    ///
    /// Distinct from the selection, and styled more weakly: it follows the
    /// pointer rather than the cursor, and must not be mistaken for what the
    /// keyboard would act on.
    pub hover: Option<usize>,
    /// When the pointer arrived on [`Self::hover`], for the marker's fade in.
    ///
    /// The one piece of wall-clock state here. It is a clock reading rather
    /// than IO, and keeping it beside the hover it describes is what lets the
    /// renderer stay a pure function of this type.
    hover_since: Option<std::time::Instant>,
    /// Whether the divider is being dragged.
    ///
    /// A drag has to be attributed to where it began: the pointer wanders well
    /// off the divider mid-drag, and a drag that started in the tree must not
    /// resize anything.
    pub dragging: bool,
    /// A URL the user asked to open, for the event loop to hand to the browser.
    ///
    /// Parked here rather than opened directly because this type is free of IO;
    /// the loop takes it with [`App::take_open_request`].
    open_request: Option<String>,
}

impl App {
    /// The tree pane's default share of the width.
    pub const DEFAULT_SPLIT: u16 = 55;
    /// How far the divider may be dragged, either way.
    pub const SPLIT_RANGE: std::ops::RangeInclusive<u16> = 20..=80;
    /// How long the hover marker takes to reach its colour.
    pub const HOVER_FADE: std::time::Duration = std::time::Duration::from_millis(150);

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
            split: Self::DEFAULT_SPLIT,
            query: String::new(),
            filter: None,
            mode: Mode::Browse,
            packages: PackageStore::new(),
            quit: false,
            message: None,
            root: None,
            hover: None,
            hover_since: None,
            dragging: false,
            open_request: None,
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

    /// The package the selection identifies, for a row a registry can answer about.
    ///
    /// Only [`NodeKind::Registry`] nodes qualify. A workspace member, a git
    /// dependency, or a path dependency did not come from the registry, and its
    /// name may well belong to an unrelated published package — looking it up
    /// would show someone else's description, license, and version history as if
    /// they were this package's. A project row, or a node whose version is unknown
    /// (a shallow graph), has nothing to look up either.
    #[must_use]
    pub fn selected_key(&self) -> Option<PackageKey> {
        let row = self.selected()?;
        if row.kind != RowKind::Package
            || row.version.is_empty()
            || row.node_kind != Some(NodeKind::Registry)
        {
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
            Action::OpenLink => match self.selected_url() {
                Some(url) => self.open_request = Some(url.to_owned()),
                // Saying so beats a key that silently does nothing.
                None => {
                    self.message = Some("no link published for this package".to_owned());
                }
            },
            Action::Select(index) => self.select(index),
            Action::ToggleAt(index) => {
                self.select(index);
                self.apply(Action::Toggle);
            }
            Action::Hover(row) => {
                let row = row.filter(|i| *i < self.rows.len());
                // Restarting the clock on an unchanged hover would hold the
                // marker at the start of its fade while the pointer moved
                // along a single row.
                if row != self.hover {
                    self.hover_since = row.is_some().then(std::time::Instant::now);
                    self.hover = row;
                }
            }
            Action::BeginDrag => self.dragging = true,
            Action::EndDrag => self.dragging = false,
            Action::SetSplit(percent) => {
                self.split = percent.clamp(*Self::SPLIT_RANGE.start(), *Self::SPLIT_RANGE.end());
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

    /// How many packages are known across every discovered project.
    ///
    /// Counts graph nodes, so a package pulled in by two projects counts once
    /// per project — which is what "how much is in front of me" means here.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.projects.iter().map(|p| p.graph.nodes().len()).sum()
    }

    /// How many looked-up packages carry at least one advisory.
    ///
    /// Only packages actually fetched can be counted, so this grows as the user
    /// browses. It is a floor, never a total, and the header says so.
    #[must_use]
    pub fn vulnerable_count(&self) -> usize {
        self.packages
            .values()
            .filter(|data| match data {
                PackageData::Ready(facts) => !facts.vulnerabilities.is_empty(),
                _ => false,
            })
            .count()
    }

    /// How far the hover fade has run, from 0.0 to 1.0.
    ///
    /// Returns 1.0 when nothing is hovered, so a caller that asks anyway gets
    /// the settled colour rather than a half-faded one.
    #[must_use]
    pub fn hover_progress(&self) -> f32 {
        let Some(since) = self.hover_since else {
            return 1.0;
        };
        let elapsed = since.elapsed().as_secs_f32();
        (elapsed / Self::HOVER_FADE.as_secs_f32()).clamp(0.0, 1.0)
    }

    /// Whether a fade is still running and the UI owes another frame.
    #[must_use]
    pub fn animating(&self) -> bool {
        self.hover_since.is_some() && self.hover_progress() < 1.0
    }

    /// The URL the selected package is best identified by.
    ///
    /// Ordered by how likely it is to be what the reader wants: the source
    /// repository first, then the project's own page, then its documentation.
    /// Returns `None` for a package with no lookup yet, or one the registry
    /// published no links for.
    #[must_use]
    pub fn selected_url(&self) -> Option<&str> {
        let PackageData::Ready(facts) = self.packages.get(&self.selected_key()?)? else {
            return None;
        };
        let meta = facts.metadata.as_ref()?;
        meta.repository
            .as_deref()
            .or(meta.homepage.as_deref())
            .or(meta.documentation.as_deref())
    }

    /// Take the URL the user asked to open, if any.
    pub fn take_open_request(&mut self) -> Option<String> {
        self.open_request.take()
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
