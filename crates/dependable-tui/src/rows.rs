//! Flatten the expanded parts of the dependency forest into the visible rows.
//!
//! Only what is expanded is ever walked, so a workspace with a hundred thousand
//! resolved edges costs nothing until the user opens it.
//!
//! A package may legitimately appear in many places in a dependency graph, so a
//! row is identified by its **path** from the root rather than by its node index —
//! opening `serde` under `tokio` must not also open it under `clap`.

use std::collections::HashSet;

use dependable_fetch::{NodeKind, Placement, Visit, Visitor, WalkOptions};

use crate::filter::Filter;
use crate::model::Project;

/// How deep the search behind a glob query will look for matches.
///
/// A resolved graph is effectively unbounded once cycles and repeats are counted;
/// this keeps typing in the search box responsive on a large workspace.
const MAX_SEARCH_DEPTH: usize = 12;

/// How many nodes a single search visits before giving up on finding more.
const SEARCH_BUDGET: usize = 200_000;

/// A row's position in the forest: the project index, then the index of each
/// child taken from there.
pub type RowPath = Vec<usize>;

/// What a row represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    /// A discovered project (a manifest).
    Project,
    /// A package within a project's graph.
    Package,
}

/// One visible line of the tree.
#[derive(Debug, Clone)]
pub struct Row {
    /// Where this row sits in the forest.
    pub path: RowPath,
    /// Indentation level; a project row is `0`.
    pub depth: usize,
    /// Whether this is a project or a package.
    pub kind: RowKind,
    /// Index into the projects list.
    pub project: usize,
    /// Index into the project's graph nodes; `None` for a project row.
    pub node: Option<usize>,
    /// Display name.
    pub name: String,
    /// Resolved version, empty when unknown.
    pub version: String,
    /// How the node relates to the workspace; `None` for a project row.
    pub node_kind: Option<NodeKind>,
    /// Whether the row has children to expand.
    pub has_children: bool,
    /// Whether it is currently expanded.
    pub expanded: bool,
    /// Whether expanding would revisit a package already on this path.
    pub cyclic: bool,
    /// Whether the row matched the active search.
    pub matched: bool,
}

/// Build the visible rows.
///
/// With a `filter`, the tree is opened along the paths that lead to matches and
/// everything else is hidden, so a match deep in the graph is reachable without
/// the user having expanded their way to it.
#[must_use]
pub fn visible(
    projects: &[Project],
    expanded: &HashSet<RowPath>,
    filter: Option<&Filter>,
) -> Vec<Row> {
    let found = filter.map(|f| search(projects, f));
    let mut out = Vec::new();
    for (index, project) in projects.iter().enumerate() {
        let path = vec![index];
        if found.as_ref().is_some_and(|f| !f.keep.contains(&path)) {
            continue;
        }
        let is_open =
            expanded.contains(&path) || found.as_ref().is_some_and(|f| f.open.contains(&path));
        out.push(Row {
            depth: 0,
            kind: RowKind::Project,
            project: index,
            node: None,
            name: project.label.clone(),
            version: String::new(),
            node_kind: None,
            has_children: !project.graph.roots().is_empty(),
            expanded: is_open,
            cyclic: false,
            matched: false,
            path: path.clone(),
        });
        if is_open {
            let is_expanded = |path: &[usize]| {
                expanded.contains(path) || found.as_ref().is_some_and(|f| f.open.contains(path))
            };
            let is_kept = |path: &[usize]| found.as_ref().is_none_or(|f| f.keep.contains(path));
            let opts = WalkOptions {
                // A package opened under `tokio` is not the one under `clap`, so
                // a second appearance is expanded on its own terms.
                dedupe: false,
                collapse_roots: false,
                prefix: &path,
                expand: Some(&is_expanded),
                include: Some(&is_kept),
                ..WalkOptions::default()
            };
            let mut builder = RowBuilder {
                project,
                project_index: index,
                found: found.as_ref(),
                out: &mut out,
            };
            project.graph.walk(&opts, &mut builder);
        }
    }
    out
}

/// Turns the shared walk into the flat rows the tree pane draws.
struct RowBuilder<'a> {
    project: &'a Project,
    project_index: usize,
    found: Option<&'a Found>,
    out: &'a mut Vec<Row>,
}

impl Visitor for RowBuilder<'_> {
    fn enter(&mut self, visit: &Visit<'_>) {
        let info = &self.project.graph.nodes()[visit.node];
        let expandable =
            visit.degree > 0 && matches!(visit.placement, Placement::Full | Placement::Collapsed);
        self.out.push(Row {
            // The walk counts a graph root as depth 0; the project row above it
            // is the tree's own 0.
            depth: visit.depth + 1,
            kind: RowKind::Package,
            project: self.project_index,
            node: Some(visit.node),
            name: info.name.clone(),
            version: info.version.clone(),
            node_kind: Some(info.kind),
            has_children: expandable,
            expanded: visit.placement == Placement::Full && visit.degree > 0,
            cyclic: visit.placement == Placement::Cycle,
            matched: self.found.is_some_and(|f| f.matched.contains(visit.path)),
            path: visit.path.to_vec(),
        });
    }
}

/// Paths a search turned up: the matches, the rows to keep visible, and the rows
/// to open so the matches are reachable.
struct Found {
    matched: HashSet<RowPath>,
    keep: HashSet<RowPath>,
    open: HashSet<RowPath>,
}

/// Find every path whose package name matches, within the search bounds.
fn search(projects: &[Project], filter: &Filter) -> Found {
    let mut found = Found {
        matched: HashSet::new(),
        keep: HashSet::new(),
        open: HashSet::new(),
    };
    let mut budget = SEARCH_BUDGET;
    for (index, project) in projects.iter().enumerate() {
        let path = vec![index];
        // A project whose own label matches is worth showing on its own.
        if filter.matches(&project.label) {
            found.matched.insert(path.clone());
            found.keep.insert(path.clone());
        }
        let roots: Vec<usize> = project.graph.roots().to_vec();
        descend(
            project,
            &roots,
            &path,
            0,
            &mut HashSet::new(),
            filter,
            &mut budget,
            &mut found,
        );
    }
    found
}

/// Depth-first search for matching names, recording the path to each.
#[allow(clippy::too_many_arguments)]
fn descend(
    project: &Project,
    children: &[usize],
    parent: &RowPath,
    depth: usize,
    ancestors: &mut HashSet<usize>,
    filter: &Filter,
    budget: &mut usize,
    found: &mut Found,
) {
    if depth >= MAX_SEARCH_DEPTH {
        return;
    }
    for (slot, &node) in children.iter().enumerate() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let mut path = parent.clone();
        path.push(slot);
        if filter.matches(&project.graph.nodes()[node].name) {
            found.matched.insert(path.clone());
            record(&path, found);
        }
        if ancestors.contains(&node) {
            continue;
        }
        let deps: Vec<usize> = project.graph.deps_of(node).to_vec();
        if deps.is_empty() {
            continue;
        }
        ancestors.insert(node);
        descend(
            project,
            &deps,
            &path,
            depth + 1,
            ancestors,
            filter,
            budget,
            found,
        );
        ancestors.remove(&node);
    }
}

/// Keep a match visible and open every ancestor leading to it.
fn record(path: &RowPath, found: &mut Found) {
    found.keep.insert(path.clone());
    for len in 1..path.len() {
        let prefix: RowPath = path[..len].to_vec();
        found.keep.insert(prefix.clone());
        found.open.insert(prefix);
    }
}
