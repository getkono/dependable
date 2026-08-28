//! Flatten the expanded parts of the dependency forest into the visible rows.
//!
//! Only what is expanded is ever walked, so a workspace with a hundred thousand
//! resolved edges costs nothing until the user opens it.
//!
//! A package may legitimately appear in many places in a dependency graph, so a
//! row is identified by its **path** from the root rather than by its node index —
//! opening `serde` under `tokio` must not also open it under `clap`.

use std::collections::HashSet;

use dependable_fetch::NodeKind;

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
            let roots: Vec<usize> = project.graph.roots().to_vec();
            walk(
                project,
                index,
                &roots,
                &path,
                1,
                &mut HashSet::new(),
                expanded,
                found.as_ref(),
                &mut out,
            );
        }
    }
    out
}

/// Emit `children` and, for each expanded one, its own children.
#[allow(clippy::too_many_arguments)]
fn walk(
    project: &Project,
    project_index: usize,
    children: &[usize],
    parent: &RowPath,
    depth: usize,
    ancestors: &mut HashSet<usize>,
    expanded: &HashSet<RowPath>,
    found: Option<&Found>,
    out: &mut Vec<Row>,
) {
    for (slot, &node) in children.iter().enumerate() {
        let mut path = parent.clone();
        path.push(slot);
        if found.is_some_and(|f| !f.keep.contains(&path)) {
            continue;
        }
        let info = &project.graph.nodes()[node];
        // Expanding a node already on this path would recurse forever.
        let cyclic = ancestors.contains(&node);
        let deps = project.graph.deps_of(node);
        let has_children = !deps.is_empty() && !cyclic;
        let is_open = has_children
            && (expanded.contains(&path) || found.is_some_and(|f| f.open.contains(&path)));

        out.push(Row {
            depth,
            kind: RowKind::Package,
            project: project_index,
            node: Some(node),
            name: info.name.clone(),
            version: info.version.clone(),
            node_kind: Some(info.kind),
            has_children,
            expanded: is_open,
            cyclic,
            matched: found.is_some_and(|f| f.matched.contains(&path)),
            path: path.clone(),
        });

        if is_open {
            let deps: Vec<usize> = deps.to_vec();
            ancestors.insert(node);
            walk(
                project,
                project_index,
                &deps,
                &path,
                depth + 1,
                ancestors,
                expanded,
                found,
                out,
            );
            ancestors.remove(&node);
        }
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
