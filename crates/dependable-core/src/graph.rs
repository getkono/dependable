//! A language-agnostic dependency graph plus one cycle-safe traversal of it.
//!
//! The graph itself knows nothing about Cargo — it is nodes (a package at a
//! version) and directed edges (`a` depends on `b`). Building one from a
//! `Cargo.lock` lives in [`DependencyGraph::from_resolved`]; other ecosystems
//! can grow their own constructor without touching the traversal here.
//!
//! [`DependencyGraph::walk`] is that traversal, and it is deliberately the only
//! one: the rendered `tree` and the interactive UI both drive it, so what counts
//! as a cycle, a repeat, or a crate already shown elsewhere cannot mean two
//! different things in the two places a user meets it. Rendering (color,
//! box-drawing, rows) is left to the caller — this module produces plain data.

use std::collections::{HashMap, HashSet};

use crate::lockfiles::ResolvedLockfile;

/// How a graph node relates to the workspace under analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeKind {
    /// A crate that lives in this workspace (a member).
    Workspace,
    /// A package resolved from a registry (crates.io / a sparse index).
    Registry,
    /// A git dependency.
    Git,
    /// A local path dependency that is *not* a workspace member.
    Path,
}

/// A single package in the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Node {
    /// Package name.
    pub name: String,
    /// Resolved version.
    pub version: String,
    /// Relationship to the workspace.
    pub kind: NodeKind,
}

/// A resolved dependency graph: nodes and directed edges (`a` depends on `b`),
/// plus the roots to render from.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DependencyGraph {
    nodes: Vec<Node>,
    /// `edges[i]` = indices of the nodes that node `i` directly depends on.
    edges: Vec<Vec<usize>>,
    /// Indices of the root nodes a tree is rendered from.
    roots: Vec<usize>,
    /// Reverse of [`Self::roots`]: node index to its position within it.
    ///
    /// Held rather than searched because a traversal asks "is this node one of
    /// the roots?" once per node it reaches, and a workspace may have hundreds
    /// of members.
    root_slots: HashMap<usize, usize>,
}

/// Options controlling how a [`Tree`] is expanded from a [`DependencyGraph`].
#[derive(Debug, Clone, Copy)]
pub struct TreeOptions {
    /// Maximum edge depth. `Some(0)` = roots only; `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Collapse a package's second and later appearances to a `(*)` marker.
    pub dedupe: bool,
    /// Collapse a crate that has a tree of its own in this forest to a pointer
    /// at that tree, rather than repeating its subtree wherever it is reached.
    pub collapse_roots: bool,
}

impl Default for TreeOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            dedupe: true,
            collapse_roots: true,
        }
    }
}

/// Why an appearance of a node does or does not show its dependencies below it.
///
/// Every reason a walk stops is named, rather than collapsed into one flag,
/// because they are different things to tell a reader: a repeat is shown in
/// full elsewhere, a cycle is shown higher on this same path, and a root has a
/// tree of its own in the forest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Placement {
    /// Shown in full; its dependencies, if any, follow it.
    Full,
    /// Already expanded elsewhere in this walk, collapsed by
    /// [`WalkOptions::dedupe`]. Its dependencies are at its first appearance.
    Repeat,
    /// Already on the path from the root to here. Expanding it would not
    /// terminate, so the back-edge is cut — always, whatever the options say.
    Cycle,
    /// One of the forest's own roots, reached below the top level. Its subtree
    /// is shown at its own root entry, so this appearance points there.
    Root {
        /// Index into [`DependencyGraph::roots`] of the entry it points at.
        root: usize,
    },
    /// [`WalkOptions::max_depth`] stopped the walk here. Whether anything lies
    /// below is unknown from this appearance alone.
    Depth,
    /// [`WalkOptions::expand`] declined to open it — a closed row in an
    /// interactive tree. Never produced when no predicate is given.
    Collapsed,
}

/// One node, as a walk reaches it.
///
/// Handed to a [`Visitor`] by reference and valid only for that call: `path`
/// borrows the walk's own buffer, which is rewritten as the walk moves on.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Visit<'a> {
    /// Where this appearance sits: [`WalkOptions::prefix`], then the index of
    /// each *slot* taken from there — the position within the parent's
    /// dependency list, which is stable whatever the walk chooses to expand.
    pub path: &'a [usize],
    /// Edge depth below the forest's roots; a root is `0`.
    pub depth: usize,
    /// Index into [`DependencyGraph::nodes`].
    pub node: usize,
    /// Whether this appearance is expanded, and if not, why not.
    pub placement: Placement,
    /// How many direct dependencies the node has *in the graph*, whether or not
    /// this appearance shows them.
    pub degree: usize,
}

/// Receives each node a walk reaches.
///
/// [`Self::enter`] and [`Self::leave`] are called in matched pairs around every
/// node the walk emits, so an implementor can build a nested structure without
/// tracking depth itself. `leave` is called even for a node not descended into.
pub trait Visitor {
    /// Called on arriving at a node, before any of its dependencies.
    fn enter(&mut self, visit: &Visit<'_>);

    /// Called after the node's dependencies, if any were walked.
    fn leave(&mut self, node: usize) {
        let _ = node;
    }
}

/// A question a walk asks about the node at a given [`Visit::path`].
pub type PathPredicate<'a> = &'a dyn Fn(&[usize]) -> bool;

/// How a walk decides what to expand.
///
/// The defaults are what an offline `tree` render wants, so a caller states
/// only its differences and leaves the rest to `..WalkOptions::default()`.
pub struct WalkOptions<'a> {
    /// Maximum edge depth. `Some(0)` = roots only; `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Collapse a node's second and later appearances to [`Placement::Repeat`].
    pub dedupe: bool,
    /// Collapse a node that is one of the forest's own roots, reached below the
    /// top level, to [`Placement::Root`] instead of expanding a second copy.
    pub collapse_roots: bool,
    /// Prepended to every [`Visit::path`], for a caller whose paths are rooted
    /// above this graph.
    pub prefix: &'a [usize],
    /// Whether the node at this path should be expanded. `None` = always.
    ///
    /// Consulted last, so a repeat, a cycle, or a root is never expanded even
    /// when this says yes.
    pub expand: Option<PathPredicate<'a>>,
    /// Whether the node at this path should be emitted at all. `None` = always.
    ///
    /// A node this rejects is skipped along with its whole subtree, but its
    /// siblings keep their slot indices.
    pub include: Option<PathPredicate<'a>>,
    /// Maximum number of node appearances to emit before the walk stops. `None` =
    /// unlimited, which is only safe when the caller bounds the walk some other way.
    ///
    /// The walk enumerates *paths*, not nodes. With [`dedupe`](Self::dedupe) on, each
    /// node expands at most once and the count is bounded by the graph; with it off,
    /// a dependency graph shaped like a ladder has a number of distinct simple paths
    /// exponential in its size, and a real lockfile does not finish. The budget is what
    /// makes an unbounded walk terminate rather than appear to hang.
    pub max_visits: Option<usize>,
}

/// Default appearance budget for one walk — far above any real dependency forest, and
/// far below the point at which an exponential walk stops looking like a hang.
///
/// # Where the number comes from
/// The two bounds it has to sit between. Above: the largest lockfiles in the wild run
/// to a few tens of thousands of packages, and a deduped walk emits one appearance per
/// edge, so a forest an order of magnitude past the worst real case still finishes
/// whole — no honest tree is ever cut by this. Below: an appearance is a few pointer
/// derefs and a `Vec` push, so a million of them is well under a second, which keeps a
/// walk that *is* exponential looking like a bounded operation rather than a hang.
/// A user cannot override it: raising it only buys a longer wait before the same
/// prefix, and the prefix is reported as one ([`Tree::truncated`]).
pub const DEFAULT_MAX_VISITS: usize = 1_000_000;

/// Hard recursion ceiling, independent of [`WalkOptions::max_depth`].
///
/// The walk is recursive, so depth costs stack. No real dependency chain approaches
/// this; a cyclic graph cannot reach it (back-edges are cut), but a synthesized or
/// corrupt lockfile can, and overflowing the stack aborts the process.
///
/// # Where the number comes from
/// A stack budget, not a graph property. One frame here carries the node index, the
/// child iterator, and the path bookkeeping — on the order of a hundred bytes — so 512
/// frames is tens of kilobytes, comfortably inside the smallest stack this walk runs
/// on (a non-main thread's default, which is where a checker's tasks execute). Real
/// dependency chains are an order of magnitude shorter: the deepest transitive chains
/// observed in published lockfiles are in the low tens. Overrunning the ceiling is
/// therefore evidence of a corrupt or synthesized lockfile, and the walk reports the
/// prefix ([`Tree::truncated`]) rather than aborting the process. Not user-tunable,
/// because raising it trades a reported prefix for a stack overflow.
pub const MAX_WALK_DEPTH: usize = 512;

/// What one [`DependencyGraph::walk`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WalkStats {
    /// Node appearances emitted.
    pub visits: usize,
    /// Whether the walk stopped early on [`WalkOptions::max_visits`] or
    /// [`MAX_WALK_DEPTH`], so the result is a prefix of the forest rather than all of it.
    pub truncated: bool,
}

impl Default for WalkOptions<'_> {
    fn default() -> Self {
        Self {
            max_depth: None,
            dedupe: true,
            collapse_roots: true,
            prefix: &[],
            expand: None,
            include: None,
            max_visits: Some(DEFAULT_MAX_VISITS),
        }
    }
}

/// A rendered dependency tree (a forest, one entry per root).
#[derive(Debug, Clone)]
pub struct Tree {
    /// The root nodes, each with their expanded subtree.
    pub roots: Vec<TreeNode>,
    /// Whether the walk stopped on its appearance budget or depth ceiling, so this is a
    /// prefix of the forest rather than all of it.
    ///
    /// A truncated tree that does not say so is a wrong answer wearing a complete one's
    /// clothes; a renderer is expected to tell the reader.
    pub truncated: bool,
}

/// One node in a [`Tree`], referencing a graph node by index.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Index into [`DependencyGraph::nodes`].
    pub node: usize,
    /// Expanded children. Empty for a leaf and for every collapsed appearance —
    /// see [`Self::placement`] for which.
    pub children: Vec<TreeNode>,
    /// Whether this appearance is expanded, and if not, why not.
    pub placement: Placement,
}

impl TreeNode {
    /// Whether this appearance was collapsed to the `(*)` repeat marker: a
    /// dedupe repeat, or a cycle back-edge.
    ///
    /// A crate shown at its own root entry is deliberately *not* one of these:
    /// it is a pointer to another tree, not a copy suppressed within this one.
    #[must_use]
    pub fn deduped(&self) -> bool {
        matches!(self.placement, Placement::Repeat | Placement::Cycle)
    }
}

impl DependencyGraph {
    /// Assemble a graph from a parsed `Cargo.lock`.
    ///
    /// Each package is classified via `workspace_names` (member set) and its
    /// lockfile `source`. `roots` names the crates to render from (typically the
    /// workspace members, or a single `-p` crate); if none are found, every
    /// workspace node becomes a root.
    #[must_use]
    pub fn from_resolved(
        resolved: &ResolvedLockfile,
        workspace_names: &HashSet<String>,
        roots: &[String],
    ) -> Self {
        let nodes: Vec<Node> = resolved
            .packages
            .iter()
            .map(|p| Node {
                name: p.name.clone(),
                version: p.version.clone(),
                kind: classify(&p.name, p.source.as_deref(), workspace_names),
            })
            .collect();

        let edges: Vec<Vec<usize>> = resolved
            .packages
            .iter()
            .map(|p| {
                let mut seen = HashSet::new();
                p.dependencies
                    .iter()
                    .filter_map(|d| resolved.resolve(d))
                    .filter(|i| seen.insert(*i))
                    .collect()
            })
            .collect();

        let mut root_indices: Vec<usize> = roots
            .iter()
            .flat_map(|name| {
                let matching: Vec<usize> = nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| &n.name == name)
                    .map(|(i, _)| i)
                    .collect();
                // A name can match both a member and a registry crate that happens
                // to share it. The member is the one meant by "render this crate";
                // a name that matches no member (a `-p` on a dependency) keeps
                // every match, so asking for a crate resolved at two versions
                // still renders both.
                let members: Vec<usize> = matching
                    .iter()
                    .copied()
                    .filter(|&i| nodes[i].kind == NodeKind::Workspace)
                    .collect();
                if members.is_empty() {
                    matching
                } else {
                    members
                }
            })
            .collect();
        if root_indices.is_empty() {
            root_indices = nodes
                .iter()
                .enumerate()
                .filter(|(_, n)| n.kind == NodeKind::Workspace)
                .map(|(i, _)| i)
                .collect();
        }

        Self {
            root_slots: index_roots(&root_indices),
            nodes,
            edges,
            roots: root_indices,
        }
    }

    /// The graph's nodes, indexed by the values stored in [`TreeNode::node`].
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The direct dependencies of node `idx`, or an empty slice if `idx` is not a node
    /// in this graph.
    ///
    /// Indexing directly would panic, and this is public API on a library whose stated
    /// audience is other tools holding indices they got from somewhere else.
    #[must_use]
    pub fn deps_of(&self, idx: usize) -> &[usize] {
        self.edges.get(idx).map_or(&[], Vec::as_slice)
    }

    /// The root node indices.
    #[must_use]
    pub fn roots(&self) -> &[usize] {
        &self.roots
    }

    /// The position of `node` within [`Self::roots`], if it is one of them.
    ///
    /// Answers "does this crate have a tree of its own in this forest?" — which
    /// is what lets a traversal point at that tree instead of copying it.
    #[must_use]
    pub fn root_slot(&self, node: usize) -> Option<usize> {
        self.root_slots.get(&node).copied()
    }

    /// Reverse every edge, keeping the same nodes and roots. Rooting the result
    /// at a crate and walking it answers "what depends on this crate" — the
    /// downstream-impact (`--invert`) view.
    #[must_use]
    pub fn inverted(&self) -> Self {
        let mut edges = vec![Vec::new(); self.nodes.len()];
        for (from, deps) in self.edges.iter().enumerate() {
            for &to in deps {
                edges[to].push(from);
            }
        }
        Self {
            nodes: self.nodes.clone(),
            edges,
            roots: self.roots.clone(),
            root_slots: self.root_slots.clone(),
        }
    }

    /// Expand the graph into a [`Tree`] from its roots.
    ///
    /// A thin assembly over [`Self::walk`], which owns every rule about what is
    /// expanded where.
    #[must_use]
    pub fn tree(&self, opts: &TreeOptions) -> Tree {
        let walk = WalkOptions {
            max_depth: opts.max_depth,
            dedupe: opts.dedupe,
            collapse_roots: opts.collapse_roots,
            ..WalkOptions::default()
        };
        let mut builder = TreeBuilder::default();
        let stats = self.walk(&walk, &mut builder);
        Tree {
            roots: builder.roots,
            truncated: stats.truncated,
        }
    }

    /// Walk the forest depth-first, reporting every node reached to `visitor`.
    ///
    /// The single traversal behind both the rendered `tree` and the interactive
    /// UI: the rules for cycles, repeats, roots and the depth limit live here
    /// once, so the two cannot drift apart. Cycles (legal in Cargo via
    /// dev-dependencies) always terminate the walk, whatever the options say.
    ///
    /// Only subtrees that [`WalkOptions::expand`] admits are descended into, so
    /// a caller showing a mostly-closed tree pays for what it shows rather than
    /// for what the graph holds.
    pub fn walk(&self, opts: &WalkOptions<'_>, visitor: &mut dyn Visitor) -> WalkStats {
        let mut walker = Walker {
            graph: self,
            opts,
            path: opts.prefix.to_vec(),
            expanded: HashSet::new(),
            on_path: HashSet::new(),
            budget: opts.max_visits.unwrap_or(usize::MAX),
            stats: WalkStats::default(),
        };
        for (slot, &root) in self.roots.iter().enumerate() {
            walker.path.push(slot);
            walker.visit(root, 0, visitor);
            walker.path.pop();
        }
        walker.stats
    }
}

/// The state one [`DependencyGraph::walk`] carries down the forest.
struct Walker<'a> {
    graph: &'a DependencyGraph,
    opts: &'a WalkOptions<'a>,
    /// The path to the node currently being visited.
    path: Vec<usize>,
    /// Nodes already expanded anywhere in this walk, for `dedupe`.
    expanded: HashSet<usize>,
    /// Nodes on the path from a root to here, for cutting cycles.
    on_path: HashSet<usize>,
    /// Appearances still allowed before the walk stops.
    budget: usize,
    stats: WalkStats,
}

impl Walker<'_> {
    fn visit(&mut self, node: usize, depth: usize, visitor: &mut dyn Visitor) {
        // Both guards sit above `visitor.enter` so that a stopped walk never leaves an
        // `enter` without its `leave` — the builder's stack discipline depends on it.
        if self.budget == 0 || depth >= MAX_WALK_DEPTH {
            self.stats.truncated = true;
            return;
        }
        if let Some(include) = self.opts.include
            && !include(&self.path)
        {
            return;
        }
        self.budget -= 1;
        self.stats.visits += 1;
        // Copied out of `self` so the child list stays borrowed from the graph
        // rather than from the walker, which the recursion below borrows anew.
        let deps: &[usize] = &self.graph.edges[node];
        let degree = deps.len();
        let placement = self.placement(node, depth, degree);
        visitor.enter(&Visit {
            path: &self.path,
            depth,
            node,
            placement,
            degree,
        });
        if placement == Placement::Full {
            // Only a full appearance counts as seen: a depth-truncated one must
            // stay expandable from a shallower path elsewhere. A crate with a
            // tree of its own does not count either, or the leaf drawn here
            // would collapse its own entry to `(*)` — the very bug the pointer
            // exists to fix.
            let has_own_entry =
                self.opts.collapse_roots && depth > 0 && self.graph.root_slot(node).is_some();
            if self.opts.dedupe && !has_own_entry {
                self.expanded.insert(node);
            }
            if degree > 0 {
                self.on_path.insert(node);
                for (slot, &child) in deps.iter().enumerate() {
                    self.path.push(slot);
                    self.visit(child, depth + 1, visitor);
                    self.path.pop();
                }
                self.on_path.remove(&node);
            }
        }
        visitor.leave(node);
    }

    /// Decide how this appearance of `node` is shown.
    ///
    /// The order is the whole contract. A cycle is cut first, so a back-edge to
    /// a crate the reader is already standing inside is reported as the cycle it
    /// is rather than sent somewhere else. A root is recognised before a repeat,
    /// so a crate reached after its own entry still points at that entry instead
    /// of degrading to `(*)` — but only when it has dependencies to show, since
    /// a pointer at an empty tree helps nobody. The depth limit comes next and, as ever,
    /// does not mark the node seen — a shallower path elsewhere may still
    /// expand it.
    fn placement(&self, node: usize, depth: usize, degree: usize) -> Placement {
        if self.on_path.contains(&node) {
            return Placement::Cycle;
        }
        // Only worth pointing at a tree that has something in it: a member with
        // no dependencies of its own reads as the leaf it is, and sending the
        // reader to an empty entry would be worse than drawing it twice.
        if self.opts.collapse_roots
            && depth > 0
            && degree > 0
            && let Some(root) = self.graph.root_slot(node)
        {
            return Placement::Root { root };
        }
        if self.opts.dedupe && self.expanded.contains(&node) {
            return Placement::Repeat;
        }
        if self.opts.max_depth.is_some_and(|max| depth >= max) {
            return Placement::Depth;
        }
        if degree > 0
            && let Some(expand) = self.opts.expand
            && !expand(&self.path)
        {
            return Placement::Collapsed;
        }
        Placement::Full
    }
}

/// Assembles a [`Tree`] from a walk, using the matched `enter`/`leave` pairs to
/// rebuild the nesting without tracking depth.
#[derive(Default)]
struct TreeBuilder {
    /// One frame per node currently open; the last is the node being filled.
    stack: Vec<TreeNode>,
    /// Completed root trees, in walk order.
    roots: Vec<TreeNode>,
}

impl Visitor for TreeBuilder {
    fn enter(&mut self, visit: &Visit<'_>) {
        self.stack.push(TreeNode {
            node: visit.node,
            children: Vec::new(),
            placement: visit.placement,
        });
    }

    fn leave(&mut self, _node: usize) {
        let done = self.stack.pop().expect("leave is paired with enter");
        match self.stack.last_mut() {
            Some(parent) => parent.children.push(done),
            None => self.roots.push(done),
        }
    }
}

/// Index root node indices by their position, for [`DependencyGraph::root_slot`].
///
/// A node listed twice keeps its first position, so the slot always names the
/// entry a reader would actually find.
fn index_roots(roots: &[usize]) -> HashMap<usize, usize> {
    let mut out = HashMap::with_capacity(roots.len());
    for (slot, &node) in roots.iter().enumerate() {
        out.entry(node).or_insert(slot);
    }
    out
}

/// Classify a package by its lockfile source, then workspace membership.
///
/// Source is tested first because a member's name is not exclusive to it: a
/// crate published to a registry may share the name of a crate in this
/// workspace, and Cargo records both as separate packages. Only the one with no
/// `source` is the member — which is the rule `docs/SCOPE.md` already states.
fn classify(name: &str, source: Option<&str>, workspace_names: &HashSet<String>) -> NodeKind {
    match source {
        None if workspace_names.contains(name) => NodeKind::Workspace,
        None => NodeKind::Path,
        Some(s) if s.starts_with("git+") => NodeKind::Git,
        Some(_) => NodeKind::Registry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfiles::parse_cargo_lock_graph;

    fn names(set: &[&str]) -> HashSet<String> {
        set.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Depth-first flatten of a tree into `(name, version, deduped)` tuples.
    fn flatten<'a>(g: &'a DependencyGraph, t: &Tree) -> Vec<(&'a str, &'a str, bool)> {
        fn walk<'a>(g: &'a DependencyGraph, n: &TreeNode, out: &mut Vec<(&'a str, &'a str, bool)>) {
            let node = &g.nodes()[n.node];
            out.push((&node.name, &node.version, n.deduped()));
            for c in &n.children {
                walk(g, c, out);
            }
        }
        let mut out = Vec::new();
        for r in &t.roots {
            walk(g, r, &mut out);
        }
        out
    }

    #[test]
    fn classifies_workspace_registry_git_and_path() {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["lib", "serde", "gitdep", "localdep"]

[[package]]
name = "lib"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://example.com/g#abc"

[[package]]
name = "localdep"
version = "0.1.0"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["app", "lib"]), &["app".into()]);
        let kind = |name: &str| g.nodes().iter().find(|n| n.name == name).unwrap().kind;
        assert_eq!(kind("app"), NodeKind::Workspace);
        assert_eq!(kind("lib"), NodeKind::Workspace);
        assert_eq!(kind("serde"), NodeKind::Registry);
        assert_eq!(kind("gitdep"), NodeKind::Git);
        assert_eq!(kind("localdep"), NodeKind::Path); // no source, not a member
    }

    #[test]
    fn a_registry_crate_sharing_a_member_name_is_not_a_member() {
        // `b` is a workspace member, and a *different* crate published to
        // crates.io also happens to be called `b`. Cargo locks both.
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b 9.0.0"]

[[package]]
name = "b"
version = "0.1.0"

[[package]]
name = "b"
version = "9.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["a", "b"]), &["a".into()]);
        let kind_at = |version: &str| {
            g.nodes()
                .iter()
                .find(|n| n.name == "b" && n.version == version)
                .unwrap()
                .kind
        };
        assert_eq!(kind_at("0.1.0"), NodeKind::Workspace, "the member");
        assert_eq!(kind_at("9.0.0"), NodeKind::Registry, "the namesake");
    }

    #[test]
    fn a_member_namesake_from_the_registry_is_not_a_root() {
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b 9.0.0"]

[[package]]
name = "b"
version = "0.1.0"

[[package]]
name = "b"
version = "9.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(
            &resolved,
            &names(&["a", "b"]),
            &["a".into(), "b".into()],
        );
        let roots: Vec<(&str, &str)> = g
            .roots()
            .iter()
            .map(|&i| (g.nodes()[i].name.as_str(), g.nodes()[i].version.as_str()))
            .collect();
        assert_eq!(
            roots,
            vec![("a", "0.1.0"), ("b", "0.1.0")],
            "asking for member `b` must not also root its registry namesake"
        );
        assert_eq!(g.root_slot(g.roots()[1]), Some(1));
    }

    #[test]
    fn a_root_name_matching_no_member_keeps_every_version() {
        // `-p dep` on a crate resolved at two versions still shows both.
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dep 1.0.0", "dep 2.0.0"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://x"

[[package]]
name = "dep"
version = "2.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["app"]), &["dep".into()]);
        assert_eq!(g.roots().len(), 2);
    }

    #[test]
    fn forward_tree_has_expected_shape() {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["lib"]

[[package]]
name = "lib"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["app", "lib"]), &["app".into()]);
        let tree = g.tree(&TreeOptions::default());
        assert_eq!(
            flatten(&g, &tree),
            vec![
                ("app", "0.1.0", false),
                ("lib", "0.1.0", false),
                ("serde", "1.0.0", false),
            ]
        );
    }

    #[test]
    fn diamond_dedupes_second_appearance() {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["b", "c"]

[[package]]
name = "b"
version = "0.1.0"
source = "registry+https://x"
dependencies = ["d"]

[[package]]
name = "c"
version = "0.1.0"
source = "registry+https://x"
dependencies = ["d"]

[[package]]
name = "d"
version = "0.1.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["app"]), &["app".into()]);
        let flat = flatten(&g, &g.tree(&TreeOptions::default()));
        // d expanded once (under b), deduped once (under c).
        let d_full = flat.iter().filter(|(n, _, ded)| *n == "d" && !ded).count();
        let d_dedup = flat.iter().filter(|(n, _, ded)| *n == "d" && *ded).count();
        assert_eq!(d_full, 1);
        assert_eq!(d_dedup, 1);

        // With dedupe off, d appears in full under both b and c.
        let no_dedupe = TreeOptions {
            max_depth: None,
            dedupe: false,
            ..TreeOptions::default()
        };
        let flat2 = flatten(&g, &g.tree(&no_dedupe));
        assert_eq!(
            flat2.iter().filter(|(n, _, ded)| *n == "d" && !ded).count(),
            2
        );
    }

    /// Find the first appearance of `name` at a non-root position.
    fn under_root<'a>(g: &DependencyGraph, t: &'a Tree, root: &str, name: &str) -> &'a TreeNode {
        let entry = t
            .roots
            .iter()
            .find(|r| g.nodes()[r.node].name == root)
            .expect("root entry");
        entry
            .children
            .iter()
            .find(|c| g.nodes()[c.node].name == name)
            .expect("child")
    }

    #[test]
    fn a_member_reached_under_another_member_points_at_its_own_root() {
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b"]

[[package]]
name = "b"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(
            &resolved,
            &names(&["a", "b"]),
            &["a".into(), "b".into()],
        );
        let tree = g.tree(&TreeOptions::default());

        let b_under_a = under_root(&g, &tree, "a", "b");
        assert_eq!(
            b_under_a.placement,
            Placement::Root { root: 1 },
            "`b` has a tree of its own, so here it is a pointer at it"
        );
        assert!(b_under_a.children.is_empty(), "and carries no copy of it");
        assert!(
            !b_under_a.deduped(),
            "a pointer is not the `(*)` repeat marker"
        );

        // The entry it points at is the one that expands — which is what the
        // first-seen-wins walk used to get backwards.
        let b_root = &tree.roots[1];
        assert_eq!(g.nodes()[b_root.node].name, "b");
        assert_eq!(b_root.placement, Placement::Full);
        assert_eq!(
            flatten(
                &g,
                &Tree {
                    roots: vec![b_root.clone()],
                    truncated: false,
                }
            ),
            vec![("b", "0.1.0", false), ("serde", "1.0.0", false)],
        );
    }

    #[test]
    fn a_member_with_no_dependencies_is_a_leaf_not_a_pointer() {
        // `b` has nothing under it, so pointing at its entry would send the
        // reader somewhere empty. It reads as the leaf it is.
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b"]

[[package]]
name = "b"
version = "0.1.0"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(
            &resolved,
            &names(&["a", "b"]),
            &["a".into(), "b".into()],
        );
        let tree = g.tree(&TreeOptions::default());

        assert_eq!(under_root(&g, &tree, "a", "b").placement, Placement::Full);
        // And drawing it there must not collapse its own entry to `(*)`.
        assert_eq!(
            tree.roots[1].placement,
            Placement::Full,
            "`b`'s own entry stays the place it is shown"
        );
        assert!(!tree.roots[1].deduped());
    }

    #[test]
    fn a_registry_namesake_of_a_member_still_expands_in_place() {
        // `a` depends on a crates.io crate that happens to share member `b`'s
        // name. It is a different package, so it is not a pointer anywhere.
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b 9.0.0"]

[[package]]
name = "b"
version = "0.1.0"

[[package]]
name = "b"
version = "9.0.0"
source = "registry+https://x"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(
            &resolved,
            &names(&["a", "b"]),
            &["a".into(), "b".into()],
        );
        let tree = g.tree(&TreeOptions::default());

        let namesake = under_root(&g, &tree, "a", "b");
        assert_eq!(g.nodes()[namesake.node].version, "9.0.0");
        assert_eq!(
            namesake.placement,
            Placement::Full,
            "the registry crate is not the member, so it expands where it is used"
        );
        assert_eq!(g.nodes()[namesake.children[0].node].name, "serde");
    }

    #[test]
    fn disabling_root_collapse_restores_expansion_in_place() {
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b"]

[[package]]
name = "b"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(
            &resolved,
            &names(&["a", "b"]),
            &["a".into(), "b".into()],
        );
        let opts = TreeOptions {
            dedupe: false,
            collapse_roots: false,
            ..TreeOptions::default()
        };
        let flat = flatten(&g, &g.tree(&opts));
        assert_eq!(
            flat.iter().filter(|(n, _, _)| *n == "serde").count(),
            2,
            "with both collapses off, `b`'s subtree is drawn under `a` and again at its own root"
        );
    }

    #[test]
    fn cycle_terminates() {
        // a -> b -> a  (legal via dev-dependencies)
        let lock = r#"
[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b"]

[[package]]
name = "b"
version = "0.1.0"
dependencies = ["a"]
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["a", "b"]), &["a".into()]);
        // Must not hang; even with dedupe off the back-edge is cut.
        let flat = flatten(
            &g,
            &g.tree(&TreeOptions {
                max_depth: None,
                dedupe: false,
                ..TreeOptions::default()
            }),
        );
        assert_eq!(
            flat,
            vec![
                ("a", "0.1.0", false),
                ("b", "0.1.0", false),
                ("a", "0.1.0", true), // back-edge, cut
            ]
        );
    }

    #[test]
    fn duplicate_versions_are_distinct_nodes() {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dep 1.0.0", "dep 2.0.0"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://x"

[[package]]
name = "dep"
version = "2.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["app"]), &["app".into()]);
        let flat = flatten(&g, &g.tree(&TreeOptions::default()));
        assert!(flat.contains(&("dep", "1.0.0", false)));
        assert!(flat.contains(&("dep", "2.0.0", false)));
    }

    #[test]
    fn depth_limit_controls_expansion() {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["lib"]

[[package]]
name = "lib"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g = DependencyGraph::from_resolved(&resolved, &names(&["app", "lib"]), &["app".into()]);
        let roots_only = g.tree(&TreeOptions {
            max_depth: Some(0),
            dedupe: true,
            ..TreeOptions::default()
        });
        assert_eq!(flatten(&g, &roots_only), vec![("app", "0.1.0", false)]);

        let one_deep = g.tree(&TreeOptions {
            max_depth: Some(1),
            dedupe: true,
            ..TreeOptions::default()
        });
        assert_eq!(
            flatten(&g, &one_deep),
            vec![("app", "0.1.0", false), ("lib", "0.1.0", false)]
        );
    }

    #[test]
    fn inverted_shows_dependents() {
        // app -> lib -> serde ; invert rooted at serde reaches lib then app.
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["lib"]

[[package]]
name = "lib"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let g =
            DependencyGraph::from_resolved(&resolved, &names(&["app", "lib"]), &["serde".into()]);
        let inv = g.inverted();
        let flat = flatten(&inv, &inv.tree(&TreeOptions::default()));
        assert_eq!(
            flat,
            vec![
                ("serde", "1.0.0", false),
                ("lib", "0.1.0", false),
                ("app", "0.1.0", false),
            ]
        );
    }

    /// The walk recurses, so depth costs stack. A chain longer than the ceiling is
    /// truncated rather than allowed to overflow and abort the process.
    #[test]
    fn a_very_deep_chain_terminates_and_says_it_was_truncated() {
        let depth = MAX_WALK_DEPTH + 50;
        let mut nodes = Vec::new();
        let mut edges: Vec<Vec<usize>> = Vec::new();
        for n in 0..depth {
            nodes.push(Node {
                name: format!("c{n}"),
                version: "1.0.0".to_string(),
                kind: NodeKind::Registry,
            });
            edges.push(if n + 1 < depth { vec![n + 1] } else { vec![] });
        }
        let g = DependencyGraph {
            root_slots: std::iter::once((0, 0)).collect(),
            nodes,
            edges,
            roots: vec![0],
        };
        let tree = g.tree(&TreeOptions::default());
        assert!(
            tree.truncated,
            "a chain past the ceiling must report truncation"
        );
    }

    /// With `dedupe` off the walk enumerates simple paths, and a ladder-shaped graph has
    /// exponentially many. This used to run until it was killed.
    #[test]
    fn an_exponential_walk_is_bounded_by_its_budget() {
        // 40 layers of two nodes each: 2^40 distinct root-to-leaf paths.
        let layers = 40usize;
        let mut nodes = Vec::new();
        let mut edges: Vec<Vec<usize>> = Vec::new();
        for layer in 0..layers {
            for side in 0..2 {
                nodes.push(Node {
                    name: format!("n{layer}_{side}"),
                    version: "1.0.0".to_string(),
                    kind: NodeKind::Registry,
                });
                let next = (layer + 1) * 2;
                edges.push(if layer + 1 < layers {
                    vec![next, next + 1]
                } else {
                    vec![]
                });
            }
        }
        let g = DependencyGraph {
            root_slots: std::iter::once((0, 0)).collect(),
            nodes,
            edges,
            roots: vec![0],
        };
        let opts = WalkOptions {
            dedupe: false,
            collapse_roots: false,
            max_visits: Some(10_000),
            ..WalkOptions::default()
        };
        let mut builder = TreeBuilder::default();
        let stats = g.walk(&opts, &mut builder);
        assert!(stats.truncated);
        assert!(
            stats.visits <= 10_000,
            "emitted {} appearances",
            stats.visits
        );
    }

    /// A node index from outside this graph must not panic the library.
    #[test]
    fn deps_of_an_unknown_index_is_empty() {
        let g = DependencyGraph {
            root_slots: std::collections::HashMap::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            roots: Vec::new(),
        };
        assert!(g.deps_of(0).is_empty());
        assert!(g.deps_of(usize::MAX).is_empty());
    }

    /// A self-edge is a cycle of length one; it is cut like any other back-edge.
    #[test]
    fn a_self_edge_terminates() {
        let g = DependencyGraph {
            root_slots: std::iter::once((0, 0)).collect(),
            nodes: vec![Node {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
                kind: NodeKind::Registry,
            }],
            edges: vec![vec![0]],
            roots: vec![0],
        };
        let tree = g.tree(&TreeOptions::default());
        assert!(!tree.truncated, "a self-edge is cut, not budgeted away");
    }
}
