//! A language-agnostic dependency graph plus cycle-safe tree traversals.
//!
//! The graph itself knows nothing about Cargo — it is nodes (a package at a
//! version) and directed edges (`a` depends on `b`). Building one from a
//! `Cargo.lock` lives in [`Self::from_resolved`]; other ecosystems can grow
//! their own constructor without touching the traversal/rendering logic here.
//! Rendering (color, box-drawing) is deliberately left to the caller — this
//! module only produces plain data.

use std::collections::HashSet;

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
}

/// Options controlling how a [`Tree`] is expanded from a [`DependencyGraph`].
#[derive(Debug, Clone, Copy)]
pub struct TreeOptions {
    /// Maximum edge depth. `Some(0)` = roots only; `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Collapse a package's second and later appearances to a `(*)` marker.
    pub dedupe: bool,
}

impl Default for TreeOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            dedupe: true,
        }
    }
}

/// A rendered dependency tree (a forest, one entry per root).
#[derive(Debug, Clone)]
pub struct Tree {
    /// The root nodes, each with their expanded subtree.
    pub roots: Vec<TreeNode>,
}

/// One node in a [`Tree`], referencing a graph node by index.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Index into [`DependencyGraph::nodes`].
    pub node: usize,
    /// Expanded children (empty when deduped, cut by a cycle, or depth-limited).
    pub children: Vec<TreeNode>,
    /// Whether this appearance was collapsed (`(*)`): a repeat under dedupe or a
    /// cycle back-edge. Its children are shown at its first, full appearance.
    pub deduped: bool,
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
                nodes
                    .iter()
                    .enumerate()
                    .filter(move |(_, n)| &n.name == name)
                    .map(|(i, _)| i)
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

    /// The direct dependencies of node `idx`.
    #[must_use]
    pub fn deps_of(&self, idx: usize) -> &[usize] {
        &self.edges[idx]
    }

    /// The root node indices.
    #[must_use]
    pub fn roots(&self) -> &[usize] {
        &self.roots
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
        }
    }

    /// Expand the graph into a [`Tree`] from its roots. Cycles (legal in Cargo
    /// via dev-dependencies) always terminate: a node already on the current
    /// path is cut as a back-edge, independent of `dedupe`.
    #[must_use]
    pub fn tree(&self, opts: &TreeOptions) -> Tree {
        let mut expanded: HashSet<usize> = HashSet::new();
        let mut on_path: HashSet<usize> = HashSet::new();
        let roots = self
            .roots
            .iter()
            .map(|&r| self.build(r, 0, opts, &mut expanded, &mut on_path))
            .collect();
        Tree { roots }
    }

    fn build(
        &self,
        idx: usize,
        depth: usize,
        opts: &TreeOptions,
        expanded: &mut HashSet<usize>,
        on_path: &mut HashSet<usize>,
    ) -> TreeNode {
        // Cut a cycle (already on this path) or a dedupe repeat (seen elsewhere).
        if on_path.contains(&idx) || (opts.dedupe && expanded.contains(&idx)) {
            return TreeNode {
                node: idx,
                children: Vec::new(),
                deduped: true,
            };
        }
        // Depth-truncated: render as a leaf but do NOT mark it seen, so a
        // shallower path elsewhere can still expand its subtree.
        if opts.max_depth.is_some_and(|m| depth >= m) {
            return TreeNode {
                node: idx,
                children: Vec::new(),
                deduped: false,
            };
        }
        // Rendered fully (leaf or with children) — count it as seen for dedupe.
        expanded.insert(idx);
        if self.edges[idx].is_empty() {
            return TreeNode {
                node: idx,
                children: Vec::new(),
                deduped: false,
            };
        }
        on_path.insert(idx);
        let children = self.edges[idx]
            .iter()
            .map(|&c| self.build(c, depth + 1, opts, expanded, on_path))
            .collect();
        on_path.remove(&idx);
        TreeNode {
            node: idx,
            children,
            deduped: false,
        }
    }
}

/// Classify a package by workspace membership then lockfile source.
fn classify(name: &str, source: Option<&str>, workspace_names: &HashSet<String>) -> NodeKind {
    if workspace_names.contains(name) {
        return NodeKind::Workspace;
    }
    match source {
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
            out.push((&node.name, &node.version, n.deduped));
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
        };
        let flat2 = flatten(&g, &g.tree(&no_dedupe));
        assert_eq!(
            flat2.iter().filter(|(n, _, ded)| *n == "d" && !ded).count(),
            2
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
        });
        assert_eq!(flatten(&g, &roots_only), vec![("app", "0.1.0", false)]);

        let one_deep = g.tree(&TreeOptions {
            max_depth: Some(1),
            dedupe: true,
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
}
