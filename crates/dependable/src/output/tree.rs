//! Dependency-tree rendering: cargo-tree-style ASCII, a JSON graph, and DOT.
//!
//! The pure [`DependencyGraph`] does the traversal; this module only turns the
//! resulting [`Tree`]/graph into text. Color is TTY-aware via `owo-colors`.

use std::collections::HashSet;
use std::fmt::Write as _;

use dependable_fetch::{DependencyGraph, NodeKind, Placement, TreeNode, TreeOptions};
use owo_colors::{OwoColorize, Stream, Style};
use serde::Serialize;

use crate::cli::TreeFormat;

/// Render `graph` in the requested `format` using `opts` for the tree shape.
///
/// # Errors
/// Propagates serialization errors from the JSON renderer.
pub fn render(
    graph: &DependencyGraph,
    format: TreeFormat,
    opts: &TreeOptions,
) -> anyhow::Result<()> {
    match format {
        TreeFormat::Tree => {
            print!("{}", ascii(graph, opts));
            Ok(())
        }
        TreeFormat::Json => {
            println!("{}", json(graph, opts)?);
            Ok(())
        }
        TreeFormat::Dot => {
            print!("{}", dot(graph, opts));
            Ok(())
        }
    }
}

/// cargo-tree-style ASCII, a forest with one tree per root.
fn ascii(graph: &DependencyGraph, opts: &TreeOptions) -> String {
    let tree = graph.tree(opts);
    if tree.roots.is_empty() {
        return "(no crates to show)\n".to_owned();
    }
    let mut out = String::new();
    for (i, root) in tree.roots.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        write_node(&mut out, graph, root, "", true, true);
    }
    out
}

fn write_node(
    out: &mut String,
    graph: &DependencyGraph,
    node: &TreeNode,
    prefix: &str,
    is_last: bool,
    is_root: bool,
) {
    let connector = if is_root {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };
    let _ = writeln!(out, "{prefix}{connector}{}", label(graph, node));

    let child_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };
    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        write_node(out, graph, child, &child_prefix, i + 1 == count, false);
    }
}

/// A node's display label: `name vX.Y.Z`, a kind tag, and a collapse marker —
/// `(*)` for a repeat, `(see root)` for a crate with a tree of its own further
/// down the forest. Colored by kind (workspace bold cyan, git magenta, path
/// yellow, registry plain) and dimmed wherever it is collapsed.
fn label(graph: &DependencyGraph, node: &TreeNode) -> String {
    let n = &graph.nodes()[node.node];
    let mut text = match n.version.as_deref() {
        Some(version) => format!("{} v{}", n.name, version),
        None => n.name.clone(),
    };
    match n.kind {
        NodeKind::Workspace => text.push_str(" (workspace)"),
        NodeKind::Git => text.push_str(" (git)"),
        NodeKind::Path => text.push_str(" (path)"),
        _ => {}
    }
    match node.placement {
        Placement::Root { .. } => text.push_str(" (see root)"),
        _ if node.deduped() => text.push_str(" (*)"),
        _ => {}
    }
    let mut style = match n.kind {
        NodeKind::Workspace => Style::new().cyan().bold(),
        NodeKind::Git => Style::new().magenta(),
        NodeKind::Path => Style::new().yellow(),
        _ => Style::new(),
    };
    if collapsed(node) {
        style = style.dimmed();
    }
    format!(
        "{}",
        text.if_supports_color(Stream::Stdout, |t| t.style(style))
    )
}

/// Whether a node's dependencies are shown somewhere other than beneath it.
fn collapsed(node: &TreeNode) -> bool {
    node.deduped() || matches!(node.placement, Placement::Root { .. })
}

/// A flat graph (nodes + edges) derived from the expanded tree, so `--depth` and
/// `--no-dedupe` shape the JSON/DOT the same way they shape the ASCII tree.
struct FlatGraph {
    /// Original node indices, in first-seen order; position = compact id.
    order: Vec<usize>,
    /// Edges as (compact-from, compact-to).
    edges: Vec<(usize, usize)>,
    /// Compact ids of the roots.
    roots: Vec<usize>,
}

fn flatten(graph: &DependencyGraph, opts: &TreeOptions) -> FlatGraph {
    let tree = graph.tree(opts);
    let mut order: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let mut edge_set: HashSet<(usize, usize)> = HashSet::new();

    fn walk(
        node: &TreeNode,
        order: &mut Vec<usize>,
        seen: &mut HashSet<usize>,
        edge_set: &mut HashSet<(usize, usize)>,
    ) {
        if seen.insert(node.node) {
            order.push(node.node);
        }
        for child in &node.children {
            edge_set.insert((node.node, child.node));
            walk(child, order, seen, edge_set);
        }
    }
    for root in &tree.roots {
        walk(root, &mut order, &mut seen, &mut edge_set);
    }

    let compact = |orig: usize| order.iter().position(|&o| o == orig).unwrap();
    let mut edges: Vec<(usize, usize)> = edge_set
        .into_iter()
        .map(|(a, b)| (compact(a), compact(b)))
        .collect();
    edges.sort_unstable();
    let roots = tree.roots.iter().map(|r| compact(r.node)).collect();
    FlatGraph {
        order,
        edges,
        roots,
    }
}

fn kind_str(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Workspace => "workspace",
        NodeKind::Registry => "registry",
        NodeKind::Git => "git",
        NodeKind::Path => "path",
        _ => "unknown",
    }
}

#[derive(Serialize)]
struct GraphDto<'a> {
    roots: Vec<usize>,
    nodes: Vec<NodeDto<'a>>,
    edges: Vec<EdgeDto>,
}

#[derive(Serialize)]
struct NodeDto<'a> {
    id: usize,
    name: &'a str,
    /// `null` when no version was ever read for this node — a graph built from
    /// manifests alone resolves none. Emitted rather than omitted so every node
    /// has the same shape and a consumer never has to tell an absent key from an
    /// absent version.
    version: Option<&'a str>,
    kind: &'static str,
}

#[derive(Serialize)]
struct EdgeDto {
    from: usize,
    to: usize,
}

fn json(graph: &DependencyGraph, opts: &TreeOptions) -> anyhow::Result<String> {
    let flat = flatten(graph, opts);
    let nodes = flat
        .order
        .iter()
        .enumerate()
        .map(|(id, &orig)| {
            let n = &graph.nodes()[orig];
            NodeDto {
                id,
                name: &n.name,
                version: n.version.as_deref(),
                kind: kind_str(n.kind),
            }
        })
        .collect();
    let edges = flat
        .edges
        .iter()
        .map(|&(from, to)| EdgeDto { from, to })
        .collect();
    let dto = GraphDto {
        roots: flat.roots,
        nodes,
        edges,
    };
    Ok(serde_json::to_string_pretty(&dto)?)
}

/// Graphviz DOT: workspace nodes filled, git/path tinted, registry plain.
fn dot(graph: &DependencyGraph, opts: &TreeOptions) -> String {
    let flat = flatten(graph, opts);
    let mut out = String::from(
        "digraph dependencies {\n  rankdir=LR;\n  node [shape=box, fontname=\"monospace\"];\n",
    );
    for (id, &orig) in flat.order.iter().enumerate() {
        let n = &graph.nodes()[orig];
        let label = match n.version.as_deref() {
            Some(version) => format!("{} v{}", n.name, version),
            None => n.name.clone(),
        };
        let escaped = label.replace('"', "\\\"");
        let attrs = match n.kind {
            NodeKind::Workspace => ", style=filled, fillcolor=\"#a6d8ff\"",
            NodeKind::Git => ", style=filled, fillcolor=\"#e6ccff\"",
            NodeKind::Path => ", style=filled, fillcolor=\"#fff0b3\"",
            _ => "",
        };
        let _ = writeln!(out, "  n{id} [label=\"{escaped}\"{attrs}];");
    }
    for (from, to) in &flat.edges {
        let _ = writeln!(out, "  n{from} -> n{to};");
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dependable_fetch::DependencyGraph;
    use dependable_fetch::core::{LockedPackage, ResolvedLockfile, parse_cargo_lock_graph};

    /// app (workspace) -> serde (registry) -> serde_derive; and app -> serde too,
    /// so serde is deduped on its second appearance.
    fn sample() -> DependencyGraph {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "serde_derive"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://x"
dependencies = ["serde_derive"]

[[package]]
name = "serde_derive"
version = "1.0.0"
source = "registry+https://x"
"#;
        let resolved = parse_cargo_lock_graph(lock).unwrap();
        let names = ["app".to_owned()].into_iter().collect();
        DependencyGraph::from_resolved(&resolved, &names, &["app".to_owned()])
    }

    #[test]
    fn ascii_marks_workspace_and_dedupe() {
        // Color is disabled in the test harness (not a TTY), so labels are plain.
        let out = ascii(&sample(), &TreeOptions::default());
        assert!(out.contains("app v0.1.0 (workspace)"));
        assert!(out.contains("├── serde v1.0.0"));
        assert!(out.contains("└── ")); // last-child connector
        assert!(out.contains("(*)")); // serde_derive (or serde) deduped once
    }

    /// Two workspace members, `app` -> `lib`, so `lib` has a tree of its own.
    fn workspace() -> DependencyGraph {
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
        let names = ["app".to_owned(), "lib".to_owned()].into_iter().collect();
        DependencyGraph::from_resolved(&resolved, &names, &["app".to_owned(), "lib".to_owned()])
    }

    #[test]
    fn ascii_points_a_member_at_its_own_tree() {
        let out = ascii(&workspace(), &TreeOptions::default());
        assert!(
            out.contains("└── lib v0.1.0 (workspace) (see root)"),
            "under `app`, `lib` is a pointer rather than a copy; {out}"
        );
        assert!(
            !out.contains("(*)"),
            "a pointer is not the repeat marker; {out}"
        );
        // The tree it points at is the one that carries the subtree.
        assert!(
            out.contains("lib v0.1.0 (workspace)\n└── serde v1.0.0"),
            "`lib`'s own entry expands; {out}"
        );
    }

    #[test]
    fn no_dedupe_expands_a_member_in_place() {
        let opts = TreeOptions {
            dedupe: false,
            collapse_roots: false,
            ..TreeOptions::default()
        };
        let out = ascii(&workspace(), &opts);
        assert!(!out.contains("(see root)"), "{out}");
        assert_eq!(out.matches("serde v1.0.0").count(), 2, "{out}");
    }

    #[test]
    fn depth_zero_shows_roots_only() {
        let opts = TreeOptions {
            max_depth: Some(0),
            dedupe: true,
            ..TreeOptions::default()
        };
        let out = ascii(&sample(), &opts);
        assert!(out.contains("app v0.1.0 (workspace)"));
        assert!(!out.contains("serde"));
    }

    #[test]
    fn json_has_nodes_edges_and_roots() {
        let out = json(&sample(), &TreeOptions::default()).unwrap();
        assert!(out.contains("\"roots\""));
        assert!(out.contains("\"kind\": \"workspace\""));
        assert!(out.contains("\"kind\": \"registry\""));
        assert!(out.contains("\"from\""));
        assert!(out.contains("\"version\": \"1.0.0\""));
    }

    /// A graph built from manifests alone resolves no versions. Emitting `""`
    /// there tells a consumer the package is at the empty version; `null` tells
    /// it the truth, which is that nobody read one.
    #[test]
    fn json_reports_an_unread_version_as_null() {
        let packages = vec![
            LockedPackage::new("app".to_owned(), None, None, vec!["serde".to_owned()]),
            LockedPackage::new(
                "serde".to_owned(),
                None,
                Some("registry+".to_owned()),
                Vec::new(),
            ),
        ];
        let resolved = ResolvedLockfile::from_packages(packages);
        let names = ["app".to_owned()].into_iter().collect();
        let graph = DependencyGraph::from_resolved(&resolved, &names, &["app".to_owned()]);

        let out = json(&graph, &TreeOptions::default()).unwrap();
        assert!(out.contains("\"version\": null"), "{out}");
        assert!(!out.contains("\"version\": \"\""), "{out}");
    }

    #[test]
    fn dot_is_a_digraph_with_styled_workspace() {
        let out = dot(&sample(), &TreeOptions::default());
        assert!(out.starts_with("digraph dependencies {"));
        assert!(out.contains("label=\"app v0.1.0\", style=filled"));
        assert!(out.contains(" -> "));
        assert!(out.trim_end().ends_with('}'));
    }
}
