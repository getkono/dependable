//! Dependency-tree rendering: cargo-tree-style ASCII, a JSON graph, and DOT.
//!
//! The pure [`DependencyGraph`] does the traversal; this module only turns the
//! resulting [`Tree`]/graph into text. Color is TTY-aware via `owo-colors`.

use std::collections::HashSet;
use std::fmt::Write as _;

use dependable_fetch::{DependencyGraph, NodeKind, TreeNode, TreeOptions};
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

/// A node's display label: `name vX.Y.Z`, a kind tag, and a `(*)` dedupe marker,
/// colored by kind (workspace bold cyan, git magenta, path yellow, registry
/// plain) and dimmed when deduped.
fn label(graph: &DependencyGraph, node: &TreeNode) -> String {
    let n = &graph.nodes()[node.node];
    let mut text = if n.version.is_empty() {
        n.name.clone()
    } else {
        format!("{} v{}", n.name, n.version)
    };
    match n.kind {
        NodeKind::Workspace => text.push_str(" (workspace)"),
        NodeKind::Git => text.push_str(" (git)"),
        NodeKind::Path => text.push_str(" (path)"),
        _ => {}
    }
    if node.deduped {
        text.push_str(" (*)");
    }
    let mut style = match n.kind {
        NodeKind::Workspace => Style::new().cyan().bold(),
        NodeKind::Git => Style::new().magenta(),
        NodeKind::Path => Style::new().yellow(),
        _ => Style::new(),
    };
    if node.deduped {
        style = style.dimmed();
    }
    format!(
        "{}",
        text.if_supports_color(Stream::Stdout, |t| t.style(style))
    )
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
    version: &'a str,
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
                version: &n.version,
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
        let label = if n.version.is_empty() {
            n.name.clone()
        } else {
            format!("{} v{}", n.name, n.version)
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
    use dependable_fetch::core::parse_cargo_lock_graph;

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

    #[test]
    fn depth_zero_shows_roots_only() {
        let opts = TreeOptions {
            max_depth: Some(0),
            dedupe: true,
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
