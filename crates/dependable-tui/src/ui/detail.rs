//! The detail pane: everything known about the selected package.
//!
//! Absence is rendered honestly. A field the registry did not publish reads
//! "not published", never as a blank line that looks like missing data, and a
//! lookup that failed says so rather than looking like an empty package.

use dependable_fetch::{DependencyStatus, NodeKind, Owner, OwnerKind, PackageMetadata};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::model::{PackageData, PackageFacts, compact_count, dated_age};
use crate::rows::RowKind;
use crate::theme::{self, Token};

/// Draw the pane for the current selection.
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let lines = match app.selected() {
        None => vec![dim("nothing selected")],
        Some(row) if row.kind == RowKind::Project => project_lines(app, row.project),
        Some(row) => package_lines(app, row),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::fg(Token::Border))
                    .title(Span::styled(" details ", theme::fg(Token::Muted))),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// What we can say about a whole project.
fn project_lines(app: &App, index: usize) -> Vec<Line<'static>> {
    let project = &app.projects[index];
    let mut lines = vec![
        heading(&project.label),
        field("ecosystem", project.ecosystem.display_name()),
        field("manifest", &project.manifest.display().to_string()),
        field("packages", &project.graph.nodes().len().to_string()),
    ];
    if let Some(caveat) = project.caveat() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(caveat.to_owned(), theme::fg(Token::Warn)));
    }
    lines
}

/// What we know about the selected package.
fn package_lines(app: &App, row: &crate::rows::Row) -> Vec<Line<'static>> {
    let mut lines = vec![heading(&row.name)];
    if row.version.is_empty() {
        // A shallow graph resolves no versions, so there is nothing to look up.
        lines.push(dim("version not resolved — no lockfile for this project"));
        return lines;
    }
    lines.push(field("resolved", &row.version));
    lines.push(Line::raw(""));

    // A package that did not come from the registry is not the registry's package
    // of the same name, so nothing is fetched and nothing is claimed.
    if let Some(origin) = local_origin(row) {
        lines.push(dim(origin));
        return lines;
    }

    match app.selected_data() {
        None | Some(PackageData::Unloaded) => lines.push(dim("loading…")),
        Some(PackageData::Loading) => lines.push(dim("loading…")),
        Some(PackageData::Failed(error)) => {
            lines.push(Line::styled(
                format!("could not load: {error}"),
                theme::fg(Token::Critical),
            ));
            lines.push(dim("press r to try again"));
        }
        Some(PackageData::Ready(facts)) => lines.extend(facts_lines(facts, &row.version)),
    }
    lines
}

/// Render a completed lookup.
///
/// `resolved` is the version the project actually uses, which is what the
/// publish date must describe.
fn facts_lines(facts: &PackageFacts, resolved: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Freshness first: it is the question most often being asked.
    if let Some(latest) = &facts.latest {
        lines.push(field("latest", latest));
    }
    if let Some(status) = &facts.status {
        lines.push(Line::from(vec![
            label("status"),
            Span::styled(status.label().to_owned(), status_style(status)),
        ]));
    }

    if facts.vulnerabilities.is_empty() {
        lines.push(field("advisories", "none known"));
    } else {
        lines.push(Line::from(vec![
            label("advisories"),
            Span::styled(
                facts.vulnerabilities.join(", "),
                theme::bold(Token::Critical),
            ),
        ]));
    }

    lines.push(Line::raw(""));
    match &facts.metadata {
        None => lines.push(dim("this registry publishes no package metadata")),
        Some(meta) => lines.extend(metadata_lines(meta, resolved)),
    }

    for warning in &facts.warnings {
        lines.push(Line::styled(warning.clone(), theme::fg(Token::Warn)));
    }
    lines
}

/// The public metadata block.
fn metadata_lines(meta: &PackageMetadata, resolved: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(description) = &meta.description {
        // Registry descriptions are often hard-wrapped; the pane does its own
        // wrapping, and the embedded newlines would otherwise run words together.
        lines.push(Line::raw(
            description.split_whitespace().collect::<Vec<_>>().join(" "),
        ));
        lines.push(Line::raw(""));
    }
    lines.push(optional("repository", meta.repository.as_deref()));
    lines.push(optional("homepage", meta.homepage.as_deref()));
    lines.push(optional("docs", meta.documentation.as_deref()));
    lines.push(optional("license", meta.license.as_deref()));
    lines.push(optional("msrv", meta.msrv.as_deref()));

    if meta.owners.is_empty() {
        lines.push(optional("owners", None));
    } else {
        // One per line: a comma-joined run of names, logins, and emails is
        // unreadable, and there is no room to align them on one row.
        for (i, owner) in meta.owners.iter().enumerate() {
            let name = if i == 0 {
                label("owners")
            } else {
                Span::raw(" ".repeat(13))
            };
            lines.push(Line::from(vec![name, owner_span(owner)]));
        }
    }

    lines.push(Line::raw(""));
    lines.push(optional(
        "downloads",
        meta.downloads.map(compact_count).as_deref(),
    ));
    // The resolved version's own date, not the newest release's: printed under
    // `resolved`, the latter reads as a claim about a version the project does
    // not use.
    lines.push(optional(
        "published",
        meta.published_at(resolved).map(dated_age).as_deref(),
    ));
    // The newest release, shown only when it is a different one to compare to.
    if meta.published_at(resolved) != meta.latest_published.as_deref()
        && let Some(latest) = &meta.latest_published
    {
        lines.push(field("released", &dated_age(latest)));
    }
    if meta.yanked {
        lines.push(Line::styled(
            "this version has been yanked",
            theme::bold(Token::Critical),
        ));
    }
    lines
}

/// One owner, showing every identifier the registry published for them.
///
/// Registries differ in what they know, so this renders what is there rather
/// than a fixed shape: a name and a login become `David Tolnay (@dtolnay)`, a
/// login alone becomes `@dtolnay`, and an owner known only by email is shown by
/// it. A team is marked, because "owned by a group" is a different fact from
/// "owned by a person who happens to be called that".
fn owner_span(owner: &Owner) -> Span<'static> {
    let mut text = match (owner.name.as_deref(), owner.login.as_deref()) {
        (Some(name), Some(login)) if name != login => format!("{name} (@{login})"),
        (Some(name), _) => name.to_owned(),
        (None, Some(login)) => format!("@{login}"),
        (None, None) => owner.email.clone().unwrap_or_default(),
    };
    // Only worth repeating when it is not already the whole label.
    if let Some(email) = &owner.email
        && !text.contains(email.as_str())
    {
        text.push_str(&format!(" <{email}>"));
    }
    if owner.kind == OwnerKind::Team {
        text.push_str("  [team]");
    }
    Span::styled(text, theme::fg(Token::Text))
}

/// Why a package is not looked up, when it did not come from a registry.
fn local_origin(row: &crate::rows::Row) -> Option<&'static str> {
    match row.node_kind? {
        NodeKind::Workspace => Some("a member of this workspace — not fetched from a registry"),
        NodeKind::Path => Some("a local path dependency — not fetched from a registry"),
        NodeKind::Git => Some("a git dependency — not fetched from a registry"),
        _ => None,
    }
}

fn status_style(status: &DependencyStatus) -> Style {
    match status {
        DependencyStatus::UpToDate => theme::fg(Token::Ok),
        DependencyStatus::PatchAvailable | DependencyStatus::UpdateAvailable => {
            theme::fg(Token::Warn)
        }
        DependencyStatus::Outdated => theme::fg(Token::Critical),
        DependencyStatus::Vulnerable => theme::bold(Token::Critical),
        _ => theme::fg(Token::Muted),
    }
}

fn heading(text: &str) -> Line<'static> {
    Line::styled(text.to_owned(), theme::bold(Token::Heading))
}

fn label(name: &str) -> Span<'static> {
    Span::styled(format!("{name:>11}  "), theme::fg(Token::Muted))
}

fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        label(name),
        Span::styled(value.to_owned(), theme::fg(Token::Text)),
    ])
}

/// A field the registry may not have published — said plainly either way.
fn optional(name: &str, value: Option<&str>) -> Line<'static> {
    match value {
        Some(value) => field(name, value),
        None => Line::from(vec![
            label(name),
            Span::styled("not published", theme::fg(Token::Muted)),
        ]),
    }
}

fn dim(text: &str) -> Line<'static> {
    Line::styled(text.to_owned(), theme::fg(Token::Muted))
}
