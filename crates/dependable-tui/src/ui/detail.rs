//! The detail pane: everything known about the selected package.
//!
//! Absence is rendered honestly. A field the registry did not publish reads
//! "not published", never as a blank line that looks like missing data, and a
//! lookup that failed says so rather than looking like an empty package.

use dependable_fetch::{DependencyStatus, Ecosystem, NodeKind, Owner, OwnerKind, PackageMetadata};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;
use crate::model::{PackageData, PackageFacts, compact_count, dated_age};
use crate::rows::RowKind;
use crate::theme::{self, Token};
use crate::ui::link;
use crate::url;

/// The width of a field label, including the two spaces after it.
const LABEL_WIDTH: u16 = 13;

/// A hyperlink's place in the pane: which line it is on, and at which column.
struct Spot {
    line: usize,
    col: u16,
    url: String,
    text: String,
}

/// The pane's content: its lines, and the links sitting inside them.
///
/// The links are recorded as positions rather than drawn with the lines,
/// because a `Span` cannot carry a URL — they are written into the buffer after
/// the paragraph, by [`link::write`].
#[derive(Default)]
struct Content {
    lines: Vec<Line<'static>>,
    links: Vec<Spot>,
}

impl Content {
    fn push(&mut self, line: Line<'static>) {
        self.lines.push(line);
    }

    /// Record a link on the line that is about to be pushed.
    fn link(&mut self, col: u16, url: &str, text: &str) {
        self.links.push(Spot {
            line: self.lines.len(),
            col,
            url: url::target_url(url),
            text: text.to_owned(),
        });
    }
}

/// Draw the pane for the current selection.
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::fg(Token::Border))
        .title(Span::styled(" details ", theme::fg(Token::Muted)));
    let inner = block.inner(area);

    let content = match app.selected() {
        None => Content {
            lines: vec![dim("nothing selected")],
            links: Vec::new(),
        },
        Some(row) if row.kind == RowKind::Project => project_lines(app, row.project),
        Some(row) => package_lines(app, row, inner.width),
    };

    // Rendered without `Wrap`, so line `i` is always at `inner.y + i` and a link
    // can be written at a position known before the paragraph is drawn. Long
    // values are truncated instead, which also keeps the labels aligned.
    frame.render_widget(Paragraph::new(content.lines).block(block), area);

    let buffer = frame.buffer_mut();
    for spot in content.links {
        let Ok(offset) = u16::try_from(spot.line) else {
            continue;
        };
        link::write(
            buffer,
            inner,
            inner.x + spot.col,
            inner.y + offset,
            &spot.url,
            &spot.text,
            theme::fg(Token::Link),
        );
    }
}

/// What we can say about a whole project.
fn project_lines(app: &App, index: usize) -> Content {
    let project = &app.projects[index];
    let mut content = Content::default();
    content.push(heading(&project.label));
    content.push(field("ecosystem", project.ecosystem.display_name()));
    content.push(field("manifest", &project.manifest.display().to_string()));
    content.push(field("packages", &project.graph.nodes().len().to_string()));
    if let Some(caveat) = project.caveat() {
        content.push(Line::raw(""));
        content.push(Line::styled(caveat.to_owned(), theme::fg(Token::Warn)));
    }
    content
}

/// What we know about the selected package.
fn package_lines(app: &App, row: &crate::rows::Row, width: u16) -> Content {
    let mut content = Content::default();
    let ecosystem = app.ecosystem_of(row);
    // Only a package that came from the registry has pages there. The same name
    // on a workspace member or a git dependency belongs to someone else.
    let published = row.node_kind == Some(NodeKind::Registry);

    content.push(heading(&row.name));
    let Some(version) = row.version.as_deref() else {
        // Nothing read a version for this dependency, so nothing here may be
        // looked up or claimed. Why it could not be read is the project row's
        // caveat to explain, not this pane's.
        content.push(dim(
            "version not resolved — nothing read a version for this",
        ));
        return content;
    };
    if published {
        // The version the project uses, not the newest one: the package page
        // describes a release this project may be years behind.
        let url = ecosystem.version_url(&row.name, version);
        linked_field(&mut content, "resolved", version, &url);
    } else {
        content.push(field("resolved", version));
    }
    content.push(Line::raw(""));

    // A package that did not come from the registry is not the registry's package
    // of the same name, so nothing is fetched and nothing is claimed.
    if !published {
        content.push(dim(local_origin(row)));
        return content;
    }

    // Derived from the name rather than fetched, so it is on screen while
    // everything below it is still being looked up.
    link_field(&mut content, "registry", &ecosystem.package_url(&row.name));
    content.push(Line::raw(""));

    // `Unloaded` and `None` are a request that has not been sent yet rather than
    // one in flight, but the distinction is a fraction of a second the reader
    // cannot act on, and both are genuinely being waited for.
    let fetching = format!(
        "{} fetching from {}…",
        app.spinner(),
        ecosystem.display_name()
    );
    match app.selected_data() {
        None | Some(PackageData::Unloaded) => content.push(dim(&fetching)),
        Some(PackageData::Loading) => content.push(dim(&fetching)),
        Some(PackageData::Failed(error)) => {
            content.push(Line::styled(
                format!("could not load: {error}"),
                theme::fg(Token::Critical),
            ));
            content.push(dim("press r to try again"));
        }
        Some(PackageData::Ready(facts)) => {
            facts_lines(&mut content, facts, row, version, ecosystem, width);
        }
    }
    content
}

/// Render a completed lookup.
///
/// `resolved` is the version the project actually uses, which is what the
/// publish date must describe and which version's pages to link. It is passed in
/// rather than read back off `row` because reaching here at all means it is
/// known — a row without one never gets this far.
fn facts_lines(
    content: &mut Content,
    facts: &PackageFacts,
    row: &crate::rows::Row,
    resolved: &str,
    ecosystem: Ecosystem,
    width: u16,
) {
    // Freshness first: it is the question most often being asked.
    if let Some(latest) = &facts.latest {
        content.push(field("latest", latest));
    }
    if let Some(status) = &facts.status {
        content.push(Line::from(vec![
            label("status"),
            Span::styled(status.label().to_owned(), status_style(status)),
        ]));
    }

    if facts.vulnerabilities.is_empty() {
        content.push(field("advisories", "none known"));
    } else {
        // Each advisory is linked to its OSV page: the ID alone is a lookup the
        // reader would otherwise have to do by hand.
        for (i, advisory) in facts.vulnerabilities.iter().enumerate() {
            let prefix = if i == 0 {
                label("advisories")
            } else {
                Span::raw(" ".repeat(LABEL_WIDTH as usize))
            };
            content.link(LABEL_WIDTH, &osv_url(advisory), advisory);
            content.push(Line::from(vec![
                prefix,
                Span::styled(advisory.clone(), theme::bold(Token::Critical)),
            ]));
        }
    }

    content.push(Line::raw(""));
    match &facts.metadata {
        None => {
            content.push(dim("this registry publishes no package metadata"));
            // Derived from the name, so it survives a registry that publishes
            // nothing at all — which is the case pub.dev and NuGet are in.
            if let Some(url) = ecosystem.docs_url(&row.name, resolved) {
                content.push(Line::raw(""));
                link_field(content, "docs", &url);
            }
        }
        Some(meta) => metadata_lines(content, meta, row, resolved, ecosystem, width),
    }

    for warning in &facts.warnings {
        content.push(Line::styled(warning.clone(), theme::fg(Token::Warn)));
    }
}

/// The advisory's page on OSV, which is where every ID we report resolves.
fn osv_url(id: &str) -> String {
    format!("https://osv.dev/vulnerability/{id}")
}

/// The public metadata block.
fn metadata_lines(
    content: &mut Content,
    meta: &PackageMetadata,
    row: &crate::rows::Row,
    resolved: &str,
    ecosystem: Ecosystem,
    width: u16,
) {
    if let Some(description) = &meta.description {
        // Registry descriptions are often hard-wrapped; the embedded newlines
        // would run words together, and the pane no longer wraps for us.
        let flowed = description.split_whitespace().collect::<Vec<_>>().join(" ");
        for line in wrap(&flowed, width) {
            content.push(Line::styled(line, theme::fg(Token::Text)));
        }
        content.push(Line::raw(""));
    }
    url_field(content, "repository", meta.repository.as_deref());
    url_field(content, "homepage", meta.homepage.as_deref());
    // Where an ecosystem builds documentation is a fact about the ecosystem
    // rather than something the registry had to record, so a package that
    // declared no `documentation` URL still has a page worth pointing at.
    let docs = meta
        .documentation
        .clone()
        .or_else(|| ecosystem.docs_url(&row.name, resolved));
    url_field(content, "docs", docs.as_deref());
    content.push(optional("license", meta.license.as_deref()));
    content.push(optional("msrv", meta.msrv.as_deref()));

    if meta.owners.is_empty() {
        content.push(optional("owners", None));
    } else {
        // One per line: a comma-joined run of names, logins, and emails is
        // unreadable, and there is no room to align them on one row.
        for (i, owner) in meta.owners.iter().enumerate() {
            let name = if i == 0 {
                label("owners")
            } else {
                Span::raw(" ".repeat(LABEL_WIDTH as usize))
            };
            let span = owner_span(owner);
            // An owner with a profile is linked by the label naming them.
            if let Some(url) = &owner.url {
                content.link(LABEL_WIDTH, url, &span.content);
            }
            content.push(Line::from(vec![name, span]));
        }
    }

    content.push(Line::raw(""));
    content.push(optional(
        "downloads",
        meta.downloads.map(compact_count).as_deref(),
    ));
    // The resolved version's own date, not the newest release's: printed under
    // `resolved`, the latter reads as a claim about a version the project does
    // not use.
    content.push(optional(
        "published",
        meta.published_at(resolved).map(dated_age).as_deref(),
    ));
    // The newest release, shown only when it is a different one to compare to.
    if meta.published_at(resolved) != meta.latest_published.as_deref()
        && let Some(latest) = &meta.latest_published
    {
        content.push(field("released", &dated_age(latest)));
    }
    if meta.yanked {
        content.push(Line::styled(
            "this version has been yanked",
            theme::bold(Token::Critical),
        ));
    }
}

/// A field whose value is a link, labelled by `text` rather than by the URL.
///
/// A link claims the rest of its row — see [`link::write`] — so nothing may be
/// added to the line this pushes.
fn linked_field(content: &mut Content, name: &str, text: &str, url: &str) {
    content.link(LABEL_WIDTH, url, text);
    content.push(Line::from(vec![
        label(name),
        Span::styled(text.to_owned(), theme::fg(Token::Link)),
    ]));
}

/// A URL field: shown by its readable form, and clickable.
fn link_field(content: &mut Content, name: &str, url: &str) {
    linked_field(content, name, &url::display_url(url), url);
}

/// A URL field the registry may not have published.
///
/// A field recorded as an empty string is one it did not publish: rendering it
/// would put a label on screen with nothing after it, which is the blank line
/// this pane exists to avoid.
fn url_field(content: &mut Content, name: &str, url: Option<&str>) {
    match url::published(url) {
        Some(url) => link_field(content, name, url),
        None => content.push(optional(name, None)),
    }
}

/// Greedily wrap `text` to `width` columns, breaking on whitespace.
///
/// The pane renders without ratatui's `Wrap` so that every line's position is
/// known before it is drawn — which is what lets a link be written at an exact
/// cell. Only free prose needs wrapping, and it needs it here instead.
fn wrap(text: &str, width: u16) -> Vec<String> {
    let width = usize::from(width).max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
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
///
/// `NodeKind` is `#[non_exhaustive]`, so a kind this build has never heard of
/// still has to say something. Saying only that it was not fetched is honest
/// about both facts: nothing was looked up, and we cannot explain why.
fn local_origin(row: &crate::rows::Row) -> &'static str {
    match row.node_kind {
        Some(NodeKind::Workspace) => "a member of this workspace — not fetched from a registry",
        Some(NodeKind::Path) => "a local path dependency — not fetched from a registry",
        Some(NodeKind::Git) => "a git dependency — not fetched from a registry",
        _ => "not fetched from a registry",
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
