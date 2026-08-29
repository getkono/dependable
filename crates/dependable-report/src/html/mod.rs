//! Self-contained HTML reports.
//!
//! [`render`] turns a [`Report`] into **one** HTML document: inline CSS, inline
//! SVG charts, no external stylesheet, script, font, or image. It opens offline
//! from a single file. The only outbound URLs are advisory links the reader may
//! choose to follow — links, not loads.
//!
//! # Purity
//!
//! [`render`] does no filesystem or network IO. Template overrides arrive
//! already-read, in [`HtmlOptions::overrides`], so the caller owns the directory
//! walk and this crate keeps the "no IO of its own" promise its
//! [crate root](crate) makes. That is also what lets every rendering test run
//! with no temporary directory.
//!
//! # The escaping guarantee
//!
//! A dependency report is built almost entirely from strings this tool did not
//! write: package names from a manifest, advisory summaries and Markdown bodies
//! from OSV, error text from a registry. Five mechanisms keep them inert, and
//! each is independently checkable.
//!
//! 1. **Autoescaping does not depend on the file name.** The environment is given
//!    a *constant* auto-escape callback, so every template — built-in or
//!    overridden, whatever it is called — is escaped as HTML. minijinja's default
//!    callback sniffs the extension, which would leave an override named
//!    anything else unescaped.
//! 2. **No `|safe`, anywhere.** Not in a template, not in the renderer. A unit
//!    test string-scans the embedded template sources for the escape hatches.
//! 3. **Every template body is first-party.** Nothing in a template's literal
//!    text derives from a [`Report`].
//! 4. **Third-party strings appear only in text nodes and double-quoted
//!    attributes.** The document contains no `<script>` element at all, no
//!    `<style>` content derived from data, no unquoted attributes, and no HTML
//!    comments carrying data.
//! 5. **URL schemes are filtered in Rust.** Escaping does not stop
//!    `javascript:` — it contains nothing an escaper touches. Only `http` and
//!    `https` URLs become an `href`; anything else is rendered as inert escaped
//!    text.
//!
//! An advisory's `details` is published Markdown, and every Markdown dialect
//! permits raw inline HTML. It is therefore **escaped and pre-wrapped, never
//! rendered** — rendering the most attacker-influenced field in the document to
//! get prettier prose is a bad trade.
//!
//! # Template overrides
//!
//! The eight names in [`TEMPLATE_NAMES`] are a public compatibility surface: each
//! can be replaced wholesale via [`HtmlOptions::with_override`]. Replacement is
//! whole-file — no merging and no inheritance tricks — so overriding
//! `report.html` alone still `{% include %}`s the built-in sections, and
//! overriding one section leaves the shell intact. An override whose name is not
//! in [`TEMPLATE_NAMES`], and one that fails to parse, are both hard errors:
//! there is no silent fall back to the built-in, because handing a user this
//! crate's template when they asked for theirs is a lie.
//!
//! `styles.css` is a template rather than a context string, which is what lets a
//! caller restyle the entire report by supplying one file. Its body is wrapped in
//! `{% raw %}` so a stray `{{` in CSS is never parsed as Jinja.
//!
//! The macro signatures in `macros.html` are part of that contract; changing one
//! is a breaking change for anyone who overrode a section that calls it.
//!
//! # Charts
//!
//! The ecosystem pie is hand-rolled inline SVG with every coordinate computed and
//! formatted in Rust, so the output is byte-deterministic. It carries `role`,
//! `<title>`, and `<desc>` — and, decisively, a real `<table>` of the same
//! figures sits directly beneath it. The chart is decoration; the table is the
//! data.

mod model;

use std::collections::BTreeMap;

use minijinja::{AutoEscape, Environment, ErrorKind};

use crate::error::ReportError;
use crate::model::Report;

/// The template that is rendered; every other template reaches the document
/// through it.
const ROOT_TEMPLATE: &str = "report.html";

/// Every template name a caller may override, in the order the document uses
/// them.
///
/// This list is a **public compatibility surface**: a caller's override
/// directory is keyed by these names, so removing or renaming one is a breaking
/// change.
pub const TEMPLATE_NAMES: &[&str] = &[
    "report.html",
    "styles.css",
    "macros.html",
    "summary.html",
    "vulnerabilities.html",
    "dependencies.html",
    "timeline.html",
    "ecosystems.html",
];

/// The built-in source for each name in [`TEMPLATE_NAMES`].
///
/// Embedded with `include_str!`, which keeps the crate a single artifact with no
/// runtime asset lookup — and keeps minijinja's `loader` feature (the one that
/// would give templates filesystem access) switched off.
const BUILTINS: &[(&str, &str)] = &[
    ("report.html", include_str!("templates/report.html")),
    ("styles.css", include_str!("templates/styles.css")),
    ("macros.html", include_str!("templates/macros.html")),
    ("summary.html", include_str!("templates/summary.html")),
    (
        "vulnerabilities.html",
        include_str!("templates/vulnerabilities.html"),
    ),
    (
        "dependencies.html",
        include_str!("templates/dependencies.html"),
    ),
    ("timeline.html", include_str!("templates/timeline.html")),
    ("ecosystems.html", include_str!("templates/ecosystems.html")),
];

/// How to render an HTML report.
///
/// `#[non_exhaustive]`: build with [`HtmlOptions::new`] and the `with_*` methods
/// so later knobs don't break callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HtmlOptions {
    /// Document `<title>` and `<h1>`.
    pub title: String,
    /// Whole-template replacements, keyed by a name from [`TEMPLATE_NAMES`].
    ///
    /// The values are template *sources*, already read: this crate does no
    /// filesystem IO, so a caller offering "a directory of overrides" reads that
    /// directory itself.
    pub overrides: BTreeMap<String, String>,
    /// Stamp [`Report::generated_at`] into a `<meta>` tag and the footer.
    ///
    /// On by default. Turning it off is what makes two reports of an unchanged
    /// tree byte-identical, which is useful when a report is committed.
    pub timestamp: bool,
    /// Banner notes for the executive summary.
    ///
    /// A report is frequently the only artifact a reviewer sees, so warnings a
    /// run would otherwise leave on a CI console — a skipped ecosystem, an
    /// unreadable lockfile, vulnerability scanning being off — belong in the
    /// document.
    pub notes: Vec<String>,
}

impl Default for HtmlOptions {
    /// Hand-written rather than derived: the derive would default
    /// [`Self::timestamp`] to `false`, silently dropping provenance from every
    /// report built with `Default`.
    fn default() -> Self {
        Self {
            title: "dependable report".to_owned(),
            overrides: BTreeMap::new(),
            timestamp: true,
            notes: Vec::new(),
        }
    }
}

impl HtmlOptions {
    /// The defaults: the standard title, no overrides, timestamp on.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the document title.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Replace one template wholesale.
    ///
    /// `name` must be one of [`TEMPLATE_NAMES`]; [`render`] rejects anything else
    /// rather than ignoring it, because an override that silently does nothing is
    /// worse than one that fails.
    #[must_use]
    pub fn with_override(mut self, name: impl Into<String>, source: impl Into<String>) -> Self {
        self.overrides.insert(name.into(), source.into());
        self
    }

    /// Add one banner note to the executive summary.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Leave [`Report::generated_at`] out of the document.
    #[must_use]
    pub fn without_timestamp(mut self) -> Self {
        self.timestamp = false;
        self
    }
}

/// Render `report` as one self-contained HTML document.
///
/// Pure: no filesystem, no network, no clock of its own (the timestamp comes from
/// the report). The same inputs always produce the same bytes.
///
/// # Errors
///
/// - [`ReportError::Template`] if an override names a template that does not
///   exist, or if any template fails to parse or render. The wrapped error names
///   the template and the line.
/// - [`ReportError::Format`] if the report's timestamp cannot be formatted.
#[must_use = "the rendered document is the only output of this call"]
pub fn render(report: &Report, options: &HtmlOptions) -> Result<String, ReportError> {
    let view = model::View::build(report, options)?;
    let env = environment(options)?;
    Ok(env.get_template(ROOT_TEMPLATE)?.render(&view)?)
}

/// The minijinja environment: built-ins, then the caller's overrides on top.
fn environment(options: &HtmlOptions) -> Result<Environment<'_>, ReportError> {
    if let Some(unknown) = options
        .overrides
        .keys()
        .find(|name| !TEMPLATE_NAMES.contains(&name.as_str()))
    {
        return Err(ReportError::Template(minijinja::Error::new(
            ErrorKind::TemplateNotFound,
            format!(
                "unknown template override `{unknown}`; valid names are: {}",
                TEMPLATE_NAMES.join(", ")
            ),
        )));
    }

    let mut env = Environment::new();
    // THE escaping guarantee. A *constant* callback, deliberately not
    // `default_auto_escape_callback`: minijinja's default decides from the file
    // extension, so an override named `sections.tpl` — or a built-in renamed in a
    // later refactor — would render every advisory summary unescaped.
    env.set_auto_escape_callback(|_| AutoEscape::Html);
    for (name, builtin) in BUILTINS {
        let source = options
            .overrides
            .get(*name)
            .map_or(*builtin, String::as_str);
        env.add_template(name, source)?;
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use dependable_core::result::{Advisory, AdvisoryReference, AdvisorySeverity, ReferenceKind};
    use dependable_core::{CheckResult, DependencyStatus, Ecosystem, ManifestKind, parse};
    use time::OffsetDateTime;

    use super::*;
    use crate::model::ManifestResults;

    /// 2023-11-14T22:13:20Z.
    const FIXED: i64 = 1_700_000_000;

    fn fixed_report(results: Vec<CheckResult>) -> Report {
        let mut report = Report::at(
            PathBuf::from("/proj"),
            OffsetDateTime::from_unix_timestamp(FIXED).expect("a valid timestamp"),
        );
        report.push(ManifestResults::new(
            PathBuf::from("Cargo.toml"),
            Ecosystem::Rust,
            results,
        ));
        report
    }

    /// `Item` has no public constructor, so a real one comes from a real parse.
    fn result(name: &str, status: DependencyStatus) -> CheckResult {
        // A TOML-quoted key, so a deliberately hostile package name still parses.
        let key = name.replace('\\', "\\\\").replace('"', "\\\"");
        let manifest = format!("[dependencies]\n\"{key}\" = \"1.0.0\"\n");
        let parsed = parse(ManifestKind::CargoToml, &manifest).expect("parse the fixture");
        let item = parsed.items.into_iter().next().expect("one item");
        CheckResult::new(item, status)
    }

    fn render_default(report: &Report) -> String {
        render(report, &HtmlOptions::new()).expect("render the report")
    }

    #[test]
    fn an_empty_report_is_a_whole_document() {
        let html = render_default(&Report::at(
            PathBuf::from("/proj"),
            OffsetDateTime::from_unix_timestamp(FIXED).expect("a valid timestamp"),
        ));

        assert!(html.starts_with("<!doctype html>"), "{html}");
        assert!(html.contains("</html>"));
        assert!(html.contains("No dependencies to chart."));
        assert!(html.contains("No advisories affect this dependency tree."));
        assert!(!html.contains("<svg class=\"pie\""), "zero slices, no pie");
    }

    #[test]
    fn no_template_reaches_for_an_escape_hatch() {
        // A pure string assertion over the embedded sources: no rendering
        // involved, so it cannot be satisfied by a lucky fixture.
        for (name, source) in BUILTINS {
            for hatch in [
                "|safe",
                "| safe",
                "safe(",
                "autoescape false",
                "|e(",
                "safe |",
            ] {
                assert!(
                    !source.contains(hatch),
                    "{name} uses `{hatch}`; every value in this report is escaped"
                );
            }
        }
    }

    #[test]
    fn the_builtin_set_and_the_public_name_list_agree() {
        let builtin: Vec<&str> = BUILTINS.iter().map(|(name, _)| *name).collect();

        assert_eq!(builtin, TEMPLATE_NAMES, "the public list is the real list");
        assert!(TEMPLATE_NAMES.contains(&ROOT_TEMPLATE));
    }

    #[test]
    fn hostile_strings_land_escaped_and_inert() {
        let mut vulnerable = result("\"><img onerror=x>", DependencyStatus::Vulnerable);
        vulnerable.current_vulnerabilities = vec!["RUSTSEC-2020-0001".into()];
        vulnerable.advisories = vec![
            Advisory::new("RUSTSEC-2020-0001")
                .with_summary("<script>alert(1)</script>")
                .with_details("</div><script>alert(2)</script>")
                .with_severity(AdvisorySeverity::from_score(9.8))
                .with_references(vec![
                    AdvisoryReference::new(ReferenceKind::Advisory, "javascript:alert(3)"),
                    AdvisoryReference::new(ReferenceKind::Web, "https://osv.dev/x"),
                ]),
        ];

        let html = render_default(&fixed_report(vec![vulnerable]));

        assert!(!html.contains("<script"), "a script element got through");
        assert!(!html.contains("<img"), "an img element got through");
        assert!(
            !html.contains("onerror=x>"),
            "an unescaped event handler got through"
        );
        assert!(
            !html.contains("href=\"javascript:"),
            "a javascript: URL reached an href"
        );
        // The escaped forms must be present: the data is shown, just inertly.
        // minijinja follows the OWASP rule and escapes `/` as `&#x2f;` too, which
        // is why a closing tag reads `&lt;&#x2f;script&gt;`.
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;&#x2f;script&gt;"),
            "{html}"
        );
        assert!(
            html.contains("&lt;&#x2f;div&gt;&lt;script&gt;alert(2)"),
            "{html}"
        );
        assert!(html.contains("&quot;&gt;&lt;img onerror=x&gt;"), "{html}");
        // The rejected reference is still shown, as text rather than a link.
        assert!(html.contains("javascript:alert(3)"), "{html}");
        assert!(html.contains("class=\"ext inert\""), "{html}");
    }

    #[test]
    fn the_document_loads_nothing_from_anywhere() {
        // No external *loads*. External *links* — advisory pages — are the point
        // of the report and are deliberately not banned.
        let mut vulnerable = result("openssl", DependencyStatus::Vulnerable);
        vulnerable.current_vulnerabilities = vec!["RUSTSEC-2020-0001".into()];
        vulnerable.advisories = vec![
            Advisory::new("RUSTSEC-2020-0001")
                .with_severity(AdvisorySeverity::from_score(7.5))
                .with_references(vec![AdvisoryReference::new(
                    ReferenceKind::Advisory,
                    "https://rustsec.org/advisories/RUSTSEC-2020-0001",
                )]),
        ];

        let html = render_default(&fixed_report(vec![vulnerable]));

        for vector in ["<script", "<link", "<img", "<iframe", "@import", "url("] {
            assert!(
                !html.contains(vector),
                "`{vector}` is an external load vector"
            );
        }
        assert!(
            html.contains("rustsec.org"),
            "advisory links are the report's point"
        );
    }

    #[test]
    fn the_timestamp_is_stamped_by_default_and_omitted_on_request() {
        let report = fixed_report(vec![result("serde", DependencyStatus::UpToDate)]);

        let stamped = render_default(&report);
        let bare = render(&report, &HtmlOptions::new().without_timestamp())
            .expect("render without a timestamp");

        assert!(stamped.contains("2023-11-14T22:13:20Z"), "{stamped}");
        assert!(stamped.contains("<meta name=\"generated\""), "{stamped}");
        assert!(!bare.contains("2023-11-14T22:13:20Z"));
        assert!(!bare.contains("<meta name=\"generated\""));
        assert!(bare.contains("not stamped"));
    }

    #[test]
    fn rendering_is_byte_stable_across_runs() {
        let report = fixed_report(vec![
            result("serde", DependencyStatus::UpToDate),
            result("tokio", DependencyStatus::Outdated),
        ]);

        assert_eq!(render_default(&report), render_default(&report));
    }

    #[test]
    fn the_title_and_notes_reach_the_document_escaped() {
        let options = HtmlOptions::new()
            .with_title("Q3 <audit>")
            .with_note("vulnerability scanning was disabled")
            .with_note("skipped mix.exs: Elixir is not enabled");

        let html = render(&fixed_report(Vec::new()), &options).expect("render");

        assert!(html.contains("<title>Q3 &lt;audit&gt;</title>"), "{html}");
        assert!(html.contains("vulnerability scanning was disabled"));
        assert!(html.contains("skipped mix.exs: Elixir is not enabled"));
    }

    #[test]
    fn a_styles_override_replaces_the_stylesheet_wholesale() {
        let options =
            HtmlOptions::new().with_override("styles.css", "body { color: rebeccapurple }");

        let html = render(&fixed_report(Vec::new()), &options).expect("render");

        assert!(html.contains("body { color: rebeccapurple }"), "{html}");
        assert!(!html.contains("--accent"), "the built-in CSS must be gone");
    }

    #[test]
    fn a_section_override_leaves_the_shell_intact() {
        let options =
            HtmlOptions::new().with_override("timeline.html", "<section id=\"t\">mine</section>");

        let html = render(&fixed_report(Vec::new()), &options).expect("render");

        assert!(html.contains("<section id=\"t\">mine</section>"), "{html}");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("1. Executive summary"));
    }

    #[test]
    fn an_override_is_escaped_no_matter_what_it_is_called() {
        // The whole point of the constant auto-escape callback: a `.css` name is
        // not a licence to emit raw interpolations.
        let options = HtmlOptions::new()
            .with_override("styles.css", "/* {{ title }} */")
            .with_title("</style><script>alert(1)</script>");

        let html = render(&fixed_report(Vec::new()), &options).expect("render");

        assert!(!html.contains("<script"), "{html}");
        assert!(html.contains("&lt;&#x2f;style&gt;&lt;script&gt;"), "{html}");
    }

    #[test]
    fn an_unknown_override_name_is_an_error_that_names_the_valid_set() {
        let options = HtmlOptions::new().with_override("sections.tpl", "boom");

        let err = render(&fixed_report(Vec::new()), &options).expect_err("must not be ignored");

        let message = err.to_string();
        assert!(message.contains("sections.tpl"), "{message}");
        assert!(message.contains("report.html"), "{message}");
        assert!(message.contains("ecosystems.html"), "{message}");
    }

    #[test]
    fn a_malformed_override_fails_loudly_rather_than_falling_back() {
        let options = HtmlOptions::new().with_override("summary.html", "{% for x in %}");

        let err = render(&fixed_report(Vec::new()), &options).expect_err("must not fall back");

        let message = err.to_string();
        assert!(message.contains("summary.html"), "{message}");
        assert!(
            !message.contains("Executive summary"),
            "no silent fallback to the built-in: {message}"
        );
    }

    #[test]
    fn a_registry_error_message_is_shown_and_escaped() {
        let report = fixed_report(vec![result(
            "brokenpkg",
            DependencyStatus::Error("502 <b>bad gateway</b>".into()),
        )]);

        let html = render_default(&report);

        assert!(
            html.contains("502 &lt;b&gt;bad gateway&lt;&#x2f;b&gt;"),
            "{html}"
        );
    }

    #[test]
    fn a_single_ecosystem_draws_a_circle_and_never_an_empty_arc() {
        let html = render_default(&fixed_report(vec![result(
            "serde",
            DependencyStatus::UpToDate,
        )]));

        assert!(
            html.contains("<circle cx=\"110\" cy=\"110\" r=\"100\""),
            "{html}"
        );
        assert!(!html.contains("<path d="), "one slice is never a path");
    }
}
