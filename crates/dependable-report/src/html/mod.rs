//! Self-contained HTML reports.
//!
//! **Slot — no implementation yet.** This module's contract is fixed so the HTML
//! renderer can be dropped in without changing anything around it.
//!
//! # Contract
//!
//! ```text
//! pub fn render(report: &Report, options: &HtmlOptions) -> Result<String, ReportError>
//! ```
//!
//! - Takes a [`Report`](crate::Report) and returns **one self-contained HTML
//!   document** as an owned `String`: inline CSS, inline SVG charts, no external
//!   stylesheet, script, font, or image loads. The document must render offline
//!   from a single file.
//! - Errors are [`ReportError`](crate::ReportError) variants; the renderer adds
//!   its own (template, IO) there rather than introducing a second error type.
//! - `HtmlOptions` is defined here and carries at least a directory of template
//!   overrides, so a consumer can restyle the report without a code change.
//! - Templates live in `src/html/templates/` and are embedded with `include_str!`,
//!   which keeps the crate a single artifact with no runtime asset lookup.
//! - The renderer owns `Report::summary()` (aggregate status counts). The CLI's
//!   own `output::Summary` is a separate, table-oriented type and stays where it is.
//! - `minijinja` (templating) and `base64` (inlining binary assets) are added by
//!   the renderer, not before — a dependency arrives with the code that uses it.
