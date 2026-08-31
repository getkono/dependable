//! GitHub Actions integration: pull-request annotations and a job summary.
//!
//! Two side channels, both written *beside* whatever `--format` puts on stdout:
//!
//! 1. **Annotations** — [workflow commands][cmd] of the form
//!    `::error file=…,line=…,title=…::message`, one per line, written to
//!    **stderr**. The runner parses workflow commands on stderr exactly as it
//!    does on stdout (both streams are fed to output managers built from the
//!    same command manager, which inspects a line without knowing which stream
//!    it came from). Using stderr is what lets `--format json` and
//!    `--format sarif` keep stdout a single valid document while the
//!    annotations still reach the pull request. No format has to be excluded and
//!    nothing has to be suppressed.
//! 2. **A job summary** — Markdown appended to the file named by
//!    `GITHUB_STEP_SUMMARY`, when that variable is set.
//!
//! [`emit`] returns `()`, never a `Result`. That is the mechanism rather than a
//! style choice: with no `Result` there is no `?`, so no failure in here can
//! reach the binary's error arm and turn a clean run into exit 2. Every internal
//! failure is logged to stderr and swallowed.
//!
//! **`col`/`endColumn` are deliberately never emitted.** [`Item::version_col_start`]
//! and `version_col_end` are *byte* offsets, and GitHub counts columns in
//! characters. They coincide only for an ASCII line; any earlier non-ASCII byte
//! silently shifts the highlight. A silently wrong column is worse than none —
//! the diff highlights the whole line regardless, so the payoff is zero.
//!
//! [cmd]: https://docs.github.com/actions/reference/workflow-commands-for-github-actions
//! [`Item::version_col_start`]: dependable_fetch::Item::version_col_start

use std::cmp::Ordering;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use dependable_fetch::core::result::Advisory;
use dependable_fetch::{CheckResult, DependencyStatus};

use crate::cli::AnnotationMode;
use crate::output::{ManifestReport, Summary, current_display, latest_display};

/// How many annotations of one level are emitted before the rest are elided.
///
/// GitHub renders at most ten `error` and ten `warning` annotations per step;
/// emitting more is not an error, they are simply never shown. Self-capping
/// keeps the log honest about what the reader will actually see.
pub const MAX_ANNOTATIONS_PER_LEVEL: usize = 10;

/// How many rows one job-summary table may carry.
///
/// Applied before the byte budget so a five-thousand-dependency monorepo
/// produces something readable long before size matters.
pub const MAX_ROWS_PER_TABLE: usize = 100;

/// GitHub's documented per-step job-summary size limit, in bytes.
pub const SUMMARY_LIMIT: usize = 1_048_576;

/// Bytes held back from [`SUMMARY_LIMIT`] as a safety margin.
pub const SUMMARY_MARGIN: usize = 4_096;

/// The annotation levels GitHub renders, in descending severity.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Level {
    Error,
    Warning,
    Notice,
}

impl Level {
    /// The workflow-command name.
    fn token(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warning => "warning",
            Level::Notice => "notice",
        }
    }

    /// The `title=` property shared by every annotation at this level.
    fn title(self) -> &'static str {
        match self {
            Level::Error => "dependable: vulnerable dependency",
            Level::Warning => "dependable: outdated dependency",
            Level::Notice => "dependable: dependency could not be checked",
        }
    }

    /// How the elision note names the findings at this level.
    fn noun(self) -> &'static str {
        match self {
            Level::Error => "vulnerable",
            Level::Warning => "outdated",
            Level::Notice => "unresolved",
        }
    }
}

/// The level a status is annotated at, or `None` when it is not annotated.
///
/// `PatchAvailable` is deliberately excluded: a patch-level bump inside the
/// declared constraint is noise on a pull request. It still appears in the table
/// and in the job summary's totals.
///
/// Levels are independent of `--fail-on`. Deriving the level from whether a
/// finding trips the gate would make a vulnerability a warning under
/// `--fail-on outdated`, and would silence everything under `--fail-on none`.
fn level_of(status: &DependencyStatus) -> Option<Level> {
    match status {
        DependencyStatus::Vulnerable => Some(Level::Error),
        DependencyStatus::Outdated | DependencyStatus::UpdateAvailable => Some(Level::Warning),
        DependencyStatus::Error(_) => Some(Level::Notice),
        _ => None,
    }
}

/// One annotatable result, paired with the manifest location it was found in.
struct Finding<'a> {
    result: &'a CheckResult,
    /// Repository-relative, forward-slashed path, or `None` when the manifest
    /// lies outside the repository and no honest `file=` can be written.
    file: Option<String>,
    /// What to show a human: [`Self::file`] when there is one, else the
    /// absolute path.
    manifest: String,
}

/// Escape a workflow-command **message** (everything after `::`).
///
/// `%`, CR and LF only — `:` and `,` are left alone, because a message is
/// terminated by end-of-line, not by a delimiter. Advisory summaries routinely
/// contain both, and escaping them here would render literal `%3A`/`%2C` in the
/// annotation.
///
/// A single pass over the input is what makes the ordering bug unrepresentable:
/// with a chained `str::replace`, the `%` written by a `\n` → `%0A` replacement
/// would be re-escaped into `%250A` by a later `%` pass.
#[must_use]
fn escape_data(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a workflow-command **property value** (the right-hand side of
/// `file=`, `line=`, `title=`).
///
/// The three [`escape_data`] replacements plus `:` → `%3A` and `,` → `%2C`,
/// which do terminate a property list. A Windows path `C:\proj` becomes
/// `C%3A\proj`.
#[must_use]
fn escape_property(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            ':' => out.push_str("%3A"),
            ',' => out.push_str("%2C"),
            other => out.push(other),
        }
    }
    out
}

/// Normalise a path lexically: drop `.`, resolve `..` against the preceding
/// component, and collapse redundant separators.
///
/// Deliberately *not* `Path::canonicalize`: that resolves symlinks, and a macOS
/// runner's workspace and `TMPDIR` differ in exactly that way, so canonicalising
/// both sides can fail to strip a prefix that is genuinely there.
#[must_use]
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The repository-relative, forward-slashed path for `manifest`, or `None`.
///
/// `None` means no `file=`/`line=`/`endLine=` may be written at all: GitHub
/// defaults an absent `file` to `.github`, so a *wrong* path would attach the
/// finding to an unrelated file. A fileless annotation beats a misattributed one.
#[must_use]
fn relative_file(manifest: &Path, workspace: Option<&Path>, cwd: Option<&Path>) -> Option<String> {
    let absolute = if manifest.is_absolute() {
        manifest.to_path_buf()
    } else {
        cwd.map_or_else(|| manifest.to_path_buf(), |dir| dir.join(manifest))
    };
    let absolute = lexical_normalize(&absolute);

    for base in [workspace, cwd].into_iter().flatten() {
        let base = lexical_normalize(base);
        if let Ok(rest) = absolute.strip_prefix(&base)
            && let Some(text) = rest.to_str()
            && !text.is_empty()
        {
            return Some(text.replace('\\', "/"));
        }
    }
    None
}

/// Group every annotatable result by level, each list in emission order.
fn group<'a>(
    reports: &'a [ManifestReport],
    workspace: Option<&Path>,
    cwd: Option<&Path>,
) -> [Vec<Finding<'a>>; 3] {
    let mut grouped: [Vec<Finding<'a>>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for report in reports {
        let file = relative_file(&report.path, workspace, cwd);
        let manifest = file
            .clone()
            .unwrap_or_else(|| report.path.display().to_string());
        for result in &report.results {
            let Some(level) = level_of(&result.status) else {
                continue;
            };
            let slot = match level {
                Level::Error => 0,
                Level::Warning => 1,
                Level::Notice => 2,
            };
            grouped[slot].push(Finding {
                result,
                file: file.clone(),
                manifest: manifest.clone(),
            });
        }
    }
    grouped[0].sort_by(cmp_error);
    grouped[1].sort_by(cmp_warning);
    grouped[2].sort_by(cmp_notice);
    grouped
}

/// Compare two `Option<f64>` so the larger score sorts first and `None` sorts
/// last. `f64::total_cmp` keeps this a total order even for exotic values.
fn cmp_score_desc(a: Option<f64>, b: Option<f64>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => y.total_cmp(&x),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// The last tie-breakers every level shares, making each ordering *total* — and
/// so the whole output byte-stable for the same input.
fn cmp_location(a: &Finding<'_>, b: &Finding<'_>) -> Ordering {
    a.manifest
        .cmp(&b.manifest)
        .then_with(|| a.result.item.name.cmp(&b.result.item.name))
        .then_with(|| a.result.item.version_line.cmp(&b.result.item.version_line))
        .then_with(|| {
            a.result
                .item
                .version_constraint
                .cmp(&b.result.item.version_constraint)
        })
}

/// Worst first: CVSS score, then severity band, then how many advisories hit.
fn cmp_error(a: &Finding<'_>, b: &Finding<'_>) -> Ordering {
    cmp_score_desc(a.result.max_cvss(), b.result.max_cvss())
        .then_with(|| b.result.max_severity().cmp(&a.result.max_severity()))
        .then_with(|| {
            b.result
                .current_vulnerabilities
                .len()
                .cmp(&a.result.current_vulnerabilities.len())
        })
        .then_with(|| cmp_location(a, b))
}

/// `Outdated` (outside the constraint) before `UpdateAvailable` (inside it).
///
/// Deliberately *not* "how many major versions behind": that would need semver
/// re-parsing here for a marginal gain in ordering quality.
fn cmp_warning(a: &Finding<'_>, b: &Finding<'_>) -> Ordering {
    fn rank(status: &DependencyStatus) -> u8 {
        match status {
            DependencyStatus::Outdated => 0,
            _ => 1,
        }
    }
    rank(&a.result.status)
        .cmp(&rank(&b.result.status))
        .then_with(|| cmp_location(a, b))
}

/// Errors carry no severity, so location alone orders them.
fn cmp_notice(a: &Finding<'_>, b: &Finding<'_>) -> Ordering {
    cmp_location(a, b)
}

/// The advisory that best represents a result: the highest-scoring one, else the
/// first recorded.
fn top_advisory(result: &CheckResult) -> Option<&Advisory> {
    result
        .advisories
        .iter()
        .max_by(|a, b| cmp_score_desc(b.severity.score, a.severity.score))
}

/// The version that fixes a vulnerable result, if one is known.
fn fixed_version(result: &CheckResult) -> Option<String> {
    top_advisory(result)
        .and_then(|advisory| advisory.fixed_versions.first().cloned())
        .or_else(|| result.latest_compatible.clone())
}

/// `critical (9.8)`, `high`, or `unrated` — never a fabricated `0.0`.
fn severity_display(result: &CheckResult) -> String {
    match result.max_severity() {
        Some(band) => match result.max_cvss() {
            Some(score) => format!("{} ({score:.1})", band.label()),
            None => band.label().to_string(),
        },
        None => "unrated".to_string(),
    }
}

/// The annotation body for one finding, before escaping.
fn message(finding: &Finding<'_>, level: Level) -> String {
    let result = finding.result;
    let name = &result.item.name;
    let current = current_display(result);
    let mut body = match level {
        Level::Error => {
            let mut text = format!(
                "{name} {current} is vulnerable ({})",
                severity_display(result)
            );
            if !result.current_vulnerabilities.is_empty() {
                text.push_str(&format!(": {}", result.current_vulnerabilities.join(", ")));
            }
            if let Some(advisory) = top_advisory(result)
                && advisory.title() != advisory.id
            {
                text.push_str(&format!(" — {}", advisory.title()));
            }
            if let Some(fixed) = fixed_version(result) {
                text.push_str(&format!("; fixed in {fixed}"));
            }
            text
        }
        Level::Warning => format!(
            "{name} {current} is {}; latest is {}",
            result.status.label(),
            latest_display(result)
        ),
        Level::Notice => match &result.status {
            DependencyStatus::Error(why) => format!("{name} could not be checked: {why}"),
            other => format!("{name}: {}", other.label()),
        },
    };
    // With no `file=` the annotation floats free of the diff, so the path has to
    // be in the text or the reader cannot tell which manifest is meant.
    if finding.file.is_none() {
        body = format!("{} — {body}", finding.manifest);
    }
    body
}

/// Render one finding as a workflow command.
fn command(finding: &Finding<'_>, level: Level) -> String {
    let mut properties = Vec::new();
    if let Some(file) = &finding.file {
        properties.push(format!("file={}", escape_property(file)));
        // Same rule as the columns: a location this file cannot support is worse than
        // none. An inherited dependency's version lives in the workspace root, so its
        // recorded line is a zero that would annotate line 1 of the wrong file.
        if finding.result.item.is_rewritable() {
            // Zero-indexed in the parser, one-based in the command.
            let line = finding.result.item.version_line + 1;
            properties.push(format!("line={line}"));
            properties.push(format!("endLine={line}"));
        }
    }
    properties.push(format!("title={}", escape_property(level.title())));
    format!(
        "::{} {}::{}",
        level.token(),
        properties.join(","),
        escape_data(&message(finding, level))
    )
}

/// The plain-text note that stands in for the annotations a level had to drop.
///
/// Deliberately *not* itself an annotation: spending one of ten rendered slots
/// to say "there are more" is a bad trade. The full list lives in the job
/// summary, which is not capped at ten.
fn elision(level: Level, omitted: usize) -> String {
    let noun = if omitted == 1 {
        "dependency"
    } else {
        "dependencies"
    };
    format!(
        "dependable: {omitted} more {} {noun} not annotated (GitHub renders at most {} {} annotations per step); see the job summary.",
        level.noun(),
        MAX_ANNOTATIONS_PER_LEVEL,
        level.token()
    )
}

/// Every line to write to stderr: the workflow commands, plus a plain elision
/// note for each level that had to be capped.
///
/// Pure — `workspace` and `cwd` are passed in rather than read from the
/// environment, which is what makes the ordering and escaping testable.
#[must_use]
pub fn annotations(
    reports: &[ManifestReport],
    workspace: Option<&Path>,
    cwd: Option<&Path>,
) -> Vec<String> {
    let grouped = group(reports, workspace, cwd);
    let mut lines = Vec::new();
    for (slot, level) in [Level::Error, Level::Warning, Level::Notice]
        .into_iter()
        .enumerate()
    {
        let findings = &grouped[slot];
        for finding in findings.iter().take(MAX_ANNOTATIONS_PER_LEVEL) {
            lines.push(command(finding, level));
        }
        if findings.len() > MAX_ANNOTATIONS_PER_LEVEL {
            lines.push(elision(level, findings.len() - MAX_ANNOTATIONS_PER_LEVEL));
        }
    }
    lines
}

/// Make `text` safe inside a Markdown table cell.
fn cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '|' => out.push_str("\\|"),
            '\r' | '\n' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// A table cell wrapped in backticks, with any backtick in the content dropped
/// so the wrapping cannot be broken from inside.
fn code_cell(text: &str) -> String {
    let inner: String = cell(text).chars().filter(|ch| *ch != '`').collect();
    format!("`{inner}`")
}

/// One Markdown table, kept structured so truncation can drop whole rows.
struct Table {
    heading: String,
    columns: &'static str,
    divider: &'static str,
    rows: Vec<String>,
    notes: Vec<String>,
}

impl Table {
    /// Append this table to `out`, keeping at most `keep` rows. Writes nothing
    /// when `keep` is zero.
    fn write(&self, out: &mut String, keep: usize) {
        if keep == 0 {
            return;
        }
        let _ = writeln!(out, "{}\n", self.heading);
        let _ = writeln!(out, "{}", self.columns);
        let _ = writeln!(out, "{}", self.divider);
        for row in self.rows.iter().take(keep) {
            let _ = writeln!(out, "{row}");
        }
        out.push('\n');
        for note in &self.notes {
            let _ = writeln!(out, "{note}\n");
        }
    }
}

/// `n singular` / `n plural`, since English will not derive one from the other.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// The totals line, from the same [`Summary`] the table renderer uses.
fn totals(reports: &[ManifestReport]) -> String {
    let summary = Summary::of(reports);
    format!(
        "{} checked — {} vulnerable, {} outdated, {}, {} up to date.",
        counted(summary.total, "dependency", "dependencies"),
        summary.vulnerable,
        summary.outdated + summary.update_available,
        counted(summary.error, "error", "errors"),
        summary.up_to_date + summary.patch_available
    )
}

/// The advisory cell: a Markdown link where there is a canonical page, else the
/// bare advisory IDs.
fn advisory_cell(result: &CheckResult) -> String {
    if let Some(advisory) = top_advisory(result) {
        let title = cell(advisory.title());
        return match advisory.advisory_url() {
            Some(url) => format!("[{title}]({})", cell(url)),
            None => title,
        };
    }
    if result.current_vulnerabilities.is_empty() {
        "—".to_string()
    } else {
        cell(&result.current_vulnerabilities.join(", "))
    }
}

/// Build the three tables, already ordered and row-capped.
fn tables(grouped: &[Vec<Finding<'_>>; 3]) -> Vec<Table> {
    let mut out = Vec::new();
    let specs: [(Level, &str, &'static str, &'static str); 3] = [
        (
            Level::Error,
            "Vulnerable",
            "| Package | Manifest | Current | Fixed | Severity | Advisory |",
            "| --- | --- | --- | --- | --- | --- |",
        ),
        (
            Level::Warning,
            "Outdated",
            "| Package | Manifest | Current | Latest | Status |",
            "| --- | --- | --- | --- | --- |",
        ),
        (
            Level::Notice,
            "Errors",
            "| Package | Manifest | Error |",
            "| --- | --- | --- |",
        ),
    ];

    for (slot, (level, name, columns, divider)) in specs.into_iter().enumerate() {
        let findings = &grouped[slot];
        if findings.is_empty() {
            continue;
        }
        let rows: Vec<String> = findings
            .iter()
            .take(MAX_ROWS_PER_TABLE)
            .map(|finding| {
                let result = finding.result;
                let package = code_cell(&result.item.name);
                let manifest = code_cell(&finding.manifest);
                match level {
                    Level::Error => format!(
                        "| {package} | {manifest} | {} | {} | {} | {} |",
                        code_cell(&current_display(result)),
                        code_cell(&fixed_version(result).unwrap_or_else(|| "—".to_string())),
                        cell(&severity_display(result)),
                        advisory_cell(result),
                    ),
                    Level::Warning => format!(
                        "| {package} | {manifest} | {} | {} | {} |",
                        code_cell(&current_display(result)),
                        code_cell(&latest_display(result)),
                        cell(result.status.label()),
                    ),
                    Level::Notice => format!(
                        "| {package} | {manifest} | {} |",
                        match &result.status {
                            DependencyStatus::Error(why) => cell(why),
                            other => cell(other.label()),
                        }
                    ),
                }
            })
            .collect();

        let mut notes = Vec::new();
        if findings.len() > MAX_ROWS_PER_TABLE {
            notes.push(format!(
                "_… {} more not shown (at most {MAX_ROWS_PER_TABLE} rows per table)._",
                findings.len() - MAX_ROWS_PER_TABLE
            ));
        }
        if findings.len() > MAX_ANNOTATIONS_PER_LEVEL {
            notes.push(format!(
                "_{} of these were not annotated: GitHub renders at most {MAX_ANNOTATIONS_PER_LEVEL} {} annotations per step._",
                findings.len() - MAX_ANNOTATIONS_PER_LEVEL,
                level.token()
            ));
        }

        out.push(Table {
            heading: format!("### {name} ({})", findings.len()),
            columns,
            divider,
            rows,
            notes,
        });
    }
    out
}

/// Assemble the document with `keep[i]` rows of table `i` and, when `omitted` is
/// non-zero, a closing note saying how many rows the size limit cost.
fn assemble(head: &str, tables: &[Table], keep: &[usize], omitted: usize) -> String {
    let mut out = String::from(head);
    for (table, keep) in tables.iter().zip(keep) {
        table.write(&mut out, *keep);
    }
    if omitted > 0 {
        let _ = writeln!(
            out,
            "_… {omitted} more omitted (step summary size limit)._\n"
        );
    }
    out
}

/// The job-summary Markdown for `reports`, at most `budget` bytes.
///
/// Returns an empty string when even the heading does not fit — the caller warns
/// and writes nothing rather than appending a fragment.
///
/// Truncation drops **whole table rows** from the end, in reverse priority
/// order, which makes a cut in the middle of a line, or of a UTF-8 sequence,
/// impossible by construction.
#[must_use]
pub fn summary_markdown(
    reports: &[ManifestReport],
    budget: usize,
    workspace: Option<&Path>,
    cwd: Option<&Path>,
) -> String {
    let grouped = group(reports, workspace, cwd);
    let head = format!("## dependable\n\n{}\n\n", totals(reports));
    let tables = tables(&grouped);

    if tables.is_empty() {
        // An empty summary is indistinguishable from a step that never ran, so
        // say so explicitly.
        let out = format!("{head}No outdated or vulnerable dependencies found.\n\n");
        return if out.len() <= budget {
            out
        } else {
            String::new()
        };
    }

    let mut keep: Vec<usize> = tables.iter().map(|table| table.rows.len()).collect();
    let mut omitted = 0;
    loop {
        let out = assemble(&head, &tables, &keep, omitted);
        if out.len() <= budget {
            return out;
        }
        let Some(index) = keep.iter().rposition(|count| *count > 0) else {
            return String::new();
        };
        keep[index] -= 1;
        omitted += 1;
    }
}

/// Whether the GitHub side channels are on.
///
/// `auto` is on exactly when `GITHUB_ACTIONS` is `true`, which is what the
/// runner sets. `always` is what makes the behaviour reproducible locally and
/// testable without faking a runner.
fn enabled(mode: AnnotationMode) -> bool {
    match mode {
        AnnotationMode::Always => true,
        AnnotationMode::Never => false,
        AnnotationMode::Auto => {
            std::env::var("GITHUB_ACTIONS").is_ok_and(|value| value.eq_ignore_ascii_case("true"))
        }
    }
}

/// Append the job summary to `GITHUB_STEP_SUMMARY`, if it is set.
///
/// Absent variable → silent no-op: the variable exists only under the runner, so
/// its absence is simply "not in CI". Anything else that goes wrong is a
/// `warning:` on stderr and nothing more.
fn write_summary(reports: &[ManifestReport], workspace: Option<&Path>, cwd: Option<&Path>) {
    let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    // Append rather than truncate: summaries are per-step, the toolkit appends,
    // and appending means two `dependable` runs in one step concatenate instead
    // of one clobbering the other.
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(why) => {
            eprintln!("warning: could not write GitHub step summary: {why}");
            return;
        }
    };
    // The limit applies to the file, not to this run's contribution — which is
    // precisely why the existing length has to be measured.
    let existing = usize::try_from(file.metadata().map(|meta| meta.len()).unwrap_or(0))
        .unwrap_or(SUMMARY_LIMIT);
    let budget = SUMMARY_LIMIT
        .saturating_sub(existing)
        .saturating_sub(SUMMARY_MARGIN);

    let markdown = summary_markdown(reports, budget, workspace, cwd);
    if markdown.is_empty() {
        eprintln!("warning: GitHub step summary is at its size limit; nothing written");
        return;
    }
    if let Err(why) = file.write_all(markdown.as_bytes()) {
        eprintln!("warning: could not write GitHub step summary: {why}");
    }
}

/// Write the annotations and the job summary for `reports`.
///
/// Returns `()`, never a `Result` — see the module documentation. Exit codes are
/// unaffected by anything that happens in here.
pub fn emit(reports: &[ManifestReport], mode: AnnotationMode) {
    if !enabled(mode) {
        return;
    }
    let workspace = std::env::var_os("GITHUB_WORKSPACE").map(PathBuf::from);
    let cwd = std::env::current_dir().ok();

    let lines = annotations(reports, workspace.as_deref(), cwd.as_deref());
    if !lines.is_empty() {
        // One lock for the whole batch: a workflow command is a whole line, so
        // interleaved output would corrupt it.
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        for line in &lines {
            let _ = writeln!(handle, "{line}");
        }
        let _ = handle.flush();
    }

    write_summary(reports, workspace.as_deref(), cwd.as_deref());
}

#[cfg(test)]
mod tests {
    use dependable_fetch::core::parse;
    use dependable_fetch::core::result::{AdvisoryReference, AdvisorySeverity, ReferenceKind};
    use dependable_fetch::{Ecosystem, Item, ManifestKind, PackageSource};

    use super::*;

    /// A real [`Item`], obtained the only way another crate can — `Item` is
    /// `#[non_exhaustive]` and has no constructor, so it is parsed out of a
    /// manifest and then moved to the line the test wants.
    fn item(name: &str, line: usize) -> Item {
        let manifest = format!("[dependencies]\n{name} = \"1.0\"\n");
        let mut item = parse(ManifestKind::CargoToml, &manifest)
            .expect("parse the fixture manifest")
            .items
            .into_iter()
            .next()
            .expect("one dependency");
        item.version_line = line;
        item.locked_version = Some("1.0.0".to_string());
        item
    }

    fn vulnerable(name: &str, line: usize, score: f64) -> CheckResult {
        let advisory = Advisory::new(format!("RUSTSEC-2020-{line:04}"))
            .with_summary(format!("{name}: use after free, plus a comma"))
            .with_severity(AdvisorySeverity::from_score(score))
            .with_fixed_versions(vec!["2.0.0".to_string()])
            .with_references(vec![AdvisoryReference::new(
                ReferenceKind::Advisory,
                "https://osv.dev/x",
            )]);
        let mut result = CheckResult::new(item(name, line), DependencyStatus::Vulnerable);
        result.current_vulnerabilities = vec![advisory.id.clone()];
        result.advisories = vec![advisory];
        result
    }

    fn report(path: &str, results: Vec<CheckResult>) -> ManifestReport {
        ManifestReport {
            path: PathBuf::from(path),
            ecosystem: Ecosystem::Rust,
            results,
        }
    }

    fn workspace() -> PathBuf {
        PathBuf::from("/w")
    }

    fn lines_for(reports: &[ManifestReport]) -> Vec<String> {
        annotations(reports, Some(&workspace()), Some(Path::new("/w")))
    }

    #[test]
    fn escape_data_handles_percent_and_newlines_but_not_delimiters() {
        assert_eq!(escape_data("100% \n done"), "100%25 %0A done");
        assert_eq!(escape_data("a,b:c"), "a,b:c");
        assert_eq!(escape_data("\r\n"), "%0D%0A");
    }

    #[test]
    fn escape_data_escapes_percent_before_the_others() {
        // Literal text, not an already-escaped newline: a chained `replace`
        // would produce `%250A` only by accident, and `%0A` -> `%250A` here is
        // the proof the single pass never re-escapes its own output.
        assert_eq!(escape_data("%0A"), "%250A");
        assert_eq!(escape_data("%\n"), "%25%0A");
    }

    #[test]
    fn escape_property_also_escapes_the_delimiters() {
        assert_eq!(escape_property("a,b:c"), "a%2Cb%3Ac");
        assert_eq!(escape_property("C:\\proj"), "C%3A\\proj");
        assert_eq!(escape_property("%0A"), "%250A");
    }

    #[test]
    fn the_message_keeps_colons_and_commas_the_properties_escape() {
        let reports = vec![report("/w/Cargo.toml", vec![vulnerable("serde", 3, 9.8)])];
        let line = &lines_for(&reports)[0];
        let (properties, message) = line
            .strip_prefix("::error ")
            .expect("an error command")
            .split_once("::")
            .expect("a message");

        assert!(properties.contains("title=dependable%3A vulnerable dependency"));
        assert!(!properties.contains("dependable: "));
        // The same characters, unescaped, on the other side of the `::`.
        assert!(
            message.contains("use after free, plus a comma"),
            "{message}"
        );
        assert!(
            message.contains("is vulnerable (critical (9.8))"),
            "{message}"
        );
        assert!(
            !message.contains("%3A") && !message.contains("%2C"),
            "{message}"
        );
    }

    #[test]
    fn version_line_is_rebased_to_one() {
        let reports = vec![report(
            "/w/Cargo.toml",
            vec![vulnerable("a", 0, 9.0), vulnerable("b", 11, 9.0)],
        )];
        let lines = lines_for(&reports);
        assert!(
            lines.iter().any(|l| l.contains("line=1,endLine=1")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("line=12,endLine=12")),
            "{lines:?}"
        );
    }

    /// A workspace member's `dep.workspace = true` is checkable — so it does reach the
    /// annotator — but its version string is in the root manifest. Annotating line 1 of
    /// the member would point a reviewer at the wrong line of the right file, which is
    /// the same trade the columns already lose.
    #[test]
    fn an_inherited_dependency_is_annotated_without_a_line() {
        let mut result = vulnerable("serde", 0, 9.8);
        result.item.source = PackageSource::Inherited;
        result.item.version_constraint = "1.0.100".to_string();
        assert!(result.item.is_checkable() && !result.item.is_rewritable());

        let reports = vec![report("/w/crates/app/Cargo.toml", vec![result])];
        let lines = lines_for(&reports);

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("file=crates/app/Cargo.toml"), "{lines:?}");
        assert!(!lines[0].contains("line="), "{lines:?}");
        assert!(!lines[0].contains("endLine="), "{lines:?}");
    }

    #[test]
    fn columns_are_never_emitted() {
        let mut result = vulnerable("serde", 3, 9.8);
        result.item.version_col_start = 9;
        result.item.version_col_end = 14;
        let reports = vec![report("/w/Cargo.toml", vec![result])];
        for line in lines_for(&reports) {
            assert!(!line.contains("col="), "{line}");
            assert!(!line.contains("endColumn="), "{line}");
        }
    }

    #[test]
    fn paths_are_made_workspace_relative() {
        assert_eq!(
            relative_file(
                Path::new("/w/crates/a/Cargo.toml"),
                Some(Path::new("/w")),
                None
            )
            .as_deref(),
            Some("crates/a/Cargo.toml")
        );
        // `.` components are dropped and `..` resolved lexically.
        assert_eq!(
            relative_file(
                Path::new("./crates/./b/../a/Cargo.toml"),
                Some(Path::new("/w")),
                Some(Path::new("/w"))
            )
            .as_deref(),
            Some("crates/a/Cargo.toml")
        );
        // The workspace wins over the working directory.
        assert_eq!(
            relative_file(
                Path::new("/w/a/Cargo.toml"),
                Some(Path::new("/w")),
                Some(Path::new("/w/a"))
            )
            .as_deref(),
            Some("a/Cargo.toml")
        );
        // Outside both: no honest relative path exists.
        assert_eq!(
            relative_file(
                Path::new("/elsewhere/Cargo.toml"),
                Some(Path::new("/w")),
                Some(Path::new("/w"))
            ),
            None
        );
    }

    #[test]
    fn a_manifest_outside_the_repository_gets_no_file_property() {
        let reports = vec![report(
            "/elsewhere/Cargo.toml",
            vec![vulnerable("serde", 3, 9.8)],
        )];
        let line = &lines_for(&reports)[0];
        assert!(!line.contains("file="), "{line}");
        assert!(!line.contains("line="), "{line}");
        assert!(!line.contains("endLine="), "{line}");
        // The path has to survive somewhere, so it goes in the message.
        assert!(line.contains("/elsewhere/Cargo.toml — serde"), "{line}");
    }

    #[test]
    fn backslashes_become_forward_slashes() {
        let file = relative_file(
            Path::new("/w/crates\\a\\Cargo.toml"),
            Some(Path::new("/w")),
            None,
        );
        assert_eq!(file.as_deref(), Some("crates/a/Cargo.toml"));
    }

    #[test]
    fn errors_are_capped_at_ten_worst_first_with_a_plain_elision_note() {
        let results: Vec<CheckResult> = (0u8..25)
            .map(|i| vulnerable(&format!("pkg{i:02}"), usize::from(i), f64::from(i) / 3.0))
            .collect();
        let reports = vec![report("/w/Cargo.toml", results)];
        let lines = lines_for(&reports);

        let commands: Vec<&String> = lines.iter().filter(|l| l.starts_with("::error")).collect();
        assert_eq!(commands.len(), MAX_ANNOTATIONS_PER_LEVEL);
        // 24 scores highest, then 23, …
        assert!(commands[0].contains("pkg24"), "{:?}", commands[0]);
        assert!(commands[9].contains("pkg15"), "{:?}", commands[9]);

        let notes: Vec<&String> = lines.iter().filter(|l| !l.starts_with("::")).collect();
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("dependable: 15 more vulnerable"),
            "{:?}",
            notes[0]
        );
    }

    #[test]
    fn output_is_byte_stable_for_the_same_input() {
        let mut results = vec![
            vulnerable("zzz", 4, 5.0),
            vulnerable("aaa", 4, 5.0),
            CheckResult::new(item("mmm", 2), DependencyStatus::Outdated),
            CheckResult::new(item("bbb", 1), DependencyStatus::UpdateAvailable),
            CheckResult::new(item("ccc", 3), DependencyStatus::Error("boom".into())),
        ];
        let reports = vec![report("/w/Cargo.toml", results.clone())];
        results.reverse();
        let reversed = vec![report("/w/Cargo.toml", results)];

        let first = lines_for(&reports);
        assert_eq!(first, lines_for(&reports));
        // A total order means the input order cannot change the output.
        assert_eq!(first, lines_for(&reversed));
        assert_eq!(first.len(), 5);
    }

    #[test]
    fn patch_available_is_not_annotated() {
        let reports = vec![report(
            "/w/Cargo.toml",
            vec![
                CheckResult::new(item("a", 1), DependencyStatus::PatchAvailable),
                CheckResult::new(item("b", 2), DependencyStatus::UpToDate),
                CheckResult::new(item("c", 3), DependencyStatus::Local),
            ],
        )];
        assert!(lines_for(&reports).is_empty());
    }

    #[test]
    fn a_clean_run_still_writes_a_summary() {
        let reports = vec![report(
            "/w/Cargo.toml",
            vec![CheckResult::new(item("a", 1), DependencyStatus::UpToDate)],
        )];
        let markdown = summary_markdown(
            &reports,
            SUMMARY_LIMIT,
            Some(Path::new("/w")),
            Some(Path::new("/w")),
        );
        assert!(markdown.starts_with("## dependable\n"));
        assert!(markdown.contains("1 dependency checked"), "{markdown}");
        assert!(markdown.contains("No outdated or vulnerable dependencies found."));
    }

    #[test]
    fn the_summary_tabulates_each_level() {
        let reports = vec![report(
            "/w/Cargo.toml",
            vec![
                vulnerable("serde", 3, 9.8),
                CheckResult::new(item("tokio", 4), DependencyStatus::Outdated),
                CheckResult::new(item("time", 5), DependencyStatus::Error("boom".into())),
            ],
        )];
        let markdown = summary_markdown(
            &reports,
            SUMMARY_LIMIT,
            Some(Path::new("/w")),
            Some(Path::new("/w")),
        );
        assert!(markdown.contains("### Vulnerable (1)"), "{markdown}");
        assert!(markdown.contains("### Outdated (1)"), "{markdown}");
        assert!(markdown.contains("### Errors (1)"), "{markdown}");
        assert!(markdown.contains("[serde: use after free, plus a comma](https://osv.dev/x)"));
        assert!(markdown.contains("critical (9.8)"));
        assert!(markdown.contains("`2.0.0`"));
    }

    #[test]
    fn the_summary_truncates_at_a_row_boundary_and_says_so() {
        let results: Vec<CheckResult> = (0u8..60)
            .map(|i| vulnerable(&format!("pkg{i:02}"), usize::from(i), f64::from(i) / 7.0))
            .collect();
        let reports = vec![report("/w/Cargo.toml", results)];
        let full = summary_markdown(
            &reports,
            SUMMARY_LIMIT,
            Some(Path::new("/w")),
            Some(Path::new("/w")),
        );
        let budget = full.len() / 2;
        let cut = summary_markdown(
            &reports,
            budget,
            Some(Path::new("/w")),
            Some(Path::new("/w")),
        );

        assert!(!cut.is_empty());
        assert!(cut.len() <= budget, "{} > {budget}", cut.len());
        assert!(
            cut.contains("more omitted (step summary size limit)"),
            "{cut}"
        );
        // Every table line is a whole row: row-granular truncation makes a
        // mid-line or mid-UTF-8 cut impossible.
        for line in cut.lines().filter(|l| l.starts_with("| `")) {
            assert!(line.ends_with('|'), "{line}");
        }
    }

    #[test]
    fn a_budget_that_cannot_hold_the_heading_yields_nothing() {
        let reports = vec![report("/w/Cargo.toml", vec![vulnerable("serde", 3, 9.8)])];
        assert!(
            summary_markdown(&reports, 4, Some(Path::new("/w")), Some(Path::new("/w"))).is_empty()
        );
    }

    #[test]
    fn table_cells_cannot_break_the_table() {
        assert_eq!(cell("a|b\nc"), "a\\|b c");
        assert_eq!(code_cell("a`b`c"), "`abc`");
    }
}
