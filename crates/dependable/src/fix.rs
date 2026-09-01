//! In-place version rewriting via recorded byte offsets.
//!
//! Every parser records the exact byte span of a dependency's version value, so
//! `--fix` is format-agnostic: it replaces that span in place, leaving
//! surrounding formatting and comments untouched. The leading operator/`v` prefix
//! is preserved (`^1.0` → `^1.5.0`, `v1.2.3` → `v1.5.0`) so a constraint's meaning
//! is not silently changed (e.g. an npm caret range is not turned into a pin).
//!
//! Preserving the operator is not enough on its own, because a constraint that
//! carried no operator is written back as a bare version — and what a bare
//! version means is an ecosystem question, not a string one. Cargo's `1.*` and
//! npm's `1.x` are the same shape and opposite calls: `1.0.219` is `^1.0.219` in
//! one and one release in the other. The manifest path answers it, via
//! [`Ecosystem::bare_version`]; see [`rewrite_constraint`].

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;

use anyhow::Context;
use dependable_fetch::CheckResult;
use dependable_fetch::core::{BareVersion, Ecosystem, ManifestKind};

/// A single applied (or would-be-applied) version change.
#[derive(Debug, Clone)]
pub struct FixRecord {
    pub name: String,
    pub from: String,
    pub to: String,
}

/// Why [`rewrite_constraint`] would not substitute a new version into a
/// constraint.
///
/// Carried out of the planner rather than recomputed, because the answer is only
/// live at the point the guard fires: reconstructing it later would mean a second
/// copy of every guard below, kept in step with this one by hope. It reaches the
/// user as the second half of a `note:` line — see [`DeclineReason::explain`] —
/// so a dependency `check` reports an update for and `fix` leaves alone says so
/// instead of vanishing into "everything is already up to date".
///
/// `#[non_exhaustive]`: match with a wildcard arm so a new guard is additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DeclineReason {
    /// A comma-separated range: Cargo's `>=1.0, <2.0`.
    CommaRange,
    /// A space- or `|`-separated range: `>=1.0.0 <2.0.0`, `^1 || ^2`.
    MultiClause,
    /// An `@` qualifier: a Composer stability flag (`@dev`, `^1.0@beta`) or an
    /// npm alias (`npm:pkg@1.0.0`).
    Qualifier,
    /// A dist-tag or channel name: `latest`, `next`.
    DistTag,
    /// A wildcard behind an operator (`^1.x`, `=1.*`), whose rewrite would not be
    /// a bare version at all.
    WildcardOperator,
    /// A wildcard in an ecosystem that reads a bare version as one release:
    /// npm's `"lodash": "1.x"`.
    WildcardPins,
    /// A wildcard in an ecosystem that reads a bare version as a minimum:
    /// NuGet's `1.*`, Gradle's `1.+`.
    WildcardUnbounds,
    /// A wildcard whose shape no bare version reproduces even where the bare
    /// reading is a caret: `*`, `1.2.*`, `1.+`.
    WildcardShape,
    /// A partial version, which is an X-range wherever a bare version is exact:
    /// npm's `"react": "16"`.
    PartialVersion,
}

impl DeclineReason {
    /// The clause that completes a `note:` line, reading on from
    /// "… is available, but ".
    ///
    /// Every reason says what the constraint *is*, not that a rule fired — the
    /// point of the note is to let the author decide whether to widen the
    /// constraint by hand, and a rule name would not help them do that.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::CommaRange => {
                "a comma-separated range has two bounds and one version cannot carry both"
            }
            Self::MultiClause => {
                "a space- or `||`-separated range has more than one clause and one version \
                 cannot carry them all"
            }
            Self::Qualifier => {
                "an `@` qualifier — a stability flag or an alias — describes the range, not the \
                 version"
            }
            Self::DistTag => "a dist-tag names a release channel, not a version",
            Self::WildcardOperator => {
                "an operator in front of a wildcard is a range the new version would not reproduce"
            }
            Self::WildcardPins => {
                "a wildcard already tracks new releases, and a bare version here would pin it to \
                 one"
            }
            Self::WildcardUnbounds => {
                "a wildcard already tracks new releases, and a bare version here would drop its \
                 upper bound"
            }
            Self::WildcardShape => {
                "a wildcard already tracks new releases, and no bare version covers the same range"
            }
            Self::PartialVersion => {
                "a partial version is an X-range that already tracks new releases"
            }
        }
    }
}

/// An update `check` reports that `fix` will not write.
///
/// The whole point of recording it: without one, a declined constraint and a
/// dependency with nothing to do are the same empty result, and `fix` answers
/// "everything is already up to date" to a manifest `check` just said had an
/// update waiting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Declined {
    /// The dependency's name.
    pub name: String,
    /// The constraint left in place, verbatim.
    pub constraint: String,
    /// The version that would have been written had the constraint allowed it.
    pub target: String,
    /// Why it was not.
    pub reason: DeclineReason,
}

/// A byte-range replacement within one line of the manifest.
struct Edit {
    line: usize,
    start: usize,
    end: usize,
    /// The text the span held when the plan was made.
    ///
    /// The span comes from a parse that happened before the network check, and the file
    /// is read again at write time. If anything moved in between — an editor auto-save, a
    /// `cargo add`, a concurrent `dependable fix` — the offsets now point somewhere else,
    /// and splicing into them corrupts the manifest. Checking the text first is what
    /// turns that into a refusal.
    expected: String,
    replacement: String,
}

/// A manifest rewrite that has been computed but not yet written.
pub struct PlannedFix {
    /// The manifest the rewrite applies to.
    pub path: std::path::PathBuf,
    /// The full new contents.
    updated: String,
    /// What changed, for reporting.
    pub records: Vec<FixRecord>,
    /// The updates this rewrite declined to make, and why — reported so `check`
    /// and `fix` do not appear to contradict each other.
    pub declined: Vec<Declined>,
}

/// Compute the rewrite for `manifest` without touching it.
///
/// Pinned (`=x.y.z`) deps are skipped unless `all` is set; multi-constraint forms
/// (containing `,`) are skipped because they can't be rewritten to a single
/// version.
///
/// Planning is separated from writing so a multi-manifest run can compute every rewrite
/// before it writes any. Writing as it went left the tree half-rewritten when the third
/// of five manifests failed, with no record of the two already changed.
///
/// # Errors
/// Returns an error if the manifest cannot be read, or if a recorded span no longer
/// holds the constraint it was planned against.
pub fn plan(manifest: &Path, results: &[CheckResult], all: bool) -> anyhow::Result<PlannedFix> {
    let content = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    // What a rewritten constraint *means* is an ecosystem question, and the file
    // name is where the answer is. `None` — a manifest discovery surfaced but
    // `detect` does not recognize — is not an error here: the rewrite still runs,
    // under the reading that declines the most (see [`rewrite_constraint`]).
    let ecosystem = ManifestKind::detect(manifest).map(ManifestKind::ecosystem);
    let (updated, records, declined) = plan_fixes(&content, results, all, ecosystem)
        .with_context(|| format!("rewriting {}", manifest.display()))?;
    Ok(PlannedFix {
        path: manifest.to_path_buf(),
        updated,
        records,
        declined,
    })
}

/// Write a planned rewrite, atomically.
///
/// The new contents go to a temporary file in the manifest's own directory and are
/// renamed over it, so a crash, a full disk, or a `SIGINT` leaves the original intact.
/// `fs::write` truncates first, which meant an interrupted write left a manifest empty
/// or half-written and no backup to recover from.
///
/// # Errors
/// Returns an error if the temporary file cannot be created, written, or renamed.
pub fn commit(planned: &PlannedFix) -> anyhow::Result<()> {
    if planned.records.is_empty() {
        return Ok(());
    }
    let directory = planned.path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(directory).with_context(|| {
        format!(
            "creating a temporary file beside {}",
            planned.path.display()
        )
    })?;
    temp.write_all(planned.updated.as_bytes())
        .with_context(|| format!("writing {}", planned.path.display()))?;
    // Flush to the filesystem before the rename, so the rename cannot publish a file
    // whose contents are still only in memory.
    temp.as_file()
        .sync_all()
        .with_context(|| format!("flushing {}", planned.path.display()))?;
    // A manifest is usually 0644 while a temporary file is 0600; preserve what was there.
    #[cfg(unix)]
    if let Ok(metadata) = std::fs::metadata(&planned.path) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = temp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(
                metadata.permissions().mode(),
            ));
    }
    temp.persist(&planned.path)
        .with_context(|| format!("replacing {}", planned.path.display()))?;
    Ok(())
}

/// Compute the rewritten manifest and the applied records from `content` and the
/// check `results`, with no filesystem IO (the file boundary lives in [`plan`]).
/// Format-agnostic: it edits each recorded version span in place, so JSON, YAML,
/// and TOML manifests are rewritten without reformatting.
///
/// `ecosystem` decides which constraints are safe to rewrite at all —
/// [`rewrite_constraint`] explains what turns on it — and `None` means the
/// manifest kind was not recognized, which is treated as the most restrictive
/// answer rather than as permission.
///
/// Returns the rewritten content, the changes made, and the changes *not* made:
/// every dependency with an update available whose constraint
/// [`rewrite_constraint`] declined. The third list exists because it cannot be
/// recovered afterwards — the caller would have to redo the rewritability,
/// pinning, and target selection above *and* every guard inside
/// [`rewrite_constraint`] to learn what this loop already knew and threw away.
fn plan_fixes(
    content: &str,
    results: &[CheckResult],
    all: bool,
    ecosystem: Option<Ecosystem>,
) -> anyhow::Result<(String, Vec<FixRecord>, Vec<Declined>)> {
    let mut edits: Vec<Edit> = Vec::new();
    let mut records = Vec::new();
    let mut declined = Vec::new();
    for result in results {
        let item = &result.item;
        // `is_rewritable` and not `is_checkable`: a workspace member inheriting a
        // constraint is worth checking, but its version string lives in the root, so its
        // recorded span is `0/0/0` — which `apply_edits`' bounds check passes trivially,
        // splicing the new version into byte 0 of line 0 of this file.
        if !item.is_rewritable() {
            continue;
        }
        if !result.status.has_update() || (item.is_pinned() && !all) {
            continue;
        }

        let target = if all {
            result.latest_available.as_ref()
        } else {
            result.latest_compatible.as_ref()
        };
        let Some(target) = target else { continue };
        let new_constraint = match rewrite_constraint(&item.version_constraint, target, ecosystem) {
            Ok(new_constraint) => new_constraint,
            Err(reason) => {
                declined.push(Declined {
                    name: item.name.clone(),
                    constraint: item.version_constraint.clone(),
                    target: target.clone(),
                    reason,
                });
                continue;
            }
        };
        // Already at the target: nothing to write and nothing to say. Not a
        // decline — the constraint would have accepted the rewrite.
        if new_constraint == item.version_constraint {
            continue;
        }

        edits.push(Edit {
            line: item.version_line,
            start: item.version_col_start,
            end: item.version_col_end,
            expected: item.version_constraint.clone(),
            replacement: new_constraint.clone(),
        });
        records.push(FixRecord {
            name: item.name.clone(),
            from: item.version_constraint.clone(),
            to: new_constraint,
        });
    }

    let updated = if edits.is_empty() {
        content.to_string()
    } else {
        apply_edits(content, &edits)?
    };
    // One note per distinct decline: the same crate under `[dependencies]` and
    // `[dev-dependencies]` is one fact about one constraint, not two.
    declined.sort();
    declined.dedup();
    Ok((updated, records, declined))
}

/// Build a new constraint from `original`, preserving its leading operator/`v`
/// prefix and substituting `new_version`. Returns [`Err`] for the forms that
/// can't be rewritten without changing their meaning: a comma-separated range
/// (Cargo `>=1.0, <2.0`), a space-separated range (npm/pubspec `>=1.0.0 <2.0.0`),
/// a `||` alternation (`^1 || ^2`), a dist-tag (`latest`), anything carrying an
/// `@` (a Composer stability flag such as `@dev` or `^1.0@beta`, an npm alias
/// such as `npm:pkg@1.0.0`), and — depending on `ecosystem` — a wildcard (`*`,
/// `1.x`, `1.*`) or a partial version (npm `"16"`).
///
/// The error is a [`DeclineReason`] and not a bare `None`, because *which* guard
/// fired is the only thing that makes the resulting note actionable, and this is
/// the sole place that knows it. An `Option` return threw that away at the one
/// boundary where it was still free.
///
/// `ecosystem` is what the wildcard and partial-version guards turn on, because
/// both ask the same question: the rewrite writes the new version back bare, so
/// is a bare version in this ecosystem still the range the author had? `None`
/// means the manifest kind was not recognized; it is read as
/// [`BareVersion::Exact`], which declines strictly more than either other
/// reading, so an unknown manifest is never rewritten into something a known one
/// would have refused.
///
/// # Errors
/// Returns the [`DeclineReason`] for the first guard that refuses the rewrite.
fn rewrite_constraint(
    original: &str,
    new_version: &str,
    ecosystem: Option<Ecosystem>,
) -> Result<String, DeclineReason> {
    let trimmed = original.trim();
    if trimmed.contains(',') {
        return Err(DeclineReason::CommaRange);
    }
    const OP_CHARS: &[char] = &['^', '~', '>', '<', '=', '!', 'v', 'V', ' ', '\t'];
    let prefix: String = trimmed
        .chars()
        .take_while(|c| OP_CHARS.contains(c))
        .collect();
    // After the leading operator prefix, a further space or `|` means a second
    // clause (range upper bound or alternative) we'd silently drop — leave it be.
    let rest = &trimmed[prefix.len()..];
    if rest.contains([' ', '\t', '|']) {
        return Err(DeclineReason::MultiClause);
    }
    // An `@` never belongs to a version: it introduces a Composer stability flag
    // (`@dev`, `2.8.*@dev`, `^1.0@beta`) or an npm alias target (`npm:pkg@1.0.0`).
    // A stability flag qualifies the *range* — `@dev` alone means "any version, dev
    // stability" — and this layer cannot reconstruct it, so substituting a concrete
    // release drops the flag and, for a bare `@dev`, collapses the range to an exact
    // pin. That is the harm of #87, so take the same call already taken for a
    // dist-tag and decline.
    if rest.contains('@') {
        return Err(DeclineReason::Qualifier);
    }
    // A dist-tag / channel name (`latest`, `next`, `beta`, …) starts with a letter
    // once any operator prefix is removed — it names a channel, not a version
    // range, so it must never be pinned to a concrete version (npm D8).
    if rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(DeclineReason::DistTag);
    }

    let bare = ecosystem.map_or(BareVersion::Exact, Ecosystem::bare_version);

    if is_wildcard(rest) {
        // A wildcard (`*`, `1.x`, `1.*`, Gradle's `1.+`) is a range the author
        // chose, not a version. Substituting a concrete release preserves it in
        // exactly one situation: the constraint carries no operator, the wildcard
        // sits in the minor position, and the ecosystem reads the bare version we
        // write back as a caret range. Then `1.*` (`>=1.0.0, <2.0.0`) becomes
        // `1.0.219` (`>=1.0.219, <2.0.0`) — the floor is raised, which is what
        // `fix` does to every other constraint, and the author's upper bound
        // survives.
        //
        // Every other combination changes what the constraint admits (#87, #92):
        //
        // - [`BareVersion::Exact`] collapses the range to one release: npm's
        //   `"lodash": "1.x"` would become `"1.9.0"`, and Composer and Hex read a
        //   bare version the same way.
        // - [`BareVersion::Minimum`] loses the upper bound instead: NuGet's `1.*`
        //   is any 1.x resolved to the newest, while a bare `1.9.0` is `>= 1.9.0`
        //   resolved to the *oldest* — a different range and a different pick.
        //   Gradle's `1.+` against its `require` semantics is the same trade.
        // - A bare `*` is every version, and any concrete release confines it to
        //   one major — a narrowing even where the bare form is a caret.
        // - `1.2.*` is `>=1.2.0, <1.3.0`, and a caret over any 1.2.z release
        //   reaches to `<2.0.0` — a widening even where the bare form is a caret.
        // - An operator in front (`^1.x`, `=1.*`, Python's `==1.*`) means the
        //   result is not a bare version at all, so the caret reading that
        //   justifies the rewrite does not apply to it.
        //
        // The three conditions are checked in order of what the note should say,
        // not in the order they were written: an operator answers for the whole
        // constraint whatever the ecosystem reads a bare version as, and the
        // ecosystem's reading answers before the wildcard's shape because it is
        // the more specific harm.
        if !prefix.is_empty() {
            return Err(DeclineReason::WildcardOperator);
        }
        match bare {
            BareVersion::Exact => return Err(DeclineReason::WildcardPins),
            BareVersion::Minimum => return Err(DeclineReason::WildcardUnbounds),
            BareVersion::Caret => {}
            // A reading added since this was written. Decline, as every non-caret
            // reading already does, under the reason that names no particular
            // harm — inventing one for a reading this code has never seen would
            // be worse than saying only that the shapes do not correspond.
            _ => return Err(DeclineReason::WildcardShape),
        }
        if !is_minor_wildcard(rest) {
            return Err(DeclineReason::WildcardShape);
        }
    } else if bare == BareVersion::Exact && prefix.is_empty() && is_partial_version(rest) {
        // The same harm one wildcard character away. npm treats a partial version
        // as an X-range — `"react": "16"` is `16.x`, `"1.0"` is `1.0.x` — so
        // rewriting it to `"16.14.0"` pins a dependency that was tracking a line
        // of releases, with no `*` anywhere for `is_wildcard` to see.
        //
        // Guarded for every ecosystem that reads a bare version exactly, not just
        // npm. Composer normalizes a partial to a full version and Hex and pub
        // reject one outright, so there the rewrite would have been harmless — but
        // "harmless" is the whole claim being made, and declining costs a fix on a
        // constraint that already pins while a wrong `true` costs the author their
        // range. Cargo and NuGet keep the rewrite: `1.0` is `^1.0` and `>=1.0`
        // respectively, and raising the floor of either is exactly what `fix` is.
        return Err(DeclineReason::PartialVersion);
    }
    Ok(format!("{prefix}{new_version}"))
}

/// Whether `rest` — a wildcard constraint with its operator prefix already
/// stripped — is the one wildcard shape a caret reading reproduces: a numeric
/// major followed by a wildcard in the minor position, `1.*` or `1.x`.
///
/// Deliberately narrow. `*`, `1.2.*`, and NuGet's `1.0.0.*` are all wildcards
/// too, and a caret over a concrete release matches none of their ranges. The
/// wildcard character must be `*`, `x`, or `X`: Gradle's `+` is a prefix range
/// with its own resolution rules and no ecosystem that reads a bare version as a
/// caret accepts it.
fn is_minor_wildcard(rest: &str) -> bool {
    let mut segments = rest.split('.');
    let (Some(major), Some(minor), None) = (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    !major.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && matches!(minor, "*" | "x" | "X")
}

/// Whether `rest` — a constraint with its operator prefix already stripped, and
/// already known to hold no wildcard — names fewer components than a full
/// version: `16` or `1.0` rather than `1.0.0`.
///
/// Every component must be pure digits, which is what keeps the concrete forms
/// out: Python's `1!2.0` carries an epoch, semver build metadata and prereleases
/// put non-digits in the last component, and NuGet's `1.0.0.4` has four.
fn is_partial_version(rest: &str) -> bool {
    let segments: Vec<&str> = rest.split('.').collect();
    segments.len() < 3
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `rest` — a constraint with its leading operator prefix already
/// stripped, and already known to carry no `@` — floats over a range of versions
/// rather than naming one.
///
/// A wildcard segment is not always the whole dot-segment, so `*` and `+` are
/// matched by their leading character too: neither can legitimately begin a
/// version segment — semver build metadata and Go's `+incompatible` attach their
/// `+` to the end of a numeric segment (`0+incompatible`), never the start.
/// `x`/`X` stay an exact whole-segment match, because a letter *can* legitimately
/// lead a segment inside a prerelease or build identifier
/// (`1.0.0-alpha+exp.sha.5114f85`). A Composer stability flag (`2.8.*@dev`) needs
/// no handling here: `rewrite_constraint` declines every `@` form before asking.
fn is_wildcard(rest: &str) -> bool {
    rest.split('.')
        .any(|segment| matches!(segment, "x" | "X") || segment.starts_with(['*', '+']))
}

/// Apply byte-range edits to `content`, operating per line. Edits on the same
/// line are applied right-to-left so earlier offsets stay valid.
fn apply_edits(content: &str, edits: &[Edit]) -> anyhow::Result<String> {
    let mut by_line: HashMap<usize, Vec<&Edit>> = HashMap::new();
    for edit in edits {
        by_line.entry(edit.line).or_default().push(edit);
    }
    let mut out = String::with_capacity(content.len() + 16);
    for (idx, line) in content.split_inclusive('\n').enumerate() {
        let Some(line_edits) = by_line.get(&idx) else {
            out.push_str(line);
            continue;
        };
        let mut sorted = line_edits.clone();
        sorted.sort_by_key(|edit| std::cmp::Reverse(edit.start));
        let mut s = line.to_string();
        for edit in sorted {
            // A bounds check alone only proves the span is *inside* the file, not that it
            // still points at the constraint. The content is re-read after the network
            // check, so anything that edited the file in between shifts every later
            // offset — and the splice would land on whatever now occupies them.
            let found = s
                .get(edit.start..edit.end)
                .filter(|found| *found == edit.expected);
            let Some(_) = found else {
                anyhow::bail!(
                    "the manifest changed while it was being checked: expected `{}` at line {}, \
                     found `{}` — nothing was written; re-run to pick up the new contents",
                    edit.expected,
                    edit.line + 1,
                    s.get(edit.start..edit.end).unwrap_or("<out of range>")
                );
            };
            s.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out.push_str(&s);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every ecosystem, so a guard that is ecosystem-independent is asserted
    /// against all of them rather than against a convenient one — and so a new
    /// variant cannot quietly opt out of a claim made here.
    const EVERY_ECOSYSTEM: [Ecosystem; 9] = [
        Ecosystem::Rust,
        Ecosystem::Go,
        Ecosystem::Npm,
        Ecosystem::Python,
        Ecosystem::Php,
        Ecosystem::Dart,
        Ecosystem::CSharp,
        Ecosystem::Elixir,
        Ecosystem::Jvm,
    ];

    /// Preserving the operator prefix has nothing to do with the ecosystem: every
    /// form here either carries an operator or is a full concrete version, so what
    /// a *bare* version means cannot bear on it. Asserted against all nine rather
    /// than one, which is what makes that a claim instead of an assumption.
    #[test]
    fn rewrite_preserves_operator_prefix() {
        for ecosystem in EVERY_ECOSYSTEM {
            let it = Some(ecosystem);
            assert_eq!(
                rewrite_constraint("^1.0", "1.5.0", it).as_deref(),
                Ok("^1.5.0"),
                "{ecosystem:?}"
            );
            assert_eq!(
                rewrite_constraint("~1.0", "1.5.0", it).as_deref(),
                Ok("~1.5.0"),
                "{ecosystem:?}"
            );
            assert_eq!(
                rewrite_constraint(">=1.0", "1.5.0", it).as_deref(),
                Ok(">=1.5.0"),
                "{ecosystem:?}"
            );
            assert_eq!(
                rewrite_constraint("v1.2.3", "1.5.0", it).as_deref(),
                Ok("v1.5.0"),
                "{ecosystem:?}"
            );
            // A full bare version names one release under every reading, and
            // moving it forward is what `fix` is for.
            assert_eq!(
                rewrite_constraint("1.0.0", "1.5.0", it).as_deref(),
                Ok("1.5.0"),
                "{ecosystem:?}"
            );
            assert_eq!(
                rewrite_constraint("=1.2.0", "1.5.0", it).as_deref(),
                Ok("=1.5.0"),
                "{ecosystem:?}"
            );
            // The bare wildcard `*` is a range, not a version — see
            // `rewrite_never_narrows_a_wildcard_to_a_pin`. Declined everywhere,
            // Cargo included: `*` admits every major and a caret admits one.
            assert!(
                rewrite_constraint("*", "1.5.0", it).is_err(),
                "{ecosystem:?}"
            );
        }
    }

    #[test]
    fn rewrite_skips_multi_constraint() {
        for ecosystem in EVERY_ECOSYSTEM {
            assert!(
                rewrite_constraint(">=1.0,<2.0", "1.5.0", Some(ecosystem)).is_err(),
                "{ecosystem:?}"
            );
        }
    }

    #[test]
    fn rewrite_skips_dist_tags() {
        // npm dist-tags / channels are not version ranges — never pin them, so a
        // `"latest"` dependency keeps tracking the channel after `--fix`. The
        // guard is a leading-letter test, so it fires for every ecosystem, and a
        // channel name means the same thing wherever one is written.
        for ecosystem in EVERY_ECOSYSTEM {
            let it = Some(ecosystem);
            assert!(
                rewrite_constraint("latest", "2.3.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("next", "2.3.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("beta", "2.3.0", it).is_err(),
                "{ecosystem:?}"
            );
            // The bare wildcard `*` is declined for the same reason: it is a range
            // the author chose, and pinning it would narrow their manifest (#87).
            assert!(
                rewrite_constraint("*", "2.3.0", it).is_err(),
                "{ecosystem:?}"
            );
        }
    }

    /// Issue #87: a wildcard is a range, not a version. Rewriting `1.x` to a
    /// concrete release narrows what the author wrote into a pin — in npm a bare
    /// version is an exact match, so the floating constraint is destroyed. None of
    /// the other guards sees a wildcard: there is no comma, no space or `|` after
    /// the (empty) operator prefix, and `1.x` starts with a digit so the dist-tag
    /// guard passes it through.
    ///
    /// Issue #92 narrowed the decline to the ecosystems that need it, so the rule
    /// is now asserted in two halves. Wherever a bare version is *not* a caret
    /// range, every wildcard shape is still declined; and where it is — Cargo
    /// alone — every shape a caret does not reproduce is still declined too. The
    /// one shape that survives has its own test.
    #[test]
    fn rewrite_never_narrows_a_wildcard_to_a_pin() {
        for ecosystem in EVERY_ECOSYSTEM {
            if ecosystem.bare_version() == BareVersion::Caret {
                continue;
            }
            let it = Some(ecosystem);
            assert!(
                rewrite_constraint("1.x", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("1.*", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("1.X", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            // Gradle's dynamic version has the same shape (issue #87), and NuGet's
            // floating `1.*` resolves differently from a bare `2.0.0`.
            assert!(
                rewrite_constraint("1.+", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("^1.x", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("1.2.x", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            // The bare wildcard is the same kind of thing.
            assert!(
                rewrite_constraint("*", "2.0.0", it).is_err(),
                "{ecosystem:?}"
            );
        }

        // Cargo reads a bare version as a caret, which reproduces exactly one
        // wildcard shape. The rest are declined there too, each for its own reason.
        let cargo = Some(Ecosystem::Rust);
        // Gradle's `+` is a prefix range with its own resolution rules, and no
        // caret-reading ecosystem accepts it as a wildcard at all.
        assert!(rewrite_constraint("1.+", "2.0.0", cargo).is_err());
        // An operator means what gets written back is not a bare version, so the
        // caret reading that would justify the rewrite does not apply to it.
        assert!(rewrite_constraint("^1.x", "2.0.0", cargo).is_err());
        assert!(rewrite_constraint("=1.*", "2.0.0", cargo).is_err());
        // `1.2.*` is `>=1.2.0, <1.3.0`; a caret over any 1.2.z release reaches to
        // `<2.0.0`, so substituting *widens* what the author admitted.
        assert!(rewrite_constraint("1.2.x", "2.0.0", cargo).is_err());
        // `*` is every version; any concrete release confines it to one major.
        assert!(rewrite_constraint("*", "2.0.0", cargo).is_err());
    }

    /// The other side of issue #92: declining every wildcard was conservatism, not
    /// necessity. Where the ecosystem reads a bare version as a caret range, `1.*`
    /// and `1.0.219` are the same *kind* of constraint — `>=1.0.0, <2.0.0` and
    /// `>=1.0.219, <2.0.0` — so substituting raises the floor exactly as it does
    /// for `^1.0`, and the manifest keeps a range in the form the Cargo book calls
    /// equivalent. Before this, `serde = "1.*"` was simply left behind by `fix`.
    #[test]
    fn rewrite_updates_a_minor_wildcard_where_a_bare_version_is_a_caret() {
        let cargo = Some(Ecosystem::Rust);
        assert_eq!(
            rewrite_constraint("1.*", "1.0.219", cargo).as_deref(),
            Ok("1.0.219")
        );
        assert_eq!(
            rewrite_constraint("1.x", "1.0.219", cargo).as_deref(),
            Ok("1.0.219")
        );
        assert_eq!(
            rewrite_constraint("1.X", "1.0.219", cargo).as_deref(),
            Ok("1.0.219")
        );
        // The same input is declined for every ecosystem that reads a bare version
        // any other way — the whole point of asking which one this is.
        for ecosystem in EVERY_ECOSYSTEM {
            if ecosystem == Ecosystem::Rust {
                continue;
            }
            assert!(
                rewrite_constraint("1.*", "1.0.219", Some(ecosystem)).is_err(),
                "{ecosystem:?}"
            );
        }
        // And a manifest whose kind was not recognized gets the reading that
        // declines the most, never the one that permits the most.
        assert!(rewrite_constraint("1.*", "1.0.219", None).is_err());
    }

    /// Issue #92's second gap, and the one with no `*` in it. npm reads a partial
    /// version as an X-range — `"react": "16"` is `16.x`, `"1.0"` is `1.0.x` — so
    /// rewriting one to `"16.14.0"` pins a dependency that was tracking a line of
    /// releases. `is_wildcard` sees nothing to object to, and the only thing
    /// separating it from Cargo's `"1.0"`, where that rewrite is correct, is which
    /// ecosystem is being written.
    #[test]
    fn rewrite_declines_a_partial_version_where_a_bare_version_is_exact() {
        let npm = Some(Ecosystem::Npm);
        assert!(rewrite_constraint("16", "16.14.0", npm).is_err());
        assert!(rewrite_constraint("1.0", "1.5.0", npm).is_err());
        // Cargo's `1.0` is `^1.0` and `1.5.0` is `^1.5.0`: the floor rises and the
        // upper bound holds, which is what every other `fix` rewrite does.
        assert_eq!(
            rewrite_constraint("1.0", "1.5.0", Some(Ecosystem::Rust)).as_deref(),
            Ok("1.5.0")
        );
        // NuGet's `1.0` is `>= 1.0` and `1.5.0` is `>= 1.5.0` — a raised floor too.
        assert_eq!(
            rewrite_constraint("1.0", "1.5.0", Some(Ecosystem::CSharp)).as_deref(),
            Ok("1.5.0")
        );
        // Only the *partial* form is a range. A full bare version is a pin, and
        // moving a pin forward is exactly what `fix` is asked to do.
        assert_eq!(
            rewrite_constraint("16.0.0", "16.14.0", npm).as_deref(),
            Ok("16.14.0")
        );
        // An operator makes it a range in its own right, npm included: `^16` is a
        // caret range and `^16.14.0` is that range with a raised floor.
        assert_eq!(
            rewrite_constraint("^16", "16.14.0", npm).as_deref(),
            Ok("^16.14.0")
        );
        // An unrecognized manifest declines, like every exact reading.
        assert!(rewrite_constraint("16", "16.14.0", None).is_err());
    }

    /// A wildcard segment is not always the whole dot-segment. Composer allows a
    /// stability flag after the constraint, so `"symfony/symfony": "2.8.*@dev"`
    /// splits into `["2", "8", "*@dev"]` — no segment *equals* a wildcard, and a
    /// whole-segment guard hands back `7.0.0`, an exact pin in Composer that
    /// destroys both the wildcard and the stability flag. That is issue #87 one
    /// flag away from the guard.
    ///
    /// The `@` guard that catches these runs before the ecosystem is consulted, so
    /// the verdict is the same for all nine — including Cargo, where the wildcard
    /// alone would now be rewritten.
    #[test]
    fn rewrite_declines_a_wildcard_wearing_a_stability_flag() {
        for ecosystem in EVERY_ECOSYSTEM {
            let it = Some(ecosystem);
            assert!(
                rewrite_constraint("2.8.*@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("2.8.x@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("1.*@stable", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("*@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("^2.8.*@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
        }
    }

    /// A Composer stability flag qualifies the range, and nothing in a rewritten
    /// constraint can carry it: `format!("{prefix}{new_version}")` emits the
    /// operator prefix and the version, never the flag. So a flag hung off a plain
    /// version used to pass every guard and be rewritten flag-free — `">=2.8@dev"`
    /// became `">=7.0.0"`, and the unbounded `"@dev"` ("any version, dev
    /// stability") became the exact pin `"7.0.0"`: issue #87's harm again, reached
    /// without a wildcard. An `@` never belongs to a version, so decline the lot,
    /// in every ecosystem — the guard runs before the ecosystem is consulted.
    #[test]
    fn rewrite_declines_a_stability_flag_on_a_plain_version() {
        for ecosystem in EVERY_ECOSYSTEM {
            let it = Some(ecosystem);
            // The bare flag: a range over every version, collapsed to a pin.
            assert!(
                rewrite_constraint("@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            // Flag on an operator-led constraint, and on a bare version.
            assert!(
                rewrite_constraint(">=2.8@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("2.8@dev", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("^1.0@beta", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
            // npm's alias form carries an `@` too. The dist-tag guard caught it only
            // incidentally, because `npm:` happens to start with a letter; now it is
            // declined for the reason that actually applies.
            assert!(
                rewrite_constraint("npm:pkg@1.0.0", "7.0.0", it).is_err(),
                "{ecosystem:?}"
            );
        }
    }

    /// The other side of the guard: every concrete form the shipped parsers
    /// actually emit must stay rewritable. A wildcard test that also swallowed
    /// build metadata, a Go pseudo-version, or a prerelease identifier would
    /// silently stop `fix` from working on ordinary dependencies, so each shape
    /// is asserted by name. None of them contains an `@`, which is what makes
    /// declining every `@` form safe.
    ///
    /// Each shape is now asserted against the ecosystem that actually writes it,
    /// which is a stronger claim than the single-ecosystem version it replaces: a
    /// partial-version or wildcard guard that fired on the wrong reading would
    /// take one of these with it.
    #[test]
    fn rewrite_leaves_every_concrete_version_form_rewritable() {
        let go = Some(Ecosystem::Go);
        let rust = Some(Ecosystem::Rust);
        let nuget = Some(Ecosystem::CSharp);
        let python = Some(Ecosystem::Python);
        let hex = Some(Ecosystem::Elixir);

        // Go: a pseudo-version and the `+incompatible` marker.
        assert_eq!(
            rewrite_constraint("v0.0.0-20191109021931-daa7c04131f5", "1.5.0", go).as_deref(),
            Ok("v1.5.0")
        );
        assert_eq!(
            rewrite_constraint("v2.0.0+incompatible", "1.5.0", go).as_deref(),
            Ok("v1.5.0")
        );
        // Semver build metadata and prereleases — note the dotted identifiers,
        // which a leading-character test for `x` would have to survive.
        assert_eq!(
            rewrite_constraint("1.2.3+build.5", "1.5.0", rust).as_deref(),
            Ok("1.5.0")
        );
        assert_eq!(
            rewrite_constraint("1.0.0-alpha+exp.sha.5114f85", "1.5.0", rust).as_deref(),
            Ok("1.5.0")
        );
        // From the semver spec itself: a prerelease whose identifiers include `x`.
        assert_eq!(
            rewrite_constraint("1.0.0-x.7.z.92", "1.5.0", rust).as_deref(),
            Ok("1.5.0")
        );
        // NuGet's four-part version — four numeric segments, which the
        // partial-version guard must not mistake for a truncated one.
        assert_eq!(
            rewrite_constraint("1.0.0.4", "1.5.0", nuget).as_deref(),
            Ok("1.5.0")
        );
        // Python epochs and compatible-release operators.
        assert_eq!(
            rewrite_constraint("1!2.0", "1.5.0", python).as_deref(),
            Ok("1.5.0")
        );
        assert_eq!(
            rewrite_constraint("~=1.4", "1.5.0", python).as_deref(),
            Ok("~=1.5.0")
        );
        // Hex's `~>`, whose space belongs to the operator prefix.
        assert_eq!(
            rewrite_constraint("~> 1.0", "1.5.0", hex).as_deref(),
            Ok("~> 1.5.0")
        );
        // Declined already, and for a different reason: NuGet's bracketed range
        // holds a comma. The wildcard guard must not change that verdict.
        assert!(rewrite_constraint("[1.0,2.0)", "1.5.0", nuget).is_err());
        // Python's `==1.*` is a wildcard, and stays declined — twice over: Python
        // reads a bare version exactly, and the `==` means the rewrite would not
        // have produced a bare version anyway.
        assert!(rewrite_constraint("==1.*", "1.5.0", python).is_err());
    }

    #[test]
    fn rewrite_skips_space_and_pipe_compound_constraints() {
        // npm / pubspec space-separated ranges and `||` alternations can't collapse
        // to a single version without dropping a clause, so they are left untouched.
        // Dropping a clause is a loss in every ecosystem, so assert it in all nine.
        for ecosystem in EVERY_ECOSYSTEM {
            let it = Some(ecosystem);
            assert!(
                rewrite_constraint(">=1.0.0 <2.0.0", "1.5.0", it).is_err(),
                "{ecosystem:?}"
            );
            assert!(
                rewrite_constraint("^1.0.0 || ^2.0.0", "1.5.0", it).is_err(),
                "{ecosystem:?}"
            );
            // A single constraint that merely spaces its operator is still rewritten.
            assert_eq!(
                rewrite_constraint(">= 1.0.0", "1.5.0", it).as_deref(),
                Ok(">= 1.5.0"),
                "{ecosystem:?}"
            );
        }
    }

    /// A decline is only worth carrying out of the planner if it says which
    /// guard fired, because that is the whole content of the note the user sees.
    /// One assertion per variant, so a guard that starts answering under another
    /// reason changes a test rather than quietly changing what `fix` tells people.
    #[test]
    fn a_decline_names_the_guard_that_refused_it() {
        let cargo = Some(Ecosystem::Rust);
        let npm = Some(Ecosystem::Npm);
        let nuget = Some(Ecosystem::CSharp);

        let reason = |original, ecosystem| rewrite_constraint(original, "2.0.0", ecosystem).err();

        assert_eq!(reason(">=1.0,<2.0", cargo), Some(DeclineReason::CommaRange));
        assert_eq!(
            reason(">=1.0.0 <2.0.0", npm),
            Some(DeclineReason::MultiClause)
        );
        assert_eq!(
            reason("^1.0.0 || ^2.0.0", npm),
            Some(DeclineReason::MultiClause)
        );
        assert_eq!(reason("2.8.*@dev", cargo), Some(DeclineReason::Qualifier));
        assert_eq!(reason("latest", npm), Some(DeclineReason::DistTag));

        // The wildcard family, whose reason is the point of #92: the same three
        // characters are declined for three different harms.
        //
        // An operator answers first, and for every ecosystem — with one in front,
        // what gets written back is not a bare version at all, so what a bare
        // version *means* here cannot be the reason.
        assert_eq!(reason("^1.x", cargo), Some(DeclineReason::WildcardOperator));
        assert_eq!(reason("^1.x", npm), Some(DeclineReason::WildcardOperator));
        // Then the ecosystem's reading, which is the more specific harm than the
        // shape: npm pins, NuGet loses the upper bound.
        assert_eq!(reason("1.x", npm), Some(DeclineReason::WildcardPins));
        assert_eq!(reason("1.*", nuget), Some(DeclineReason::WildcardUnbounds));
        // And only where a bare version is already a caret does the shape get to
        // be the reason — there the reading is fine and the wildcard is not.
        assert_eq!(reason("1.2.*", cargo), Some(DeclineReason::WildcardShape));
        assert_eq!(reason("*", cargo), Some(DeclineReason::WildcardShape));

        assert_eq!(reason("16", npm), Some(DeclineReason::PartialVersion));

        // An unrecognized manifest reads a bare version exactly, so it declines
        // under that reading rather than under a reason of its own.
        assert_eq!(reason("1.x", None), Some(DeclineReason::WildcardPins));
    }

    /// The issue #93 defect at the planner's own boundary: `plan_fixes` used to
    /// return an empty record list for a wildcard it declined, which is the same
    /// answer it returns for a manifest with nothing to do. The declined list is
    /// what tells those two apart.
    #[test]
    fn a_declined_constraint_leaves_a_record_of_what_was_not_done() {
        let content = r#"{
  "name": "demo",
  "dependencies": {
    "lodash": "1.x",
    "react": "^18.0.0"
  }
}
"#;
        let results = results_for(
            ManifestKind::PackageJson,
            content,
            &[("lodash", "1.9.0"), ("react", "18.2.0")],
        );
        let (updated, records, declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::PackageJson.ecosystem()),
        )
        .expect("the plan applies");

        // The wildcard is untouched and the ordinary caret is rewritten: the
        // decline is a record, not a refusal to plan the rest of the manifest.
        assert!(updated.contains(r#""lodash": "1.x""#));
        assert!(updated.contains(r#""react": "^18.2.0""#));
        assert_eq!(records.len(), 1);
        assert_eq!(
            declined,
            vec![Declined {
                name: "lodash".to_string(),
                constraint: "1.x".to_string(),
                target: "1.9.0".to_string(),
                reason: DeclineReason::WildcardPins,
            }]
        );
    }

    /// A dependency with nothing available must not be reported as left alone —
    /// the note claims `check` had something to say, so anything up to date has
    /// to be filtered out before the constraint is ever consulted.
    #[test]
    fn an_up_to_date_dependency_is_not_a_decline() {
        let content = r#"{
  "name": "demo",
  "dependencies": {
    "lodash": "1.x"
  }
}
"#;
        // `results_for` marks its targets `UpdateAvailable`; naming none leaves
        // the manifest's only dependency with no result at all.
        let (_, records, declined) = plan_fixes(
            content,
            &results_for(ManifestKind::PackageJson, content, &[]),
            false,
            Some(ManifestKind::PackageJson.ecosystem()),
        )
        .expect("the plan applies");
        assert!(records.is_empty());
        assert!(declined.is_empty());
    }

    #[test]
    fn apply_edits_replaces_recorded_span() {
        // `serde = "^1.0"` — replace the `^1.0` span (bytes 9..13) on line 1.
        let content = "[dependencies]\nserde = \"^1.0\"\n";
        let edits = vec![Edit {
            line: 1,
            start: 9,
            end: 13,
            expected: "^1.0".to_string(),
            replacement: "^1.5.0".to_string(),
        }];
        let out = apply_edits(content, &edits).expect("the span still holds `^1.0`");
        assert_eq!(out, "[dependencies]\nserde = \"^1.5.0\"\n");
    }

    #[test]
    fn apply_edits_handles_multiple_edits_on_one_line() {
        // Two replacements on the same line, applied right-to-left.
        let content = "a=1.0 b=2.0\n";
        let edits = vec![
            Edit {
                line: 0,
                start: 2,
                end: 5,
                expected: "1.0".to_string(),
                replacement: "1.9".to_string(),
            },
            Edit {
                line: 0,
                start: 8,
                end: 11,
                expected: "2.0".to_string(),
                replacement: "2.9".to_string(),
            },
        ];
        let out = apply_edits(content, &edits).expect("both spans still hold their text");
        assert_eq!(out, "a=1.9 b=2.9\n");
    }

    use dependable_fetch::DependencyStatus;
    use dependable_fetch::core::{DependencyKind, parse, resolve_workspace_inheritance};

    /// Parse `content`, then build an `UpdateAvailable` result with the given
    /// target for each named dependency — enough to drive `plan_fixes`. The target
    /// fills both `latest_compatible` and `latest_available`, so the same fixture
    /// drives the default path and the `--all` path, which read different fields.
    fn results_for(
        kind: ManifestKind,
        content: &str,
        targets: &[(&str, &str)],
    ) -> Vec<CheckResult> {
        parse(kind, content)
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| {
                targets
                    .iter()
                    .find(|(name, _)| *name == item.name)
                    .map(|(_, target)| {
                        let mut result = CheckResult::new(item, DependencyStatus::UpdateAvailable);
                        result.latest_compatible = Some((*target).to_string());
                        result.latest_available = Some((*target).to_string());
                        result
                    })
            })
            .collect()
    }

    #[test]
    fn fixes_package_json_in_place() {
        let content = r#"{
  "name": "demo",
  "dependencies": {
    "react": "^18.0.0",
    "lodash": "^4.17.0"
  },
  "devDependencies": {
    "typescript": "~5.3.0"
  }
}
"#;
        // Only react and typescript are targeted; lodash is left as-is.
        let results = results_for(
            ManifestKind::PackageJson,
            content,
            &[("react", "18.2.0"), ("typescript", "5.4.5")],
        );
        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::PackageJson.ecosystem()),
        )
        .expect("the plan applies");

        assert_eq!(
            updated,
            r#"{
  "name": "demo",
  "dependencies": {
    "react": "^18.2.0",
    "lodash": "^4.17.0"
  },
  "devDependencies": {
    "typescript": "~5.4.5"
  }
}
"#
        );
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn fixes_composer_json_in_place() {
        let content = r#"{
  "require": {
    "php": ">=8.1",
    "monolog/monolog": "^2.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.5"
  }
}
"#;
        // The `php` platform requirement is not a checkable package; only monolog
        // is targeted here.
        let results = results_for(
            ManifestKind::ComposerJson,
            content,
            &[("monolog/monolog", "2.9.1")],
        );
        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::ComposerJson.ecosystem()),
        )
        .expect("the plan applies");

        assert_eq!(
            updated,
            r#"{
  "require": {
    "php": ">=8.1",
    "monolog/monolog": "^2.9.1"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.5"
  }
}
"#
        );
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn fixes_pubspec_yaml_in_place_preserving_comments() {
        let content = "name: my_app\n\ndependencies:\n  http: ^1.1.0\n  provider: ^6.0.0  # state mgmt\n\ndev_dependencies:\n  test: ^1.24.0\n";
        let results = results_for(
            ManifestKind::PubspecYaml,
            content,
            &[("http", "1.2.0"), ("provider", "6.1.0")],
        );
        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::PubspecYaml.ecosystem()),
        )
        .expect("the plan applies");

        // Versions bumped, indentation and the trailing comment untouched.
        assert_eq!(
            updated,
            "name: my_app\n\ndependencies:\n  http: ^1.2.0\n  provider: ^6.1.0  # state mgmt\n\ndev_dependencies:\n  test: ^1.24.0\n"
        );
        assert_eq!(records.len(), 2);
    }
    /// The manifest-corruption guard.
    ///
    /// A resolved `dep.workspace = true` passes both of the guards `plan_fixes` used to
    /// carry: it is checkable, and it has a constraint. Its span is still `0/0/0`, which
    /// `apply_edits`' `start <= end && end <= len` check passes trivially — so the edit
    /// would land as `replace_range(0..0, ..)`, prepending the version to the first line
    /// of the member manifest and writing the wreckage to disk as a successful fix.
    #[test]
    fn an_inherited_constraint_is_never_written_into_the_member_manifest() {
        let root = "[workspace.dependencies]\nserde = \"1.0.100\"\n";
        let member = "[package]\nname = \"member\"\n\n[dependencies]\nserde.workspace = true\n";

        let declarations: Vec<_> = parse(ManifestKind::CargoToml, root)
            .unwrap()
            .items
            .into_iter()
            .filter(|item| item.kind == DependencyKind::Workspace)
            .collect();
        let mut items = parse(ManifestKind::CargoToml, member).unwrap().items;
        let resolved = resolve_workspace_inheritance(&mut items, &declarations);
        assert_eq!(resolved, ["serde"], "the fixture must actually resolve");

        let results: Vec<CheckResult> = items
            .into_iter()
            .map(|item| {
                let mut result = CheckResult::new(item, DependencyStatus::UpdateAvailable);
                result.latest_compatible = Some("1.0.219".to_string());
                result
            })
            .collect();
        assert!(
            results[0].item.is_checkable() && !results[0].item.version_constraint.is_empty(),
            "the old guards would both have passed"
        );

        let (updated, records, _declined) = plan_fixes(
            member,
            &results,
            false,
            Some(ManifestKind::CargoToml.ecosystem()),
        )
        .expect("the plan applies");

        assert!(records.is_empty(), "{records:?}");
        assert_eq!(
            updated, member,
            "the member manifest must be byte-identical"
        );
    }

    /// The other half of the rule, and the half that makes it Cargo's own model: the
    /// declaration a member inherits *is* rewritable, in the one file that holds it.
    ///
    /// The pairing is the point — the same crate, the same version, rewritten at the root
    /// and refused at the member — so this asserts the gate itself and not just the
    /// outcome, which a plain registry dependency would satisfy on its own.
    #[test]
    fn the_workspace_root_declaration_is_still_rewritten() {
        let root = "[workspace.dependencies]\nserde = \"1.0.100\"\n";
        let results = results_for(ManifestKind::CargoToml, root, &[("serde", "1.0.219")]);

        let declaration = &results[0].item;
        assert_eq!(declaration.kind, DependencyKind::Workspace);
        assert!(
            declaration.is_rewritable(),
            "the version string is in this file, on line {}",
            declaration.version_line
        );
        assert_eq!(declaration.version_line, 1, "and the span points at it");

        let (updated, records, _declined) = plan_fixes(
            root,
            &results,
            false,
            Some(ManifestKind::CargoToml.ecosystem()),
        )
        .expect("the plan applies");

        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(updated, "[workspace.dependencies]\nserde = \"1.0.219\"\n");
    }

    /// The span is computed from a parse that happened before the network check, and the
    /// file is read again at write time. If it moved in between — an editor auto-save, a
    /// `cargo add`, a concurrent `fix` — the offsets point at different bytes now. The
    /// old bounds check only proved the span was inside the file, so the splice landed on
    /// whatever now occupied it and the manifest was silently corrupted.
    #[test]
    fn a_span_that_no_longer_holds_its_constraint_is_refused() {
        let content = "[dependencies]\nserde = \"^1.0\"\n";
        // The same span, against content where a line was inserted above it.
        let shifted = "[dependencies]\n# a comment someone just added\nserde = \"^1.0\"\n";
        let edits = vec![Edit {
            line: 1,
            start: 9,
            end: 13,
            expected: "^1.0".to_string(),
            replacement: "^1.5.0".to_string(),
        }];

        assert!(
            apply_edits(content, &edits).is_ok(),
            "the unshifted file still applies"
        );

        let err = apply_edits(shifted, &edits).expect_err("a moved span must be refused");
        let message = err.to_string();
        assert!(
            message.contains("changed while it was being checked"),
            "{message}"
        );
        assert!(message.contains("nothing was written"), "{message}");
    }

    /// A span running past the end of its line is refused rather than silently skipped:
    /// the old code's bounds check dropped such an edit and reported success for it.
    #[test]
    fn an_out_of_range_span_is_refused_not_skipped() {
        let content = "a=1.0\n";
        let edits = vec![Edit {
            line: 0,
            start: 2,
            end: 99,
            expected: "1.0".to_string(),
            replacement: "1.9".to_string(),
        }];
        assert!(apply_edits(content, &edits).is_err());
    }

    /// The end-to-end shape of issue #87, with no flags and no lockfile.
    ///
    /// `1.x` matches `1.0.0` and `1.9.0` but not `2.0.0`, so `check_version` reports
    /// `UpdateAvailable` with `latest_compatible == 1.9.0` (see
    /// `wildcard_constraint_is_reported_as_upgradable` in the core checker). Default
    /// `fix` therefore reaches `rewrite_constraint` with a live wildcard, and used to
    /// write `"lodash": "1.9.0"` — an exact pin in npm, where the author had asked for
    /// every `1.x` release.
    #[test]
    fn a_wildcard_dependency_is_left_untouched_by_fix() {
        let content = r#"{
  "dependencies": {
    "lodash": "1.x"
  }
}
"#;
        let results = results_for(ManifestKind::PackageJson, content, &[("lodash", "1.9.0")]);
        assert_eq!(
            results.len(),
            1,
            "the fixture must produce a checkable item"
        );

        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::PackageJson.ecosystem()),
        )
        .expect("the plan applies");

        assert!(records.is_empty(), "{records:?}");
        assert_eq!(updated, content, "the manifest must be byte-identical");
    }

    /// The same harm under `--all`, which is the branch that reaches it directly.
    ///
    /// With `all`, `plan_fixes` takes `latest_available` instead of
    /// `latest_compatible` and stops skipping pinned items, so a wildcard arrives at
    /// `rewrite_constraint` with the newest release outside its range — no lockfile
    /// and no compatible upgrade needed. The Composer fixture carries a stability
    /// flag, the form that used to slip past the whole-segment guard: `2.8.*@dev`
    /// would become `7.0.0`, an exact pin that loses the wildcard *and* the flag.
    #[test]
    fn a_wildcard_dependency_is_left_untouched_by_fix_all() {
        let content = r#"{
  "require": {
    "symfony/symfony": "2.8.*@dev",
    "monolog/monolog": "^2.0"
  }
}
"#;
        let results = results_for(
            ManifestKind::ComposerJson,
            content,
            &[("symfony/symfony", "7.0.0"), ("monolog/monolog", "2.9.1")],
        );
        assert_eq!(results.len(), 2, "the fixture must produce two items");
        assert!(
            results
                .iter()
                .all(|result| result.latest_available.is_some()),
            "the `--all` branch reads `latest_available`, so the fixture must set it"
        );

        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            true,
            Some(ManifestKind::ComposerJson.ecosystem()),
        )
        .expect("the plan applies");

        // The wildcard is declined; its non-wildcard neighbour still gets fixed, so
        // this asserts the guard and not a `--all` path that simply does nothing.
        assert_eq!(
            records
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["monolog/monolog"],
            "{records:?}"
        );
        assert_eq!(
            updated,
            r#"{
  "require": {
    "symfony/symfony": "2.8.*@dev",
    "monolog/monolog": "^2.9.1"
  }
}
"#
        );
    }

    /// Issue #92 end to end, and the case the issue was opened for.
    ///
    /// `serde = "1.*"` locked at `1.0.100` with `1.0.219` published: `check`
    /// reports an upgrade, and before #92 `fix` declined it because the guard from
    /// #87 could not tell Cargo from npm. Cargo reads a bare version as a caret, so
    /// `1.0.219` here *is* `^1.0.219` — still a range, still bounded below 2.0, and
    /// the form the Cargo book calls equivalent to what was written.
    ///
    /// The `1.2.*` neighbour is the boundary: its range stops at `1.3.0` and a
    /// caret does not, so it stays untouched in the same file, under the same
    /// ecosystem, on the same run.
    #[test]
    fn a_cargo_minor_wildcard_is_updated_by_fix() {
        let content = "[dependencies]\nserde = \"1.*\"\nclap = \"1.2.*\"\n";
        let results = results_for(
            ManifestKind::CargoToml,
            content,
            &[("serde", "1.0.219"), ("clap", "1.2.9")],
        );
        assert_eq!(results.len(), 2, "the fixture must produce two items");

        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::CargoToml.ecosystem()),
        )
        .expect("the plan applies");

        assert_eq!(
            records
                .iter()
                .map(|record| (record.name.as_str(), record.to.as_str()))
                .collect::<Vec<_>>(),
            [("serde", "1.0.219")],
            "{records:?}"
        );
        assert_eq!(
            updated,
            "[dependencies]\nserde = \"1.0.219\"\nclap = \"1.2.*\"\n"
        );
    }

    /// The same manifest shape in the ecosystem that must still decline it: npm
    /// reads a bare `1.0.219` as that release and nothing else, so the identical
    /// rewrite would destroy the range. One ecosystem apart, opposite verdicts —
    /// which is the whole of #92.
    #[test]
    fn the_same_wildcard_is_still_declined_for_npm() {
        let content = "{\n  \"dependencies\": {\n    \"lodash\": \"1.*\"\n  }\n}\n";
        let results = results_for(ManifestKind::PackageJson, content, &[("lodash", "1.9.0")]);
        assert_eq!(results.len(), 1, "the fixture must produce one item");

        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::PackageJson.ecosystem()),
        )
        .expect("the plan applies");

        assert!(records.is_empty(), "{records:?}");
        assert_eq!(updated, content, "the manifest must be byte-identical");
    }

    /// Issue #92's second gap, end to end: npm reads `"react": "16"` as `16.x`,
    /// and `fix` used to write `"16.14.0"` into it — a pin, with no wildcard
    /// character anywhere for the #87 guard to catch. Its `^18.0.0` neighbour is
    /// rewritten on the same run, so this asserts the new guard rather than a path
    /// that quietly does nothing.
    #[test]
    fn an_npm_partial_version_is_left_untouched_by_fix() {
        let content =
            "{\n  \"dependencies\": {\n    \"react\": \"16\",\n    \"vue\": \"^3.0.0\"\n  }\n}\n";
        let results = results_for(
            ManifestKind::PackageJson,
            content,
            &[("react", "16.14.0"), ("vue", "3.4.21")],
        );
        assert_eq!(results.len(), 2, "the fixture must produce two items");

        let (updated, records, _declined) = plan_fixes(
            content,
            &results,
            false,
            Some(ManifestKind::PackageJson.ecosystem()),
        )
        .expect("the plan applies");

        assert_eq!(
            records
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["vue"],
            "{records:?}"
        );
        assert_eq!(
            updated,
            "{\n  \"dependencies\": {\n    \"react\": \"16\",\n    \"vue\": \"^3.4.21\"\n  }\n}\n"
        );
    }

    /// A manifest whose kind `ManifestKind::detect` does not recognize reaches the
    /// rewriter with no ecosystem, and the answer is to decline, not to guess:
    /// every reading that could apply is one where at least one of these rewrites
    /// destroys the constraint. The `^1.0` neighbour still moves, so the decline is
    /// scoped to the forms whose meaning depends on the ecosystem.
    #[test]
    fn an_unrecognized_manifest_kind_declines_every_ecosystem_dependent_form() {
        assert!(rewrite_constraint("1.*", "1.5.0", None).is_err());
        assert!(rewrite_constraint("1.x", "1.5.0", None).is_err());
        assert!(rewrite_constraint("1.0", "1.5.0", None).is_err());
        assert!(rewrite_constraint("16", "16.14.0", None).is_err());
        // Not ecosystem-dependent: an operator-led range and a full bare version
        // mean the same thing everywhere, so they are still rewritten.
        assert_eq!(
            rewrite_constraint("^1.0", "1.5.0", None).as_deref(),
            Ok("^1.5.0")
        );
        assert_eq!(
            rewrite_constraint("1.0.0", "1.5.0", None).as_deref(),
            Ok("1.5.0")
        );
    }
}
