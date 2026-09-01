//! In-place version rewriting via recorded byte offsets.
//!
//! Every parser records the exact byte span of a dependency's version value, so
//! `--fix` is format-agnostic: it replaces that span in place, leaving
//! surrounding formatting and comments untouched. The leading operator/`v` prefix
//! is preserved (`^1.0` → `^1.5.0`, `v1.2.3` → `v1.5.0`) so a constraint's meaning
//! is not silently changed (e.g. an npm caret range is not turned into a pin).

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use dependable_fetch::{CheckResult, DependencyStatus};

/// A single applied (or would-be-applied) version change.
#[derive(Debug, Clone)]
pub struct FixRecord {
    pub name: String,
    pub from: String,
    pub to: String,
}

/// A byte-range replacement within one line of the manifest.
struct Edit {
    line: usize,
    start: usize,
    end: usize,
    replacement: String,
}

/// Rewrite version constraints in `manifest` to the best available upgrade.
///
/// Pinned (`=x.y.z`) deps are skipped unless `all` is set; multi-constraint forms
/// (containing `,`) are skipped because they can't be rewritten to a single
/// version. With `dry_run`, nothing is written.
///
/// # Errors
/// Returns an error if the manifest cannot be read or written.
pub fn apply_fixes(
    manifest: &Path,
    results: &[CheckResult],
    all: bool,
    dry_run: bool,
) -> anyhow::Result<Vec<FixRecord>> {
    let content = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let (updated, records) = plan_fixes(&content, results, all);
    if !dry_run && !records.is_empty() {
        std::fs::write(manifest, updated)
            .with_context(|| format!("writing {}", manifest.display()))?;
    }
    Ok(records)
}

/// Compute the rewritten manifest and the applied records from `content` and the
/// check `results`, with no filesystem IO (the file boundary lives in
/// [`apply_fixes`]). Format-agnostic: it edits each recorded version span in place,
/// so JSON, YAML, and TOML manifests are rewritten without reformatting.
fn plan_fixes(content: &str, results: &[CheckResult], all: bool) -> (String, Vec<FixRecord>) {
    let mut edits: Vec<Edit> = Vec::new();
    let mut records = Vec::new();
    for result in results {
        let item = &result.item;
        // `is_rewritable` and not `is_checkable`: a workspace member inheriting a
        // constraint is worth checking, but its version string lives in the root, so its
        // recorded span is `0/0/0` — which `apply_edits`' bounds check passes trivially,
        // splicing the new version into byte 0 of line 0 of this file.
        if !item.is_rewritable() {
            continue;
        }
        let updatable = matches!(
            result.status,
            DependencyStatus::PatchAvailable
                | DependencyStatus::UpdateAvailable
                | DependencyStatus::Outdated
                | DependencyStatus::Vulnerable
        );
        if !updatable || (item.is_pinned() && !all) {
            continue;
        }

        let target = if all {
            result.latest_available.as_ref()
        } else {
            result.latest_compatible.as_ref()
        };
        let Some(target) = target else { continue };
        let Some(new_constraint) = rewrite_constraint(&item.version_constraint, target) else {
            continue;
        };
        if new_constraint == item.version_constraint {
            continue;
        }

        edits.push(Edit {
            line: item.version_line,
            start: item.version_col_start,
            end: item.version_col_end,
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
        apply_edits(content, &edits)
    };
    (updated, records)
}

/// Build a new constraint from `original`, preserving its leading operator/`v`
/// prefix and substituting `new_version`. Returns `None` for the forms that
/// can't be rewritten to a single version without changing their meaning: a
/// comma-separated range (Cargo `>=1.0, <2.0`), a space-separated range
/// (npm/pubspec `>=1.0.0 <2.0.0`), a `||` alternation (`^1 || ^2`), a dist-tag
/// (`latest`), a wildcard (`*`, `1.x`, `1.*`), or anything carrying an `@`
/// (a Composer stability flag such as `@dev` or `^1.0@beta`, an npm alias such
/// as `npm:pkg@1.0.0`).
fn rewrite_constraint(original: &str, new_version: &str) -> Option<String> {
    let trimmed = original.trim();
    if trimmed.contains(',') {
        return None;
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
        return None;
    }
    // An `@` never belongs to a version: it introduces a Composer stability flag
    // (`@dev`, `2.8.*@dev`, `^1.0@beta`) or an npm alias target (`npm:pkg@1.0.0`).
    // A stability flag qualifies the *range* — `@dev` alone means "any version, dev
    // stability" — and this layer cannot reconstruct it, so substituting a concrete
    // release drops the flag and, for a bare `@dev`, collapses the range to an exact
    // pin. That is the harm of #87, so take the same call already taken for a
    // dist-tag and decline.
    if rest.contains('@') {
        return None;
    }
    // A dist-tag / channel name (`latest`, `next`, `beta`, …) starts with a letter
    // once any operator prefix is removed — it names a channel, not a version
    // range, so it must never be pinned to a concrete version (npm D8).
    if rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    // A wildcard (`*`, `1.x`, `1.*`, Gradle's `1.+`) is a range the author chose,
    // not a version — substituting a concrete release narrows it to a pin (#87).
    // The decline is deliberately blanket rather than per-ecosystem: substituting
    // is safe where a bare version is a caret or an inclusive minimum (Cargo, Go,
    // Dart) and unsafe where it is an exact pin (npm, Composer, Hex), and this
    // signature carries no `Ecosystem` to tell them apart. `apply_fixes` does hold
    // the manifest path and could supply one — #92 tracks narrowing the decline to
    // the ecosystems that need it. Until then, decline as a dist-tag is declined.
    if is_wildcard(rest) {
        return None;
    }
    Some(format!("{prefix}{new_version}"))
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
fn apply_edits(content: &str, edits: &[Edit]) -> String {
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
            if edit.start <= edit.end && edit.end <= s.len() {
                s.replace_range(edit.start..edit.end, &edit.replacement);
            }
        }
        out.push_str(&s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_preserves_operator_prefix() {
        assert_eq!(
            rewrite_constraint("^1.0", "1.5.0").as_deref(),
            Some("^1.5.0")
        );
        assert_eq!(
            rewrite_constraint("~1.0", "1.5.0").as_deref(),
            Some("~1.5.0")
        );
        assert_eq!(
            rewrite_constraint(">=1.0", "1.5.0").as_deref(),
            Some(">=1.5.0")
        );
        assert_eq!(
            rewrite_constraint("v1.2.3", "1.5.0").as_deref(),
            Some("v1.5.0")
        );
        assert_eq!(
            rewrite_constraint("1.0.0", "1.5.0").as_deref(),
            Some("1.5.0")
        );
        assert_eq!(
            rewrite_constraint("=1.2.0", "1.5.0").as_deref(),
            Some("=1.5.0")
        );
        // The bare wildcard `*` is a range, not a version — see
        // `rewrite_never_narrows_a_wildcard_to_a_pin`.
        assert_eq!(rewrite_constraint("*", "1.5.0"), None);
    }

    #[test]
    fn rewrite_skips_multi_constraint() {
        assert_eq!(rewrite_constraint(">=1.0,<2.0", "1.5.0"), None);
    }

    #[test]
    fn rewrite_skips_dist_tags() {
        // npm dist-tags / channels are not version ranges — never pin them, so a
        // `"latest"` dependency keeps tracking the channel after `--fix`.
        assert_eq!(rewrite_constraint("latest", "2.3.0"), None);
        assert_eq!(rewrite_constraint("next", "2.3.0"), None);
        assert_eq!(rewrite_constraint("beta", "2.3.0"), None);
        // The wildcard `*` is declined for the same reason: it is a range the
        // author chose, and pinning it would narrow their manifest (issue #87).
        assert_eq!(rewrite_constraint("*", "2.3.0"), None);
    }

    /// Issue #87: a wildcard is a range, not a version. Rewriting `1.x` to a
    /// concrete release narrows what the author wrote into a pin — in npm a bare
    /// version is an exact match, so the floating constraint is destroyed. None of
    /// the three existing guards sees a wildcard: there is no comma, no space or
    /// `|` after the (empty) operator prefix, and `1.x` starts with a digit so the
    /// dist-tag guard passes it through.
    #[test]
    fn rewrite_never_narrows_a_wildcard_to_a_pin() {
        assert_eq!(rewrite_constraint("1.x", "2.0.0"), None);
        assert_eq!(rewrite_constraint("1.*", "2.0.0"), None);
        assert_eq!(rewrite_constraint("1.X", "2.0.0"), None);
        // Gradle's dynamic version has the same shape (issue #87), and NuGet's
        // floating `1.*` resolves differently from a bare `2.0.0`.
        assert_eq!(rewrite_constraint("1.+", "2.0.0"), None);
        assert_eq!(rewrite_constraint("^1.x", "2.0.0"), None);
        assert_eq!(rewrite_constraint("1.2.x", "2.0.0"), None);
        // The bare wildcard is the same kind of thing.
        assert_eq!(rewrite_constraint("*", "2.0.0"), None);
    }

    /// A wildcard segment is not always the whole dot-segment. Composer allows a
    /// stability flag after the constraint, so `"symfony/symfony": "2.8.*@dev"`
    /// splits into `["2", "8", "*@dev"]` — no segment *equals* a wildcard, and a
    /// whole-segment guard hands back `7.0.0`, an exact pin in Composer that
    /// destroys both the wildcard and the stability flag. That is issue #87 one
    /// flag away from the guard.
    #[test]
    fn rewrite_declines_a_wildcard_wearing_a_stability_flag() {
        assert_eq!(rewrite_constraint("2.8.*@dev", "7.0.0"), None);
        assert_eq!(rewrite_constraint("2.8.x@dev", "7.0.0"), None);
        assert_eq!(rewrite_constraint("1.*@stable", "7.0.0"), None);
        assert_eq!(rewrite_constraint("*@dev", "7.0.0"), None);
        assert_eq!(rewrite_constraint("^2.8.*@dev", "7.0.0"), None);
    }

    /// A Composer stability flag qualifies the range, and nothing in a rewritten
    /// constraint can carry it: `format!("{prefix}{new_version}")` emits the
    /// operator prefix and the version, never the flag. So a flag hung off a plain
    /// version used to pass every guard and be rewritten flag-free — `">=2.8@dev"`
    /// became `">=7.0.0"`, and the unbounded `"@dev"` ("any version, dev
    /// stability") became the exact pin `"7.0.0"`: issue #87's harm again, reached
    /// without a wildcard. An `@` never belongs to a version, so decline the lot.
    #[test]
    fn rewrite_declines_a_stability_flag_on_a_plain_version() {
        // The bare flag: a range over every version, collapsed to a pin.
        assert_eq!(rewrite_constraint("@dev", "7.0.0"), None);
        // Flag on an operator-led constraint, and on a bare version.
        assert_eq!(rewrite_constraint(">=2.8@dev", "7.0.0"), None);
        assert_eq!(rewrite_constraint("2.8@dev", "7.0.0"), None);
        assert_eq!(rewrite_constraint("^1.0@beta", "7.0.0"), None);
        // npm's alias form carries an `@` too. The dist-tag guard caught it only
        // incidentally, because `npm:` happens to start with a letter; now it is
        // declined for the reason that actually applies.
        assert_eq!(rewrite_constraint("npm:pkg@1.0.0", "7.0.0"), None);
    }

    /// The other side of the guard: every concrete form the shipped parsers
    /// actually emit must stay rewritable. A wildcard test that also swallowed
    /// build metadata, a Go pseudo-version, or a prerelease identifier would
    /// silently stop `fix` from working on ordinary dependencies, so each shape
    /// is asserted by name. None of them contains an `@`, which is what makes
    /// declining every `@` form safe.
    #[test]
    fn rewrite_leaves_every_concrete_version_form_rewritable() {
        // Go: a pseudo-version and the `+incompatible` marker.
        assert_eq!(
            rewrite_constraint("v0.0.0-20191109021931-daa7c04131f5", "1.5.0").as_deref(),
            Some("v1.5.0")
        );
        assert_eq!(
            rewrite_constraint("v2.0.0+incompatible", "1.5.0").as_deref(),
            Some("v1.5.0")
        );
        // Semver build metadata and prereleases — note the dotted identifiers,
        // which a leading-character test for `x` would have to survive.
        assert_eq!(
            rewrite_constraint("1.2.3+build.5", "1.5.0").as_deref(),
            Some("1.5.0")
        );
        assert_eq!(
            rewrite_constraint("1.0.0-alpha+exp.sha.5114f85", "1.5.0").as_deref(),
            Some("1.5.0")
        );
        // From the semver spec itself: a prerelease whose identifiers include `x`.
        assert_eq!(
            rewrite_constraint("1.0.0-x.7.z.92", "1.5.0").as_deref(),
            Some("1.5.0")
        );
        // NuGet's four-part version.
        assert_eq!(
            rewrite_constraint("1.0.0.4", "1.5.0").as_deref(),
            Some("1.5.0")
        );
        // Python epochs and compatible-release operators.
        assert_eq!(
            rewrite_constraint("1!2.0", "1.5.0").as_deref(),
            Some("1.5.0")
        );
        assert_eq!(
            rewrite_constraint("~=1.4", "1.5.0").as_deref(),
            Some("~=1.5.0")
        );
        // Hex's `~>`, whose space belongs to the operator prefix.
        assert_eq!(
            rewrite_constraint("~> 1.0", "1.5.0").as_deref(),
            Some("~> 1.5.0")
        );
        // Declined already, and for a different reason: NuGet's bracketed range
        // holds a comma. The wildcard guard must not change that verdict.
        assert_eq!(rewrite_constraint("[1.0,2.0)", "1.5.0"), None);
        // Python's `==1.*` is a wildcard, and stays declined.
        assert_eq!(rewrite_constraint("==1.*", "1.5.0"), None);
    }

    #[test]
    fn rewrite_skips_space_and_pipe_compound_constraints() {
        // npm / pubspec space-separated ranges and `||` alternations can't collapse
        // to a single version without dropping a clause, so they are left untouched.
        assert_eq!(rewrite_constraint(">=1.0.0 <2.0.0", "1.5.0"), None);
        assert_eq!(rewrite_constraint("^1.0.0 || ^2.0.0", "1.5.0"), None);
        // A single constraint that merely spaces its operator is still rewritten.
        assert_eq!(
            rewrite_constraint(">= 1.0.0", "1.5.0").as_deref(),
            Some(">= 1.5.0")
        );
    }

    #[test]
    fn apply_edits_replaces_recorded_span() {
        // `serde = "^1.0"` — replace the `^1.0` span (bytes 9..13) on line 1.
        let content = "[dependencies]\nserde = \"^1.0\"\n";
        let edits = vec![Edit {
            line: 1,
            start: 9,
            end: 13,
            replacement: "^1.5.0".to_string(),
        }];
        let out = apply_edits(content, &edits);
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
                replacement: "1.9".to_string(),
            },
            Edit {
                line: 0,
                start: 8,
                end: 11,
                replacement: "2.9".to_string(),
            },
        ];
        let out = apply_edits(content, &edits);
        assert_eq!(out, "a=1.9 b=2.9\n");
    }

    use dependable_fetch::core::{
        DependencyKind, ManifestKind, parse, resolve_workspace_inheritance,
    };

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
        let (updated, records) = plan_fixes(content, &results, false);

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
        let (updated, records) = plan_fixes(content, &results, false);

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
        let (updated, records) = plan_fixes(content, &results, false);

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

        let (updated, records) = plan_fixes(member, &results, false);

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

        let (updated, records) = plan_fixes(root, &results, false);

        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(updated, "[workspace.dependencies]\nserde = \"1.0.219\"\n");
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

        let (updated, records) = plan_fixes(content, &results, false);

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

        let (updated, records) = plan_fixes(content, &results, true);

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
}
