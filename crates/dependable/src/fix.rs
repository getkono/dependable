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
/// prefix and substituting `new_version`. Returns `None` for compound forms that
/// can't be rewritten to a single version without changing their meaning: a
/// comma-separated range (Cargo `>=1.0, <2.0`), a space-separated range
/// (npm/pubspec `>=1.0.0 <2.0.0`), or a `||` alternation (`^1 || ^2`).
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
    // A dist-tag / channel name (`latest`, `next`, `beta`, …) starts with a letter
    // once any operator prefix is removed — it names a channel, not a version
    // range, so it must never be pinned to a concrete version (npm D8).
    if rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(format!("{prefix}{new_version}"))
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
    /// compatible target for each named dependency — enough to drive `plan_fixes`.
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
}
