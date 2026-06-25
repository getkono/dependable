//! In-place version rewriting for `Cargo.toml` (PRD decision D2: Cargo.toml only).

use std::path::Path;

use anyhow::Context;
use dependable_core::{CheckResult, DependencyStatus};
use toml_edit::{DocumentMut, value};

/// A single applied (or would-be-applied) version change.
#[derive(Debug, Clone)]
pub struct FixRecord {
    pub name: String,
    pub from: String,
    pub to: String,
}

/// Rewrite version constraints in `manifest` to the best available upgrade.
///
/// Uses `toml_edit`'s mutable document so surrounding formatting and comments are
/// preserved. Pinned (`=x.y.z`) deps are skipped unless `all` is set. With
/// `dry_run`, nothing is written.
///
/// # Errors
/// Returns an error if the manifest cannot be read, parsed, or written.
pub fn apply_fixes(
    manifest: &Path,
    results: &[CheckResult],
    all: bool,
    dry_run: bool,
) -> anyhow::Result<Vec<FixRecord>> {
    let content = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let mut doc: DocumentMut = content
        .parse()
        .with_context(|| format!("parsing {}", manifest.display()))?;

    let mut records = Vec::new();
    for result in results {
        if !result.item.is_checkable() {
            continue;
        }
        let updatable = matches!(
            result.status,
            DependencyStatus::PatchAvailable
                | DependencyStatus::UpdateAvailable
                | DependencyStatus::Outdated
                | DependencyStatus::Vulnerable
        );
        if !updatable {
            continue;
        }
        if result.item.is_pinned() && !all {
            continue;
        }

        let target = if all {
            result.latest_available.clone()
        } else {
            result.latest_compatible.clone()
        };
        let Some(target) = target else { continue };
        if target == result.item.version_constraint {
            continue;
        }

        if set_version(&mut doc, &result.item.name, &target) {
            records.push(FixRecord {
                name: result.item.name.clone(),
                from: result.item.version_constraint.clone(),
                to: target,
            });
        }
    }

    if !dry_run && !records.is_empty() {
        std::fs::write(manifest, doc.to_string())
            .with_context(|| format!("writing {}", manifest.display()))?;
    }
    Ok(records)
}

/// Set the version of `name` in any dependency section, preserving the entry's
/// shape (plain string vs. `{ version = "...", features = [...] }`).
fn set_version(doc: &mut DocumentMut, name: &str, target: &str) -> bool {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = doc.get_mut(section).and_then(|i| i.as_table_like_mut()) else {
            continue;
        };
        let Some(item) = table.get_mut(name) else {
            continue;
        };
        if item.is_str() {
            *item = value(target);
            return true;
        }
        if let Some(inner) = item.as_table_like_mut()
            && inner.contains_key("version")
        {
            inner.insert("version", value(target));
            return true;
        }
    }
    false
}
