//! The fundamental dependency unit as it appears in a manifest.

/// A single dependency as declared in a manifest.
///
/// Carries the byte position of the version *value* so the CLI can rewrite it in
/// place during `--fix` without disturbing surrounding formatting or comments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Item {
    /// Package name as declared in the manifest.
    pub name: String,
    /// Version constraint exactly as written (e.g. `"^1.2.3"`, `"=1.0.0"`).
    pub version_constraint: String,
    /// Source qualifier; non-registry sources are skipped for version checks.
    pub source: PackageSource,
    /// Zero-indexed line where the version value starts.
    pub version_line: usize,
    /// Byte offset of the version value start within that line (no quotes).
    pub version_col_start: usize,
    /// Byte offset of the version value end within that line (exclusive).
    pub version_col_end: usize,
    /// Alternate registry alias (Rust `registry = "..."`).
    pub registry: Option<String>,
    /// Resolved locked version from a lockfile, if available.
    pub locked_version: Option<String>,
    /// Which manifest section declared the dependency.
    pub kind: DependencyKind,
}

impl Item {
    /// Whether the constraint pins an exact version (`=1.2.3`, not `==`), which
    /// excludes it from a blanket `--update-all`.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        let c = self.version_constraint.trim_start();
        c.starts_with('=') && !c.starts_with("==")
    }

    /// Whether this item should be fetched + version-checked. Local and git
    /// sources are skipped.
    ///
    /// An [`Inherited`](PackageSource::Inherited) item is checkable only once
    /// [`resolve_workspace_inheritance`](crate::resolve_workspace_inheritance) has
    /// supplied the workspace root's constraint. Unresolved, the manifest states no
    /// version at all, and there is nothing to ask a registry for.
    #[must_use]
    pub fn is_checkable(&self) -> bool {
        match self.source {
            PackageSource::Registry | PackageSource::Jsr => true,
            PackageSource::Inherited => !self.version_constraint.is_empty(),
            _ => false,
        }
    }

    /// Whether the recorded version span points at a real value **in this manifest**,
    /// and may therefore be rewritten in place.
    ///
    /// This is the one rule behind three consumers — `--fix`'s edits, SARIF regions, and
    /// GitHub annotation lines — so none of them can drift from the others. It is
    /// deliberately narrower than [`is_checkable`](Self::is_checkable): an inherited
    /// dependency is worth checking, but its version string lives in the workspace root,
    /// so no position in *this* file is truthful. Since `0` is a legal line and column
    /// index, the absence of a position is carried by the source rather than by a
    /// sentinel value — an item whose span was never recorded reads as `0/0/0`, which
    /// every bounds check passes.
    #[must_use]
    pub fn is_rewritable(&self) -> bool {
        self.is_checkable()
            && self.source != PackageSource::Inherited
            && !self.version_constraint.is_empty()
    }
}

/// Which manifest section a dependency was declared in.
///
/// Manifests distinguish dependencies a package needs at runtime from ones only its
/// own development, build, or optional configurations need. The distinction is not
/// used for version checking — every checkable item is checked the same way — but a
/// consumer taking inventory of a repository needs it to tell a runtime dependency
/// from a test-only one.
///
/// Ecosystems that expose no section signal (`deno.json` imports, `mix.exs` deps,
/// `requirements.txt` lines) report [`DependencyKind::Normal`]; guessing from a file
/// name or an `only:` option would be a heuristic, not a reading of the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DependencyKind {
    /// A runtime dependency (`[dependencies]`, `dependencies`, `require`, …).
    #[default]
    Normal,
    /// Needed only to develop or test the package (`[dev-dependencies]`,
    /// `devDependencies`, `require-dev`, Poetry/PEP 735 groups, …).
    Dev,
    /// Needed only to build the package (Cargo `[build-dependencies]`).
    Build,
    /// Installed only when an extra or optional feature is enabled (PEP 621
    /// `optional-dependencies`, npm `optionalDependencies`, …).
    Optional,
    /// An npm `peerDependencies` entry: required of the *consumer*, not installed.
    Peer,
    /// A central version declaration rather than a dependency of this package —
    /// Cargo's `[workspace.dependencies]`, pnpm catalogs, NuGet `PackageVersion`.
    /// Members opt in by name, so the declaration alone means nothing is depended on.
    Workspace,
    /// A transitive dependency the manifest records explicitly (`go.mod`'s
    /// `// indirect`). Not a direct dependency of the module.
    Indirect,
}

impl DependencyKind {
    /// A stable lowercase token for machine-readable output.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Dev => "dev",
            Self::Build => "build",
            Self::Optional => "optional",
            Self::Peer => "peer",
            Self::Workspace => "workspace",
            Self::Indirect => "indirect",
        }
    }

    /// Whether this is a dependency the package itself pulls in — everything except a
    /// central declaration ([`Workspace`](Self::Workspace)) and a recorded transitive
    /// ([`Indirect`](Self::Indirect)).
    #[must_use]
    pub fn is_direct(self) -> bool {
        !matches!(self, Self::Workspace | Self::Indirect)
    }
}

/// Where a dependency comes from. Determines whether it is version-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PackageSource {
    /// A normal registry package (the default).
    #[default]
    Registry,
    /// A JSR-hosted package (unused in V1).
    Jsr,
    /// A `path` dependency — skipped for version checks.
    Local,
    /// A git dependency — skipped for version checks.
    Git,
    /// A Cargo `dep.workspace = true`: the manifest opts into a version declared in
    /// the workspace root's `[workspace.dependencies]` and states none of its own.
    ///
    /// Reading `workspace = true` needs no filesystem, so the IO-free parser records it
    /// — which is what keeps it distinct from a [`Local`](Self::Local) `path` entry that
    /// happens to share a name with a root declaration. Resolving it against the root
    /// does need IO, and is [`resolve_workspace_inheritance`](crate::resolve_workspace_inheritance)
    /// applied by the caller that has the root in hand.
    Inherited,
}

#[cfg(test)]
mod tests {
    use crate::manifest::ManifestKind;
    use crate::parsers::{cargo_workspace::resolve_workspace_inheritance, parse};

    use super::*;

    fn items(content: &str) -> Vec<Item> {
        parse(ManifestKind::CargoToml, content)
            .expect("parses")
            .items
    }

    fn find(items: &[Item], name: &str) -> Item {
        items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("no item {name}"))
            .clone()
    }

    #[test]
    fn a_registry_item_is_both_checkable_and_rewritable() {
        let serde = find(&items("[dependencies]\nserde = \"1.0\"\n"), "serde");
        assert!(serde.is_checkable());
        assert!(serde.is_rewritable());
    }

    #[test]
    fn path_and_git_items_are_neither() {
        let parsed = items(
            "[dependencies]\nutil = { path = \"../util\" }\ng = { git = \"https://example.com/g\" }\n",
        );
        for name in ["util", "g"] {
            let item = find(&parsed, name);
            assert!(!item.is_checkable(), "{name}");
            assert!(!item.is_rewritable(), "{name}");
        }
    }

    /// An inherited dependency is checkable once — and only once — the workspace root
    /// has supplied a constraint. It is never rewritable, because the string it would
    /// rewrite is in the root, not here.
    #[test]
    fn an_inherited_item_becomes_checkable_but_never_rewritable() {
        let declarations = items("[workspace.dependencies]\nserde = \"1.0.200\"\n");
        let mut parsed = items("[dependencies]\nserde.workspace = true\n");

        let unresolved = find(&parsed, "serde");
        assert!(!unresolved.is_checkable(), "no constraint yet");
        assert!(!unresolved.is_rewritable());

        let _ = resolve_workspace_inheritance(&mut parsed, &declarations);

        let resolved = find(&parsed, "serde");
        assert!(resolved.is_checkable(), "the root supplied a constraint");
        assert!(
            !resolved.is_rewritable(),
            "a resolved constraint still has no home in this file"
        );
    }
}
