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
    /// something has supplied the constraint declared elsewhere — the workspace root
    /// via [`resolve_workspace_inheritance`](crate::resolve_workspace_inheritance) for
    /// Cargo, the `[versions]` table for a Gradle catalog, the `<properties>` table
    /// for a POM. Without one the manifest states no version at all, and there is
    /// nothing to ask a registry for; a check reports such an item as
    /// [`Undetermined`](crate::result::DependencyStatus::Undetermined) rather than
    /// claiming it has no registry.
    ///
    /// A [`Locked`](PackageSource::Locked) item is read the same way and for the same
    /// reason: the version is real and worth asking a registry about, it simply was
    /// not written here. A lockfile entry that recorded no version at all — a branch
    /// pin — states nothing to check either.
    #[must_use]
    pub fn is_checkable(&self) -> bool {
        match self.source {
            PackageSource::Registry | PackageSource::Jsr => true,
            PackageSource::Inherited | PackageSource::Locked => !self.version_constraint.is_empty(),
            _ => false,
        }
    }

    /// Whether [`version_line`](Self::version_line) and the columns beside it describe a
    /// place in **this** manifest — what a reporter needs before it points at one.
    ///
    /// Since `0` is a legal line and column index, an unrecorded span is indistinguishable
    /// from a real one by value; it has to be inferred from the source instead. Every
    /// parser that declines to record a span also gives the item a source nothing would
    /// fetch, so [`is_checkable`](Self::is_checkable) covers all of them but two: a
    /// resolved [`Inherited`](PackageSource::Inherited) item is worth checking and still
    /// has no home here, because the version string it was resolved from belongs to
    /// another entry — a workspace root's table, a catalog `[versions]` alias, a shared
    /// POM `<properties>` value — and a [`Locked`](PackageSource::Locked) item is worth
    /// checking with no manifest entry anywhere to belong to.
    ///
    /// Both are named here explicitly rather than inferred from anything about the
    /// item, so a source added later starts out *without* a position and has to be
    /// added to this list deliberately. Getting that wrong is not a compile error: it
    /// silently hands the new source line `0` of this file, points reporters at it,
    /// and lets [`is_rewritable`](Self::is_rewritable) write over it.
    #[must_use]
    pub fn has_position(&self) -> bool {
        self.is_checkable()
            && !matches!(
                self.source,
                PackageSource::Inherited | PackageSource::Locked
            )
    }

    /// Whether the recorded span may be rewritten in place — it points here, and there is
    /// a value there to replace.
    ///
    /// Strictly narrower than [`has_position`](Self::has_position), which is why the two
    /// are separate: a bare `requirements.txt` requirement (`numpy`) is checkable and sits
    /// on a line worth reporting, but records a *zero-width* span, and writing a version
    /// into it would produce `numpy1.5.0`. `--fix` gates on this; the reporters, which
    /// only ever read the line, gate on `has_position`.
    #[must_use]
    pub fn is_rewritable(&self) -> bool {
        self.has_position() && !self.version_constraint.is_empty()
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
    /// A dependency that is not known to be a direct one: either recorded as
    /// transitive (`go.mod`'s `// indirect`), or drawn from a flattened
    /// resolution that marks direct and transitive pins alike (SwiftPM's
    /// `Package.resolved`). Either way, calling it direct would be a claim the
    /// file does not support.
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
    /// The dependency's version is declared **elsewhere in a manifest** — another
    /// entry, another table, another file — so there is no version string on this
    /// entry to check against or to rewrite.
    ///
    /// Three parsers emit it, for the same reason and with the same consequences:
    ///
    /// - Cargo's `dep.workspace = true` — the version is in the workspace root's
    ///   `[workspace.dependencies]`. Reading `workspace = true` needs no
    ///   filesystem, so the IO-free parser records the fact; *resolving* it does
    ///   need IO, and is
    ///   [`resolve_workspace_inheritance`](crate::resolve_workspace_inheritance)
    ///   applied by the caller that has the root in hand.
    /// - A Gradle version catalog entry whose `version.ref` names a `[versions]`
    ///   alias several entries share.
    /// - A Maven POM entry whose version comes from a `<properties>` value several
    ///   dependencies share, or from a `<parent>` / `<dependencyManagement>` /
    ///   undeclared property this file does not state.
    ///
    /// What keeps it distinct from [`Local`](Self::Local) is that the package is a
    /// real registry package — an entry that merely shares a name with a root
    /// `path` declaration is `Local`, and a POM `<scope>system</scope>` jar is
    /// `Local`, because neither has a registry at all.
    ///
    /// The constraint tells the two halves apart. Filled in, the version was found
    /// elsewhere and the item is checkable — never rewritable, since the string it
    /// would rewrite is not this dependency's own. Empty, no version was found at
    /// all, and a check reports
    /// [`DependencyStatus::Undetermined`](crate::result::DependencyStatus::Undetermined).
    ///
    /// A version that came from a *lockfile* is [`Locked`](Self::Locked), not this. It
    /// was never declared, so there is no central declaration for a consumer reading
    /// `inherited` to go and bump.
    Inherited,
    /// The version came from a **lockfile**, and no manifest declares it anywhere.
    ///
    /// SwiftPM is the case that needs it. A `Package.swift` is a Swift *program*, so
    /// this crate declines to read dependencies out of it; the entries come from
    /// `Package.resolved` instead, which records what the resolver picked and nothing
    /// about what was asked for. The package is real and published, so it is worth
    /// checking and worth scanning for advisories — but there is no manifest span
    /// anywhere to point at or to rewrite, which is what
    /// [`has_position`](Item::has_position) reads the source to decide.
    ///
    /// Mechanically identical to [`Inherited`](Self::Inherited)
    /// ([`is_checkable`](Item::is_checkable) without
    /// [`has_position`](Item::has_position)), and kept apart from it because the two
    /// tell a consumer different things. *Inherited* invites going to the central
    /// declaration and bumping it; a locked entry has no such declaration, and a
    /// consumer filtering on it would be chasing a file that does not exist.
    ///
    /// Distinct from a [`Registry`](Self::Registry) item that merely carries a
    /// [`locked_version`](Item::locked_version): that one was declared, was read from
    /// a manifest, and has a span. This one has no declaration behind it at all.
    Locked,
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
    fn a_registry_item_is_checkable_positioned_and_rewritable() {
        let serde = find(&items("[dependencies]\nserde = \"1.0\"\n"), "serde");
        assert!(serde.is_checkable());
        assert!(serde.has_position());
        assert!(serde.is_rewritable());
    }

    /// A bare requirement declares no version, so there is nothing to rewrite — its span
    /// is zero-width, and writing into it would produce `numpy1.5.0`. It is still on a
    /// real line of a real file, which is what a reporter needs.
    #[test]
    fn a_constraint_less_requirement_has_a_position_but_nothing_to_rewrite() {
        let parsed = parse(ManifestKind::RequirementsTxt, "flask==1.0\nnumpy\n")
            .expect("parses")
            .items;
        let numpy = find(&parsed, "numpy");

        assert!(numpy.is_checkable(), "a bare requirement is still fetched");
        assert!(numpy.has_position(), "line 2 of this very file");
        assert_eq!(numpy.version_line, 1);
        assert!(!numpy.is_rewritable(), "the span is zero-width");
    }

    #[test]
    fn path_and_git_items_are_neither() {
        let parsed = items(
            "[dependencies]\nutil = { path = \"../util\" }\ng = { git = \"https://example.com/g\" }\n",
        );
        for name in ["util", "g"] {
            let item = find(&parsed, name);
            assert!(!item.is_checkable(), "{name}");
            assert!(!item.has_position(), "{name}");
            assert!(!item.is_rewritable(), "{name}");
        }
    }

    /// The invariant `Locked` exists to hold. It has to behave exactly as `Inherited`
    /// does — checked, never pointed at, never rewritten — and nothing in the compiler
    /// enforces that: `PackageSource` is `#[non_exhaustive]` and every match on it
    /// carries a wildcard arm, so a `Locked` that fell through `is_checkable` would
    /// stop being checked, and one omitted from `has_position` would silently claim
    /// line 1 of a file that never declared it and become rewritable by `--fix`.
    #[test]
    fn a_locked_item_is_checkable_and_has_no_position() {
        let mut item = find(&items("[dependencies]\nserde = \"1.0.200\"\n"), "serde");
        item.source = PackageSource::Locked;
        item.locked_version = Some("1.0.200".to_owned());

        assert!(
            item.is_checkable(),
            "a lockfile pin is a real version to check"
        );
        assert!(
            !item.has_position(),
            "no manifest declared it, so no line may be pointed at"
        );
        assert!(
            !item.is_rewritable(),
            "`--fix` has nothing here to write to"
        );

        item.version_constraint.clear();
        assert!(
            !item.is_checkable(),
            "a pin with no version recorded states nothing to check"
        );
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
            !resolved.has_position(),
            "a resolved constraint still has no home in this file"
        );
        assert!(!resolved.is_rewritable());
    }
}
