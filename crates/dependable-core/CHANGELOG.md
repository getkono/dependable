# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/getkono/dependable/compare/dependable-core-v0.1.3...dependable-core-v0.2.0) - 2026-10-12

### Added

- mark a nested workspace's crate in the tree, JSON, and TUI ([#186](https://github.com/getkono/dependable/pull/186))
- *(swift)* Package.resolved reader + SwiftURL OSV scanning (no registry client) ([#97](https://github.com/getkono/dependable/pull/97))
- *(jvm)* pom.xml parser — literal versions and same-file properties only ([#95](https://github.com/getkono/dependable/pull/95))
- *(cli)* filter discovery by ecosystem ([#116](https://github.com/getkono/dependable/pull/116))
- *(fetch)* [**breaking**] report a dependency pinned to an exact version rather than leaving it unknown ([#120](https://github.com/getkono/dependable/pull/120))
- *(core)* report a manifest we recognise but cannot read
- *(core)* parse Gradle version catalogs
- *(core)* translate Maven versions and constraints to semver
- *(core)* tell a workspace-inherited dependency from a path one
- *(core)* carry the registry-declared license on CheckResult
- *(core)* advisory data model on CheckResult

### Fixed

- *(report)* count the 0.x releases skipped when major_distance leaves 0.x ([#204](https://github.com/getkono/dependable/pull/204))
- *(core)* keep a Python pre-release of a < bound outside it ([#202](https://github.com/getkono/dependable/pull/202))
- *(tui)* compare a package lookup's versions in the ecosystem's own dialect ([#196](https://github.com/getkono/dependable/pull/196))
- *(core)* read a bare npm version as exact, as node-semver does ([#198](https://github.com/getkono/dependable/pull/198))
- *(core)* announce a POM's skipped <dependencyManagement> and <build><plugins> ([#194](https://github.com/getkono/dependable/pull/194))
- *(core)* treat a Gradle strictly version as a forced override ([#183](https://github.com/getkono/dependable/pull/183))
- *(core)* read only pixi pypi-dependencies, not conda [dependencies] ([#187](https://github.com/getkono/dependable/pull/187))
- *(core)* read a bare Dart version as exact, as pub does ([#184](https://github.com/getkono/dependable/pull/184))
- *(core)* report a nested overrides.<parent>["."] pin under the parent's name ([#182](https://github.com/getkono/dependable/pull/182))
- *(core)* inherit a POM's groupId and version from <parent> ([#179](https://github.com/getkono/dependable/pull/179))
- *(core)* read a full bare version as a pin where the ecosystem reads it exactly ([#178](https://github.com/getkono/dependable/pull/178))
- *(core)* keep the escape after a lone surrogate and anchor escaped JSON values at source offsets ([#177](https://github.com/getkono/dependable/pull/177))
- *(core)* read a bare NuGet Version as exact, not an inclusive minimum ([#169](https://github.com/getkono/dependable/pull/169))
- *(core)* never query an SE-0292 registry pin against SwiftURL ([#167](https://github.com/getkono/dependable/pull/167))
- *(core)* read a bare PEP 440 prefix wildcard as a prefix match, not a caret ([#166](https://github.com/getkono/dependable/pull/166))
- *(core)* bound json_scan nesting depth and push the path in place ([#164](https://github.com/getkono/dependable/pull/164))
- *(cli)* report the updates fix declined instead of claiming none exist ([#108](https://github.com/getkono/dependable/pull/108))
- *(tui)* [**breaking**] report a dependency with no known version as unknown ([#104](https://github.com/getkono/dependable/pull/104))
- stabilization pass — twelve correctness fixes across core, fetch, cli and report ([#99](https://github.com/getkono/dependable/pull/99))
- *(fetch)* choose among versions that translate alike by comparing them
- *(core)* read a Maven flavour off its whole trailing word run
- *(fetch)* bound the supersession walk, and ask who governs a subdirectory
- *(core)* read early-access, preview, and incubating builds as pre-releases
- *(jvm)* decide a Maven flavour from the published list, not from one word
- *(core)* read Maven's qualifiers as tokens, not as suffixes
- *(fetch)* resolve an unread build script against its build root
- *(core)* count every version.ref when deciding who owns a catalog line
- *(core)* gate a reported location on the position, not on the rewrite

### Other

- enforce missing_docs on dependable-core and dependable-fetch ([#205](https://github.com/getkono/dependable/pull/205))
- *(cli)* fail when a PackageSource variant has no list token or annotation decision ([#188](https://github.com/getkono/dependable/pull/188))
- *(core)* [**breaking**] mark WalkOptions and Tree #[non_exhaustive] and add WalkOptions builders ([#172](https://github.com/getkono/dependable/pull/172))
- *(core)* derive ALL_KINDS from the ManifestKind declaration ([#174](https://github.com/getkono/dependable/pull/174))
- *(fetch)* drive the workspace-root walk with a heterogeneous descriptor ([#170](https://github.com/getkono/dependable/pull/170))
- *(core)* split a lockfile-supplied version out of PackageSource::Inherited ([#103](https://github.com/getkono/dependable/pull/103))
- *(fix)* decline a wildcard only where a bare version is not a caret range ([#106](https://github.com/getkono/dependable/pull/106))
- [**breaking**] harden the workspace-root descriptor before a second ecosystem uses it ([#102](https://github.com/getkono/dependable/pull/102))
- Merge remote-tracking branch 'origin/master' into feat/82-gradle-version-catalogs
- Merge pull request #90 from getkono/refactor/83-generalize-workspace-inheritance
- *(core)* say why a catalog entry is a dependency, not a declaration
- *(core)* describe where a workspace root lives per manifest kind
- *(fix)* show a wildcard constraint is narrowed to a pin
- *(core)* refresh doc comments that still describe a Rust-only V1

## [0.1.3](https://github.com/getkono/dependable/compare/dependable-core-v0.1.2...dependable-core-v0.1.3) - 2026-08-29

### Added

- *(cli)* point a workspace member at its own tree in the forest
- *(core)* give each ecosystem its human-facing package pages
- *(fetch)* report lockfiles that are present but unreadable
- *(core)* parse bun.lock
- *(tui)* add the dependable-tui crate
- *(core)* rebuild resolved graphs from npm, Composer, and Mix lockfiles
- *(core)* read a Cargo manifest's build-time variation surface

### Fixed

- *(core)* do not point at a workspace member that has nothing to show
- *(core)* treat only source-less packages as workspace members
- *(core)* read target declarations the way Cargo tests for them
- *(core)* apply the edition-2015 auto-discovery rule
- *(core)* read every path a `build` array declares
- *(core)* declare the build script `build = true` names
- *(core)* distinguish an explicitly disabled build script from an absent one
- *(core)* count implicit features only where Cargo creates them
- *(core)* rewrite the deno specifier chain with `?`

### Other

- describe how a workspace member is shown once
- *(tui)* flatten rows through the shared walk
- *(core)* expand the dependency forest through one shared walk
- *(core)* allow a manifest to have several candidate lockfiles
- Merge pull request #67 from getkono/feat/list-project-inventory
