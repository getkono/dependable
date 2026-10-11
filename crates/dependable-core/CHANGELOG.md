# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/getkono/dependable/compare/dependable-core-v0.1.3...dependable-core-v0.2.0) - 2026-10-11

### Added

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
