# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/getkono/dependable/compare/dependable-fetch-v0.1.3...dependable-fetch-v0.2.0) - 2026-10-12

### Added

- *(cli)* certify --fail-on over the manifests whose registries answered ([#203](https://github.com/getkono/dependable/pull/203))
- mark a nested workspace's crate in the tree, JSON, and TUI ([#186](https://github.com/getkono/dependable/pull/186))
- *(swift)* Package.resolved reader + SwiftURL OSV scanning (no registry client) ([#97](https://github.com/getkono/dependable/pull/97))
- *(jvm)* pom.xml parser — literal versions and same-file properties only ([#95](https://github.com/getkono/dependable/pull/95))
- *(check)* name the registries that declined to answer ([#141](https://github.com/getkono/dependable/pull/141))
- *(fetch)* [**breaking**] resolve a nested workspace's members against their own root ([#137](https://github.com/getkono/dependable/pull/137))
- *(fetch)* [**breaking**] report a dependency pinned to an exact version rather than leaving it unknown ([#120](https://github.com/getkono/dependable/pull/120))
- *(core)* report a manifest we recognise but cannot read
- *(fetch)* fetch versions from Maven Central
- *(fetch)* resolve a member's inherited constraints in the Checker
- *(core)* tell a workspace-inherited dependency from a path one
- *(fetch)* collect registry-declared licenses as an opt-in check pass
- *(osv)* detailed advisory enrichment (CVSS, severity, fixed versions, refs)
- *(osv)* fetch full advisory records with computed CVSS scores

### Fixed

- *(report)* count the 0.x releases skipped when major_distance leaves 0.x ([#204](https://github.com/getkono/dependable/pull/204))
- *(tui)* compare a package lookup's versions in the ecosystem's own dialect ([#196](https://github.com/getkono/dependable/pull/196))
- *(core)* read a bare npm version as exact, as node-semver does ([#198](https://github.com/getkono/dependable/pull/198))
- *(core)* read a bare Dart version as exact, as pub does ([#184](https://github.com/getkono/dependable/pull/184))
- *(fetch)* drop the request URL from FetchError::Http so credentials in it are never printed ([#181](https://github.com/getkono/dependable/pull/181))
- *(fetch)* key the disk cache by the registry each lookup queries ([#176](https://github.com/getkono/dependable/pull/176))
- *(core)* read a bare NuGet Version as exact, not an inclusive minimum ([#169](https://github.com/getkono/dependable/pull/169))
- *(core)* never query an SE-0292 registry pin against SwiftURL ([#167](https://github.com/getkono/dependable/pull/167))
- *(cli)* report the updates fix declined instead of claiming none exist ([#108](https://github.com/getkono/dependable/pull/108))
- *(tui)* [**breaking**] report a dependency with no known version as unknown ([#104](https://github.com/getkono/dependable/pull/104))
- stabilization pass — twelve correctness fixes across core, fetch, cli and report ([#99](https://github.com/getkono/dependable/pull/99))
- *(fetch)* let a scanned module reach the build root that declares it
- *(fetch)* choose among versions that translate alike by comparing them
- *(fetch)* bound the supersession walk, and ask who governs a subdirectory
- *(jvm)* decide a Maven flavour from the published list, not from one word
- *(fetch)* report the newest spelling when two versions translate alike
- *(fetch)* report the version the registry publishes, not its translation
- *(fetch)* resolve an unread build script against its build root
- *(fetch)* report a canonical root without the Windows verbatim prefix
- *(fetch)* resolve inheritance against a real ancestor, before the lockfile
- *(core)* gate a reported location on the position, not on the rewrite
- *(list)* fetch each crate's features once per run
- *(pypi)* resolve the license from PEP 639 and classifiers before free text

### Other

- enforce missing_docs on dependable-core and dependable-fetch ([#205](https://github.com/getkono/dependable/pull/205))
- *(fetch)* reattach check_path's doc comment to check_path ([#191](https://github.com/getkono/dependable/pull/191))
- *(fetch)* pin that a failing scoped npm registry is reported under its own root ([#185](https://github.com/getkono/dependable/pull/185))
- cover the UnreadableLockfile fallback for a v1 package-lock.json ([#171](https://github.com/getkono/dependable/pull/171))
- *(fetch)* drive the workspace-root walk with a heterogeneous descriptor ([#170](https://github.com/getkono/dependable/pull/170))
- *(core)* split a lockfile-supplied version out of PackageSource::Inherited ([#103](https://github.com/getkono/dependable/pull/103))
- *(fix)* decline a wildcard only where a bare version is not a caret range ([#106](https://github.com/getkono/dependable/pull/106))
- [**breaking**] harden the workspace-root descriptor before a second ecosystem uses it ([#102](https://github.com/getkono/dependable/pull/102))
- *(fetch)* resolve workspace roots from the manifest-kind descriptor
- *(core)* refresh doc comments that still describe a Rust-only V1
- compare workspace roots after the same normalization the code applies
- *(fetch)* assert one registry request across manifests sharing a package

## [0.1.3](https://github.com/getkono/dependable/compare/dependable-fetch-v0.1.2...dependable-fetch-v0.1.3) - 2026-08-29

### Added

- *(fetch)* report lockfiles that are present but unreadable
- *(core)* parse bun.lock
- *(fetch)* record per-version publish dates
- *(fetch)* model package owners as structured records
- *(cli)* launch the TUI from a bare invocation
- *(tui)* add the dependable-tui crate
- *(fetch)* read public package metadata from registries
- *(fetch)* build resolved graphs for npm, PHP, and Elixir projects
- *(core)* record which section declared each dependency

### Fixed

- *(fetch)* fall back to the manifest when a lockfile root has no edges

### Other

- *(core)* expand the dependency forest through one shared walk
- *(core)* allow a manifest to have several candidate lockfiles
- *(fetch)* add live smoke tests for package metadata
- *(fetch)* move manifest discovery into the library
