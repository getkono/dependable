# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/getkono/dependable/compare/v0.1.3...v0.2.0) - 2026-10-12

### Added

- *(cli)* certify --fail-on over the manifests whose registries answered ([#203](https://github.com/getkono/dependable/pull/203))
- mark a nested workspace's crate in the tree, JSON, and TUI ([#186](https://github.com/getkono/dependable/pull/186))
- *(cli)* label an override in check's default table ([#175](https://github.com/getkono/dependable/pull/175))
- *(swift)* Package.resolved reader + SwiftURL OSV scanning (no registry client) ([#97](https://github.com/getkono/dependable/pull/97))
- *(jvm)* pom.xml parser — literal versions and same-file properties only ([#95](https://github.com/getkono/dependable/pull/95))
- *(check)* name the registries that declined to answer ([#141](https://github.com/getkono/dependable/pull/141))
- *(cli)* filter discovery by ecosystem ([#116](https://github.com/getkono/dependable/pull/116))
- *(fetch)* [**breaking**] report a dependency pinned to an exact version rather than leaving it unknown ([#120](https://github.com/getkono/dependable/pull/120))
- *(jvm)* wire the JVM ecosystem end to end
- *(core)* report a manifest we recognise but cannot read
- *(cli)* say which manifest an inherited constraint came from
- *(core)* tell a workspace-inherited dependency from a path one
- *(cli)* filter discovered manifests with --manifest-glob
- *(output)* count manifests and unique packages in the rollup
- *(cli)* annotate the pull request and write a GitHub job summary
- *(cli)* show declared licenses in list and wire the allowlist gate
- *(report)* HTML vulnerability reports via minijinja
- *(policy)* policy enforcement engine
- *(config)* load [policy] strictly
- *(report)* SARIF v2.1.0 output
- *(report)* scaffold dependable-report crate

### Fixed

- *(core)* read a bare npm version as exact, as node-semver does ([#198](https://github.com/getkono/dependable/pull/198))
- *(cli)* stop noting registry-less Swift pins as unread versions ([#195](https://github.com/getkono/dependable/pull/195))
- *(cli)* decline a lone-= partial as EqualsPartial, not Pinned ([#193](https://github.com/getkono/dependable/pull/193))
- *(cli)* give registry-less results their own GitHub notice text ([#189](https://github.com/getkono/dependable/pull/189))
- *(core)* treat a Gradle strictly version as a forced override ([#183](https://github.com/getkono/dependable/pull/183))
- *(core)* read a bare Dart version as exact, as pub does ([#184](https://github.com/getkono/dependable/pull/184))
- *(cli)* refuse an explicitly named --config that does not exist ([#180](https://github.com/getkono/dependable/pull/180))
- *(core)* inherit a POM's groupId and version from <parent> ([#179](https://github.com/getkono/dependable/pull/179))
- *(core)* read a full bare version as a pin where the ecosystem reads it exactly ([#178](https://github.com/getkono/dependable/pull/178))
- *(cli)* reject an unrecognised DEPENDABLE_FAIL_ON or DEPENDABLE_CONCURRENCY ([#173](https://github.com/getkono/dependable/pull/173))
- *(core)* read a bare NuGet Version as exact, not an inclusive minimum ([#169](https://github.com/getkono/dependable/pull/169))
- *(core)* never query an SE-0292 registry pin against SwiftURL ([#167](https://github.com/getkono/dependable/pull/167))
- *(cli)* count unread manifests in list's summary and state text's silence ([#165](https://github.com/getkono/dependable/pull/165))
- *(cli)* head an unread dependency list as unread in list too ([#115](https://github.com/getkono/dependable/pull/115))
- *(cli)* let an override's forced version be advanced on purpose ([#122](https://github.com/getkono/dependable/pull/122))
- *(cli)* report the updates fix declined instead of claiming none exist ([#108](https://github.com/getkono/dependable/pull/108))
- *(tui)* [**breaking**] report a dependency with no known version as unknown ([#104](https://github.com/getkono/dependable/pull/104))
- stabilization pass — twelve correctness fixes across core, fetch, cli and report ([#99](https://github.com/getkono/dependable/pull/99))
- *(cli)* let `list` stay quiet about an ecosystem that is switched off
- *(fix)* decline any constraint carrying an `@`
- *(fetch)* resolve an unread build script against its build root
- *(fix)* catch a wildcard segment wearing a suffix
- *(fix)* decline to rewrite a wildcard constraint
- *(fetch)* report a canonical root without the Windows verbatim prefix
- *(fetch)* resolve inheritance against a real ancestor, before the lockfile
- *(core)* gate a reported location on the position, not on the rewrite
- *(sarif)* make the scan-root test fixture absolute on Windows
- *(list)* fetch each crate's features once per run

### Other

- give the remaining scratch fixtures unique temp directories ([#197](https://github.com/getkono/dependable/pull/197))
- *(cli)* remove the unreachable PolicySource::Unreadable ([#192](https://github.com/getkono/dependable/pull/192))
- *(cli)* fail when a PackageSource variant has no list token or annotation decision ([#188](https://github.com/getkono/dependable/pull/188))
- build and test with default features off in its own step ([#168](https://github.com/getkono/dependable/pull/168))
- *(cli)* give each scratch fixture a per-process-unique directory ([#163](https://github.com/getkono/dependable/pull/163))
- *(core)* split a lockfile-supplied version out of PackageSource::Inherited ([#103](https://github.com/getkono/dependable/pull/103))
- *(fix)* decline a wildcard only where a bare version is not a caret range ([#106](https://github.com/getkono/dependable/pull/106))
- [**breaking**] harden the workspace-root descriptor before a second ecosystem uses it ([#102](https://github.com/getkono/dependable/pull/102))
- *(cli)* stop the tree tests depending on ambient colour detection ([#101](https://github.com/getkono/dependable/pull/101))
- Merge remote-tracking branch 'origin/master' into feat/82-gradle-version-catalogs
- Merge pull request #90 from getkono/refactor/83-generalize-workspace-inheritance
- *(fix)* say why the wildcard decline is blanket rather than per-ecosystem
- *(fetch)* resolve workspace roots from the manifest-kind descriptor
- *(fix)* show a wildcard constraint is narrowed to a pin
- compare workspace roots after the same normalization the code applies
- *(cli)* drop the runner's private copy of workspace discovery
- Merge remote-tracking branch 'origin/master' into upd79
- Merge remote-tracking branch 'origin/master' into upd78
- Merge remote-tracking branch 'origin/master' into upd77
- Merge remote-tracking branch 'origin/master' into upd76
- Merge remote-tracking branch 'origin/master' into upd75
- Merge remote-tracking branch 'origin/feat/17-policy-engine' into stack/v2-r2

## [0.1.3](https://github.com/getkono/dependable/compare/v0.1.2...v0.1.3) - 2026-08-29

### Added

- *(cli)* point a workspace member at its own tree in the forest
- *(fetch)* report lockfiles that are present but unreadable
- *(core)* parse bun.lock
- *(cli)* launch the TUI from a bare invocation
- *(cli)* report the repository's projects from `list`

### Fixed

- *(cli)* emit `/`-separated paths in machine-readable list output

### Other

- *(core)* expand the dependency forest through one shared walk
- *(fetch)* move manifest discovery into the library

## [0.1.2](https://github.com/getkono/dependable/compare/v0.1.1...v0.1.2) - 2026-07-02

### Other

- update Cargo.lock dependencies
