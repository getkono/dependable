# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/getkono/dependable/compare/v0.1.3...v0.1.4) - 2026-09-01

### Added

- *(cli)* say which manifest an inherited constraint came from
- *(core)* tell a workspace-inherited dependency from a path one
- *(report)* SARIF v2.1.0 output
- *(report)* scaffold dependable-report crate

### Fixed

- *(fix)* decline any constraint carrying an `@`
- *(fix)* catch a wildcard segment wearing a suffix
- *(fix)* decline to rewrite a wildcard constraint
- *(fetch)* report a canonical root without the Windows verbatim prefix
- *(fetch)* resolve inheritance against a real ancestor, before the lockfile
- *(core)* gate a reported location on the position, not on the rewrite
- *(sarif)* make the scan-root test fixture absolute on Windows

### Other

- Merge remote-tracking branch 'origin/master' into feat/82-gradle-version-catalogs
- Merge pull request #90 from getkono/refactor/83-generalize-workspace-inheritance
- *(fix)* say why the wildcard decline is blanket rather than per-ecosystem
- *(fix)* show a wildcard constraint is narrowed to a pin
- compare workspace roots after the same normalization the code applies
- *(cli)* drop the runner's private copy of workspace discovery
- Merge remote-tracking branch 'origin/master' into upd79
- Merge remote-tracking branch 'origin/master' into upd78
- Merge remote-tracking branch 'origin/master' into upd77
- Merge remote-tracking branch 'origin/master' into upd76
- Merge remote-tracking branch 'origin/master' into upd75

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
