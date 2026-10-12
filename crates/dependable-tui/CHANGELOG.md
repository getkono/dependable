# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/getkono/dependable/compare/dependable-tui-v0.1.3...dependable-tui-v0.2.0) - 2026-10-12

### Added

- mark a nested workspace's crate in the tree, JSON, and TUI ([#186](https://github.com/getkono/dependable/pull/186))
- *(jvm)* pom.xml parser — literal versions and same-file properties only ([#95](https://github.com/getkono/dependable/pull/95))
- *(fetch)* [**breaking**] report a dependency pinned to an exact version rather than leaving it unknown ([#120](https://github.com/getkono/dependable/pull/120))
- *(core)* report a manifest we recognise but cannot read

### Fixed

- *(tui)* compare a package lookup's versions in the ecosystem's own dialect ([#196](https://github.com/getkono/dependable/pull/196))
- *(tui)* [**breaking**] report a dependency with no known version as unknown ([#104](https://github.com/getkono/dependable/pull/104))
- *(fetch)* resolve an unread build script against its build root

### Other

- *(core)* [**breaking**] mark WalkOptions and Tree #[non_exhaustive] and add WalkOptions builders ([#172](https://github.com/getkono/dependable/pull/172))
- cover the UnreadableLockfile fallback for a v1 package-lock.json ([#171](https://github.com/getkono/dependable/pull/171))

## [0.1.3](https://github.com/getkono/dependable/compare/dependable-tui-v0.1.2...dependable-tui-v0.1.3) - 2026-08-29

### Added

- *(tui)* point a workspace member at its own row instead of copying it
- *(tui)* spin while a lookup is in flight
- *(tui)* link a package to the pages that describe it
- *(fetch)* report lockfiles that are present but unreadable
- *(tui)* give the tree aligned columns
- *(tui)* add the header band
- *(tui)* highlight the row under the pointer
- *(tui)* support the mouse
- *(tui)* map pointer positions to rows
- *(tui)* render hyperlinks with OSC 8
- *(tui)* show structured owners and both publish dates
- *(tui)* add a capability-aware semantic theme
- *(fetch)* record per-version publish dates
- *(fetch)* model package owners as structured records
- *(cli)* launch the TUI from a bare invocation
- *(tui)* add the dependable-tui crate

### Fixed

- *(core)* do not point at a workspace member that has nothing to show
- *(tui)* offer the docs a registry does not publish metadata for
- *(tui)* keep a discovery notice across the swap to real projects
- *(tui)* read the spinner clock once per frame
- *(tui)* treat a URL a registry left blank as one it never published
- *(tui)* say why a package was not looked up, whatever its kind
- *(tui)* map a click to the row it landed on
- *(tui)* size the help overlay to its longest entry
- *(tui)* stop a link leaving its label behind the next frame
- *(tui)* let ordinary text keep the terminal's own foreground
- *(tui)* never show registry data for a local package

### Other

- *(tui)* flatten rows through the shared walk
- *(tui)* render the tree with a stateful widget
