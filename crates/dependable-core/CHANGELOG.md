# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
