# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
