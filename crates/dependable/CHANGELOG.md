# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
