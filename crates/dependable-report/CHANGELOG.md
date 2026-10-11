# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/getkono/dependable/compare/dependable-report-v0.1.3...dependable-report-v0.2.0) - 2026-10-11

### Added

- *(jvm)* pom.xml parser — literal versions and same-file properties only ([#95](https://github.com/getkono/dependable/pull/95))
- *(jvm)* wire the JVM ecosystem end to end
- *(core)* tell a workspace-inherited dependency from a path one
- *(report)* enforce [policy] allowed_licenses with an unknown-license knob
- *(report)* SPDX subset evaluator for license expressions
- *(report)* HTML vulnerability reports via minijinja
- *(report)* aggregate counts via Report::summary()
- *(report)* [policy] schema and rule evaluator
- *(report)* SARIF v2.1.0 output
- *(report)* scaffold dependable-report crate

### Fixed

- stabilization pass — twelve correctness fixes across core, fetch, cli and report ([#99](https://github.com/getkono/dependable/pull/99))
- *(core)* gate a reported location on the position, not on the rewrite

### Other

- Merge remote-tracking branch 'origin/feat/17-policy-engine' into stack/v2-r2
- *(report)* depend on serde and serde_json
