# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/getkono/dependable/compare/dependable-report-v0.1.3...dependable-report-v0.1.4) - 2026-09-01

### Added

- *(jvm)* wire the JVM ecosystem end to end
- *(core)* tell a workspace-inherited dependency from a path one
- *(report)* enforce [policy] allowed_licenses with an unknown-license knob
- *(report)* SPDX subset evaluator for license expressions
- *(report)* HTML vulnerability reports via minijinja
- *(report)* aggregate counts via Report::summary()
- *(report)* [policy] schema and rule evaluator
- *(report)* scaffold dependable-report crate

### Fixed

- *(core)* gate a reported location on the position, not on the rewrite

### Other

- Merge remote-tracking branch 'origin/feat/17-policy-engine' into stack/v2-r2
