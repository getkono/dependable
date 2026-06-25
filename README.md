# dependable

A fast, open-source CLI and Rust library for checking dependency versions and known
vulnerabilities — no API key, no cloud backend, a single static binary.

> **Status:** V1 targets the **Rust / Crates.io** ecosystem as a working MVP. The
> nine other ecosystems and the V2 reporting features are tracked as GitHub issues.
> See [`docs/SCOPE.md`](docs/SCOPE.md) for the finalized scope and deferral plan.

## Prerequisites

- [rustup](https://rustup.rs) — the Rust toolchain is pinned by `rust-toolchain.toml`.
- [mise](https://mise.jdx.dev) — task runner; also installs `hk` and `cargo-llvm-cov`.

```bash
mise install        # install hk + cargo-llvm-cov from mise.toml
mise run build
```

## Usage

```bash
dependable check [PATH]           # check a project (default: current dir)
dependable check . --format json  # machine-readable output (also: text)
dependable check . --fail-on vulnerable   # exit non-zero for CI
dependable list .                 # list dependencies without checking
dependable fix . --dry-run        # preview in-place upgrades
```

`check` parses every `Cargo.toml` it finds, reads `Cargo.lock`, fetches versions
from the crates.io sparse index, classifies each dependency, and scans
[OSV](https://osv.dev) for known vulnerabilities:

```
Cargo.toml — Rust (5 dependencies)

Package  Current  Latest   Status
serde    1.0.100  1.0.228  patch available
tokio    1.20.0   1.52.3   3 vulnerabilities
time     0.2.7    0.3.51   1 vulnerability
```

## Development

| Command              | Description                                  |
| -------------------- | -------------------------------------------- |
| `mise run build`     | Build the workspace                          |
| `mise run test`      | Run tests (live network tests are skipped)   |
| `mise run test:live` | Run live crates.io + OSV smoke tests         |
| `mise run fmt`       | Format the workspace                         |
| `mise run lint`      | Clippy with warnings as errors               |
| `mise run coverage`  | Coverage report (informational)              |
| `mise run ci`        | Format check + lint + test (the CI gate)     |

## Workspace

- **`dependable-core`** — pure, IO-free parsing + version logic (`&str` → data).
- **`dependable-fetch`** — async registry + OSV fetch layer with caching.
- **`dependable`** — the CLI binary.

## Git Hooks

Managed by [hk](https://hk.jdx.dev) (run `mise run hooks` once after cloning). The
pre-commit hook auto-fixes formatting and linting on staged files; the pre-push
hook runs format/lint checks plus the test suite and coverage.

## CI/CD

GitHub Actions runs format checks, linting, and tests on pushes to `main` and on
pull requests, plus a coverage job that uploads an `lcov.info` artifact.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
