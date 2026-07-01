# dependable

A fast, open-source CLI and Rust library for checking dependency versions and known
vulnerabilities — no API key, no cloud backend, a single static binary.

## Supported languages

| Language | Manifest(s) | Registry | Lockfile | Status |
| --- | --- | --- | --- | --- |
| Rust | `Cargo.toml` | crates.io | `Cargo.lock` | ✅ Stable |
| JavaScript / TypeScript | `package.json` | npm | `package-lock.json` | ✅ Stable |
| Python | `requirements*.txt`, `pyproject.toml`, `pixi.toml` | PyPI | — | ✅ Stable |
| Go | `go.mod` | Go proxy | — | 🧪 Experimental |
| Deno / JSR | `deno.json(c)` | JSR | — | 🧪 Experimental |
| pnpm | `pnpm-workspace.yaml` | npm | — | 🧪 Experimental |
| PHP | `composer.json` | Packagist | `composer.lock` | 🧪 Experimental |
| Dart / Flutter | `pubspec.yaml` | pub.dev | `pubspec.lock` | 🚧 Planned ([#7]) |
| C# / .NET | `*.csproj` | NuGet | — | 🚧 Planned ([#8]) |
| Elixir | `mix.exs` | Hex | `mix.lock` | 🚧 Planned ([#9]) |

**Status legend:**

- **✅ Stable** — maintainer-tested and used in anger.
- **🧪 Experimental** — implemented but not battle-tested by the maintainer; please
  [open an issue](https://github.com/getkono/dependable/issues) if you hit a rough edge.
- **🚧 Planned** — tracked, not yet shipped.

V2 reporting features and other deferred work are tracked as GitHub issues; see
[`docs/SCOPE.md`](docs/SCOPE.md) for the finalized scope and deferral plan.

[#7]: https://github.com/getkono/dependable/issues/7
[#8]: https://github.com/getkono/dependable/issues/8
[#9]: https://github.com/getkono/dependable/issues/9

## How it fits alongside your other tools

`dependable` **complements** Dependabot and Renovate rather than replacing them: they
own scheduled auto-update PRs, while `dependable` is the fast, on-demand check + `fix`
+ CI gate you run locally or in a pipeline — one tool that flags **outdated and
vulnerable** dependencies across the ecosystems it supports, with no cloud backend and
no API key. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for the full positioning
against existing dev tools.

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

## Use as a library

`dependable-fetch` is the high-level library: depend on it alone to scan a
`Cargo.toml` and report outdated or vulnerable dependencies. The `dependable` CLI
is a thin wrapper over the same `Checker` API, so the library and the CLI share one
implementation.

```toml
[dependencies]
dependable-fetch = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use dependable_fetch::{Checker, ManifestKind};

# async fn run() -> Result<(), dependable_fetch::CheckError> {
// Build once and reuse — clones share the HTTP pool and the version/OSV caches.
let checker = Checker::new()?;

// check_manifest takes content (ideal for in-memory / unsaved editor buffers);
// check_path(path) reads a manifest + its sibling lockfile off disk.
let manifest = std::fs::read_to_string("Cargo.toml")?;
let check = checker
    .check_manifest(ManifestKind::CargoToml, &manifest, None)
    .await?;

for result in check.outdated() {
    println!("{}: {}", result.item.name, result.status.label());
}
# Ok(())
# }
```

Only direct registry dependencies are checked (local/git/workspace deps are
skipped and transitive deps are never fetched), and the public API is
forward-compatible: enums are `#[non_exhaustive]` and the registry layer routes
per ecosystem, so future registries (npm, PyPI, Go, …) are additive.

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
- **`dependable-fetch`** — the high-level library: `Checker` ties parsing to async
  registry + OSV fetching and caching. The public end-to-end entry point for other
  tools; re-exports the core types so consumers need only this crate.
- **`dependable`** — the CLI binary; a thin wrapper over `dependable-fetch`.

## Git Hooks

Managed by [hk](https://hk.jdx.dev) (run `mise run hooks` once after cloning). The
pre-commit hook auto-fixes formatting and linting on staged files; the pre-push
hook runs format/lint checks plus the test suite and coverage.

## CI/CD

GitHub Actions runs format checks, linting, and tests on pushes to `main` and on
pull requests, plus a coverage job that uploads an `lcov.info` artifact.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
