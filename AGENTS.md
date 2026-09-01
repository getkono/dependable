# dependable

Open-source CLI + Rust library for checking dependency versions and known
vulnerabilities. Ten ecosystems ship — Rust, npm, PyPI, Go, Deno/JSR, pnpm,
Packagist, pub.dev, NuGet and Hex — with Rust, npm and Python marked stable and the
rest experimental; see [`README.md`](README.md) for the support table and
[`docs/SCOPE.md`](docs/SCOPE.md) for what is deferred and why.

## Workspace

- **`dependable-core`** (`crates/dependable-core`) — pure, **IO-free** core: takes
  `&str` manifest content, returns plain data. **No filesystem, no network, no async.**
- **`dependable-fetch`** (`crates/dependable-fetch`) — the **high-level library** and
  public end-to-end entry point: the `Checker` (parse → fetch → evaluate → OSV scan)
  plus async IO (crates.io sparse index, OSV client, moka cache). Depends on and
  re-exports `dependable-core`, so external consumers (e.g. an IDE) need only this crate.
- **`dependable-report`** (`crates/dependable-report`) — the report and policy layer:
  HTML rendering (minijinja), SARIF v2.1.0, the SPDX license evaluator, and the
  `[policy]` engine. Pure like the core: it takes the finished report model and
  returns bytes, so it holds no IO of its own. A library only — it ships no binary.
- **`dependable-tui`** (`crates/dependable-tui`) — the interactive terminal UI
  (ratatui). Holds no IO of its own: it drives `dependable-fetch`. Its `App` state
  machine is free of both IO and ratatui, which is what makes navigation, search,
  and the loading states testable without a terminal.
- **`dependable`** (`crates/dependable`) — the CLI binary (clap); a thin wrapper over
  `dependable-fetch` that owns only discovery, config, output, fix, and exit codes. The
  `tree` command renders the workspace dependency graph offline via
  `dependable_fetch::build_workspace_graph` (no `Checker`, no network).

Five crates, published to crates.io in dependency order:
core → report → fetch → tui → dependable.

## Quality

Validate changes before committing:

```bash
mise run test         # correctness (cargo test --workspace)
mise run fmt:check    # formatting
mise run lint         # clippy -D warnings
mise run coverage     # coverage (informational, no threshold)
```

## Tooling

- **mise** runs tasks (`mise.toml`) and installs `hk` + `cargo-llvm-cov`.
- **hk** (`hk.pkl`) runs git hooks: pre-commit fixes, pre-push checks + tests.
- The Rust toolchain is owned by **`rust-toolchain.toml`** (not mise).

## Conventions

- Keep `dependable-core` free of IO and async — that invariant is what makes it
  unit-testable without mocking. Network/filesystem concerns live in `dependable-fetch`.
- Libraries use typed errors (`thiserror`); the binary may use `anyhow`.
- All `pub` items get doc comments. Mark fallible/important return types `#[must_use]`.
- Network-dependent tests are `#[ignore]`d and run via `mise run test:live`, so the
  default `mise run test` stays hermetic for CI.
- Conventional-commit messages (`feat:`, `fix:`, `chore:`, `docs:`).
