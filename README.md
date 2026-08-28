# dependable

> Status: Alpha - API is aggressively being stabilized.

A fast, open-source CLI and Rust library for checking dependency versions and known
vulnerabilities — no API key, no cloud backend, a single static binary.

## Installation

```sh
# Homebrew (macOS / Linux)
brew install getkono/tap/dependable

# aqua
aqua g -i getkono/dependable

# Cargo (from source; needs Rust 1.88 or newer)
cargo install --locked --git https://github.com/getkono/dependable dependable

# From a clone
mise run install
```

Or download a prebuilt binary for your platform from the
[latest release](https://github.com/getkono/dependable/releases/latest).

## Supported languages

| Language | Manifest(s) | Registry | Lockfile | Status |
| --- | --- | --- | --- | --- |
| Rust | `Cargo.toml` | crates.io | `Cargo.lock` | ✅ Stable |
| JavaScript / TypeScript | `package.json` | npm | `package-lock.json`, `bun.lock` | ✅ Stable |
| Python | `requirements*.txt`, `pyproject.toml`, `pixi.toml` | PyPI | — | ✅ Stable |
| Go | `go.mod` | Go proxy | — | 🧪 Experimental |
| Deno / JSR | `deno.json(c)` | JSR | — | 🧪 Experimental |
| pnpm | `pnpm-workspace.yaml` | npm | — | 🧪 Experimental |
| PHP | `composer.json` | Packagist | `composer.lock` | 🧪 Experimental |
| Dart / Flutter | `pubspec.yaml` | pub.dev | `pubspec.lock` | 🧪 Experimental |
| C# / .NET | `*.csproj`, `Directory.Packages.props` | NuGet | — | 🧪 Experimental |
| Elixir | `mix.exs` | Hex | `mix.lock` | 🧪 Experimental |

### Lockfiles

A lockfile is what turns "the manifest allows `^19.0.0`" into "you are actually
running 19.0.0", so it is what the resolved dependency tree and the age column
are built from. Where the Lockfile column above reads `—`, versions come from the
manifest's constraints instead and the tree shows only directly declared
dependencies.

| Lockfile | Locked versions | Resolved tree |
| --- | --- | --- |
| `Cargo.lock` | ✅ | ✅ |
| `package-lock.json` | ✅ | ✅ |
| `bun.lock` | ✅ | ✅ |
| `composer.lock` | ✅ | ✅ |
| `mix.lock` | ✅ | ✅ |
| `pubspec.lock` | ✅ | ✕ — records versions but not which package required which |

Not read: `yarn.lock`, `pnpm-lock.yaml`, `deno.lock`, `go.sum`, `uv.lock`,
`poetry.lock`, `Pipfile.lock`, `packages.lock.json`.

**Bun.** Only the text format, `bun.lock`, is supported. The older binary
`bun.lockb` cannot be read; when one is found, `dependable` says so and tells you
to run `bun install --save-text-lockfile` to migrate, rather than silently
reporting your dependencies as unlocked. A project with both is read from
`package-lock.json`.

**Status legend:**

- **✅ Stable** — maintainer-tested and used in anger.
- **🧪 Experimental** — implemented but not battle-tested by the maintainer; please
  [open an issue](https://github.com/getkono/dependable/issues) if you hit a rough edge.
- **🚧 Planned** — tracked, not yet shipped.

V2 reporting features and other deferred work are tracked as GitHub issues; see
[`docs/SCOPE.md`](docs/SCOPE.md) for the finalized scope and deferral plan.

## How it fits alongside your other tools

`dependable` **complements** Dependabot and Renovate rather than replacing them: they
own scheduled auto-update PRs, while `dependable` is the fast, on-demand check + `fix`
+ CI gate you run locally or in a pipeline — one tool that flags **outdated and
vulnerable** dependencies across the ecosystems it supports, with no cloud backend and
no API key. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for the full positioning
against existing dev tools.

## Privacy

`dependable` collects **no telemetry** — no analytics, no usage tracking, no
phone-home of any kind. The only network requests it makes are to the package
registries and the [OSV](https://osv.dev) vulnerability database required to check
your dependencies. No API key, no account, no cloud backend. This stance holds for
both V1 and V2 (decision D9 in [`docs/SCOPE.md`](docs/SCOPE.md)).

## Prerequisites

- [rustup](https://rustup.rs) — the Rust toolchain is pinned by `rust-toolchain.toml`.
- [mise](https://mise.jdx.dev) — task runner; also installs `hk` and `cargo-llvm-cov`.

```bash
mise install        # install hk + cargo-llvm-cov from mise.toml
mise run build
mise run install    # install the dependable binary into ~/.cargo/bin
```

## Usage

```bash
dependable                        # explore dependencies interactively (TUI)
dependable check [PATH]           # check a project (default: current dir)
dependable check . --format json  # machine-readable output (also: text)
dependable check . --fail-on vulnerable   # exit non-zero for CI
dependable list .                 # every project and what it declares (offline)
dependable tree .                 # render the dependency tree (Rust)
dependable fix . --dry-run        # preview in-place upgrades
```

## Interactive UI

Run `dependable` in a terminal and it opens a browser over your dependency graph:
every project in the repository, expanded to whatever depth you care to descend,
with each package's public metadata beside it.

```
dependable  ~/src/dependable   7 packages
┌ dependencies — 3 of 8 ────────────────────────────┐┌ details ────────────────────────────────┐
│  NAME                VERSION      AGE    STATUS   ││regex                                    │
│v Cargo.toml                                       ││   resolved  1.12.4                      │
│  v dependable-core   0.1.2               workspace││                                         │
│    v regex           1.12.4       1y     update   ││   registry  crates.io/crates/regex      │
│      v aho-corasick  1.1.4                        ││                                         │
│          memchr      2.8.2                        ││     latest  1.13.1                      │
│        regex-automat 0.4.18                       ││     status  update available            │
│      serde           1.0.228                      ││ advisories  none known                  │
│      toml_edit       0.22.27                      ││                                         │
│                                                   ││ repository  github.com/rust-lang/regex  │
│                                                   ││   homepage  not published               │
│                                                   ││       docs  docs.rs/regex/1.12.4        │
└───────────────────────────────────────────────────┘└─────────────────────────────────────────┘
press / to search, ? for help
```

A workspace member that another member depends on is shown as a pointer, `↗ …
(see root)`, at its own row near the top rather than copied into every tree that
reaches it; pressing the expand key on one jumps to that row. Press `?` for the
keys. `/` searches by glob — `serde*`, `@types/*`,
`{tokio,hyper}*` — and opens the tree along every path that matches, so a package
buried six levels down is one query away.

Every URL in the detail pane is a link: the package's page on its registry, that
exact version, the repository, the homepage, the documentation, each owner's
profile, and every advisory's OSV entry. Terminals that understand OSC 8 make
them clickable; `o` opens the selected package's link anywhere else.

The registry and version pages are derived from the package's name rather than
fetched, so they are on screen before anything has been looked up. Where an
ecosystem builds documentation for everything it hosts — docs.rs, HexDocs,
pub.dev — that page is offered too, whether or not the package declared one.

The mouse works too: click a row to select it, click its marker to open it, drag
the divider between the panes, and scroll with the wheel.

The tree is built offline from your lockfiles, so it appears instantly; the
network is touched only for the package you actually select. Resolved transitive
graphs are available for **Rust, npm, PHP, and Elixir**; other ecosystems show
their directly declared dependencies and say why.

Piped or in CI, a bare `dependable` prints help and exits 2 exactly as before —
the UI only starts when there is a terminal on both ends. `dependable tui` is the
explicit form.

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

## Project inventory (`list`)

`dependable list` answers "what lives in this repository" — every manifest it
discovers, what that manifest calls itself, and what it declares — without touching
the network. `--format json` emits it as one self-describing document, which is the
form to hand to a script or an agent:

```bash
dependable list                    # human-readable, one block per project
dependable list --format json      # the full inventory
dependable list --format text      # one tab-separated record per dependency
dependable list --no-lock-file     # skip lockfiles (no locked versions)
```

```json
{
  "schema": "dependable.list/v1",
  "root": ".",
  "summary": { "projects": 4, "dependencies": 53, "by_ecosystem": { "Rust": 4 } },
  "projects": [
    {
      "name": "dependable-core",
      "version": "0.1.2",
      "version_inherited": true,
      "ecosystem": "Rust",
      "role": "package",
      "manifest": "crates/dependable-core/Cargo.toml",
      "lockfile": "Cargo.lock",
      "dependencies": [
        {
          "name": "serde",
          "constraint": "1",
          "kind": "normal",
          "direct": true,
          "source": "registry",
          "locked": "1.0.228",
          "registry": null,
          "inherited": true
        }
      ]
    }
  ]
}
```

Each dependency's `kind` is the section that declared it — `normal`, `dev`, `build`,
`optional`, `peer`, `workspace` (a central declaration such as Cargo's
`[workspace.dependencies]`, a pnpm catalog, or a NuGet `PackageVersion`), or
`indirect` (a `go.mod` requirement marked `// indirect`). The last two are not
dependencies of the package itself, which is what `direct` says outright. A manifest
that declares only central versions — a virtual Cargo workspace root,
`pnpm-workspace.yaml`, `Directory.Packages.props` — has `"role": "workspace"` and no
name of its own.

Values a single manifest cannot supply are resolved from the repository and marked as
such: `version_inherited` for a Cargo `version.workspace = true`, `inherited` for a
constraint taken from `[workspace.dependencies]`, and `lockfile` for the lockfile that
supplied the locked versions — a workspace keeps one at its root, above its members.

Only *declared* dependencies are listed. The full resolved graph, transitive
dependencies included, is what `tree` renders.

## Dependency tree (`tree`)

`dependable tree` renders the workspace's dependency graph in the style of
`cargo tree`, distinguishing **in-workspace crates** (bold cyan, tagged
`(workspace)`) from **external** ones — so you can see how crates relate and, with
`--invert`, what a change to one crate affects downstream. It is **Rust-only and
fully offline**: the resolved graph is read straight from `Cargo.lock` (no network).

```bash
dependable tree                    # forest of all workspace members
dependable tree -p my-crate        # root at a single crate
dependable tree --invert -p my-lib # who depends on my-lib (downstream impact)
dependable tree --depth 1          # roots + their direct dependencies
dependable tree --format json      # nodes + edges, for tooling / IDEs
dependable tree --format dot | dot -Tsvg > deps.svg   # visual graph
```

```
my-app v0.1.0 (workspace)
├── gitdep v0.3.0 (git)
├── my-lib v0.1.0 (workspace) (see root)
└── serde v1.0.228
    └── serde_derive v1.0.228

my-lib v0.1.0 (workspace)
└── serde v1.0.228 (*)
```

Every workspace member is a root of the forest, so each one's dependencies are
shown **once**, at its own tree. Reached under another member it is a pointer,
`(see root)`, rather than a second copy — otherwise a workspace of any size
buries itself in repeats. Crates repeated elsewhere collapse to `(*)`.
`--no-dedupe` turns both off and expands every occurrence in place.

The tree is the **resolved union graph** from `Cargo.lock`: unlike
`cargo tree --edges` it does not distinguish normal/dev/build edges or feature
activation. When no `Cargo.lock` is present, `tree` prints a warning and falls
back to a shallow graph of each member plus its direct declared dependencies.

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
