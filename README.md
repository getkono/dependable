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
dependable check . --annotations always   # GitHub Actions annotations + job summary
dependable check . --manifest-glob 'services/*/Cargo.toml'  # one slice of a monorepo
dependable list .                 # every project and what it declares (offline)
dependable tree .                 # render the dependency tree (Rust)
dependable fix . --dry-run        # preview in-place upgrades
dependable report . > report.html # a self-contained HTML report
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

### Network cost of the vulnerability scan

With vulnerability scanning on (the default), `check` first asks OSV about every
dependency in one batch, and then issues **one additional `POST /v1/query` per
distinct vulnerable package version** to pull each advisory's full record —
severity vector, fixing versions, published dates, links. A clean run pays nothing
extra: with no vulnerable versions there is nothing to enrich. Those records are
what give the CVSS policy gate a score to compare and the HTML report something to
show. `--no-vuln` (or `[vulnerability] enabled = false`) skips the scan entirely
and restores the previous behaviour.

### Monorepos and workspaces

`check`, `fix`, and `list` walk every manifest under the path you give them, and
a repository with many members shares most of its dependencies. Each distinct
package is looked up **once per run**, whichever manifests declare it: one
request to the registry and one entry in the vulnerability scan, then the same
answer applied to each manifest, against that manifest's own declared
constraint. What each manifest says about a package stays its own — which is why
`fix` still rewrites the right line in the right file.

A multi-manifest run ends with a rollup that says how far it reached:

```
Overall (4 manifests, 37 unique packages) — Totals: 30 up to date · 5 patch · 2 update
```

The status counts are per *declaration*, not per package: a crate that is
outdated in three members counts three times, because it is three edits to make,
and because `--fail-on` gates one result at a time. `unique_packages` is the
deduplicated number, and sits beside them. `--format json` carries both in its
`summary` object.

To work on part of a repository, filter discovery with `--manifest-glob`:

```bash
dependable check . --manifest-glob 'services/*/Cargo.toml'
dependable check . --manifest-glob 'services/**/Cargo.toml' --depth 5
dependable fix . --manifest-glob 'crates/*/Cargo.toml' --dry-run
```

Patterns match each manifest's path relative to the directory being scanned,
written with `/` on every platform. `*` and `?` stop at `/` — `services/*/Cargo.toml`
does not reach `services/a/vendor/b/Cargo.toml` — and `**` crosses it. The flag is
repeatable and a manifest matching any pattern is kept. It composes with `--depth`,
which still bounds the walk (and defaults to 3, so a deeper pattern needs a bigger
number; `dependable` tells you when a pattern matched none of what it searched). It
conflicts with `--manifest`, which names one file and skips discovery altogether.

It is available on `fix` for a reason: without it, `dependable fix` would rewrite
manifests that the matching `dependable check` deliberately left out.

#### Inherited versions

A Cargo workspace declares shared versions once, at the root, and members opt in by
name:

```toml
# Cargo.toml
[workspace.dependencies]
serde = { version = "1.0.100", features = ["derive"] }

# crates/app/Cargo.toml
[dependencies]
serde.workspace = true
```

`check`, `fix`, and `list` all read the root, so `crates/app` reports `serde` at
`1.0.100` — including when you scan the member on its own with
`--manifest crates/app/Cargo.toml`, or with a `--manifest-glob` the root does not
match — the root is found by walking up from the member, stopping at the repository
boundary.

The crate is therefore reported once per manifest that declares it: at the root, and
at each member that opts in. That is one entry per place a reader has to look, and it
is how the status counts already work — `unique_packages` is the deduplicated number
beside them.

**`fix` rewrites an inherited version only at the root**, which is Cargo's own model:
the version string is not in the member's file, so there is no line there to change,
and running `fix` on a member leaves it byte-identical. For the same reason, SARIF
results and GitHub annotations for an inherited dependency name the member's file
without a line — the file is where the dependency is used, and no line in it is the
version. If the root declares a crate by `path` or `git`, the member inherits that
instead, and there is no registry version to check. A member's own `path` entry always
wins over a root declaration of the same name, exactly as Cargo resolves it.

`check --format json` names the manifest a constraint came from in `inherited_from`, on
the results that have one — an absolute, symlink-resolved path, because the root is found
by walking up rather than by anything the caller spelled, and a relative answer would be
relative to a directory the caller never named. A dependency the root turns out not to
declare gets no attribution at all, and a warning saying so.

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
dependable list --licenses         # add each dependency's declared license
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
          "source": "inherited",
          "locked": "1.0.228",
          "registry": null,
          "inherited": true,
          "license": "MIT OR Apache-2.0"
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

A dependency's `source` is `registry`, `jsr`, `git`, `local` (a `path` entry), or
`inherited` — a Cargo `dep.workspace = true`, whose version is declared once at the
workspace root. An inherited dependency is checked wherever it is used and rewritten
only where it is declared; see [Monorepos and workspaces](#monorepos-and-workspaces).

`license` appears only with `--licenses`, which — together with `--features` — is
the one thing in `list` that touches the network: a license is published by the
registry, not written in the manifest, so it costs one metadata request per
dependency. `--features` costs one index request per *distinct* crate in the
repository, however many members declare it. It is available for
crates.io, npm, PyPI, Packagist, and Hex; the Go module proxy, JSR, NuGet, and
pub.dev publish no metadata this tool can read, and are left blank rather than
guessed at. `--licenses` uses the default registry URLs, because `list` reads no
config file.

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

## HTML report (`report`)

`dependable report` renders **one self-contained HTML document** — inline CSS,
inline SVG charts, no external stylesheet, script, font, or image — so it opens
offline from a single file and survives being emailed or dropped into a CI
artifact. It goes to stdout by default:

```bash
dependable report . > report.html      # the obvious idiom
dependable report . -o report.html     # write the file directly
dependable report . --no-vuln          # skip the vulnerability scan
dependable report . --manifest Cargo.toml --depth 1
```

Five sections: an executive summary, a vulnerability detail table (one row per
dependency and advisory), a dependency status table per manifest, an advisory
timeline ordered by publication date, and an ecosystem breakdown — a pie chart
with a real table of the same figures beneath it, because the chart is decoration
and the table is the data. Manifest paths are stored relative to the report root,
so no absolute machine path lands in a document you share. Warnings the run would
otherwise leave only on a console — a skipped ecosystem, an unreadable lockfile,
vulnerability scanning being off — are carried into the document itself.

Every value in the document is HTML-escaped, advisory links are restricted to
`http`/`https` in Rust before they reach an `href`, and an advisory's Markdown
description is shown escaped and pre-wrapped rather than rendered.

To restyle it, drop replacements into `dependable-templates/` in the project root.
Any of these eight names can be replaced wholesale: `report.html`, `styles.css`,
`macros.html`, `summary.html`, `vulnerabilities.html`, `dependencies.html`,
`timeline.html`, `ecosystems.html`. A file with an unrecognized name, or one that
fails to parse, is a hard error naming the problem — there is no silent fall back
to the built-in.

`report` exits `0` whether or not it finds vulnerabilities: describing them is the
command's job. Use `check --fail-on` or a `[policy]` block to gate a build.

## License policy (`[policy] allowed_licenses`)

A `[policy]` block in `.dependable.toml` gates a build. Listing SPDX identifiers
in `allowed_licenses` turns on license collection for `check` automatically and
fails the run on a dependency whose declared license falls outside the list:

```toml
[policy]
allowed_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause"]
unknown_licenses = "warn"   # ignore | warn | fail
```

**An empty `allowed_licenses` is inert.** With no entry the license rule does not
run at all — `unknown_licenses` included — so a project that has not asked for
license policy never sees a license finding.

`unknown_licenses` governs the dependencies whose license could not be *measured*:
none was published, or what was published is not a readable SPDX expression. It
defaults to `warn`, because four of the nine registries publish no metadata at all
and PyPI's license field is free text — failing on every unknown would make the
rule unusable. What it never does is silently pass. A license that *was* read and
is not on the list is always a violation, whatever this is set to. If you set an
allowlist and no license data comes back at all, the run says so once rather than
leaving you with an unexplained wall of warnings.

The expression evaluator understands atoms, `OR`, `AND`, `WITH`, parentheses, and
the legacy crates.io `MIT/Apache-2.0` slash, case-insensitively. Four limits are
worth knowing:

- **`AND` is a conjunction.** `(MIT OR Apache-2.0) AND Unicode-DFS-2016` is a
  violation under `["MIT", "Apache-2.0"]`: there is no way to take the package
  without also taking `Unicode-DFS-2016`.
- **`WITH` is satisfied by the base license.** `Apache-2.0 WITH LLVM-exception`
  passes on a plain `Apache-2.0` entry, because an SPDX exception only ever grants
  *additional* permission. Naming the whole `A WITH B` pair works too. This is
  more permissive than `cargo-deny`, which requires the exception to be listed.
- **`+` is part of the identifier.** `GPL-2.0+` matches only an entry written
  `GPL-2.0+`, never `GPL-2.0` — "or later" can pull in GPL-3.0.
- **There is no identifier registry.** dependable knows your allowlist and nothing
  else, so an identifier that parses but is not listed is a violation whether it is
  real SPDX or a typo. `GPL-2.0` is not treated as `GPL-2.0-only`, and no
  compatibility or copyleft reasoning is performed.

Anything that is not an expression at all — `MIT License`, a pasted license body,
an unbalanced parenthesis — is reported as unreadable under `unknown_licenses`
rather than being reinterpreted.

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

Any CI system can use `--fail-on` and `--format json`. On GitHub Actions there
is a composite action that installs the released binary and runs the check:

```yaml
- uses: actions/checkout@v4
- uses: getkono/dependable/.github/actions/dependable-check@v0.1.4
  with:
    fail-on: vulnerable
```

It annotates the pull request — one `error` per vulnerable dependency, `warning`
per outdated one, `notice` per one that could not be checked, each attached to
the manifest line that declares it (to the manifest alone when the version lives
elsewhere, as an inherited one does) — and appends a summary table to the job
summary. See
[`.github/actions/dependable-check`](.github/actions/dependable-check/README.md)
for inputs, outputs, and permissions.

The same thing without the action, from any `dependable` on the runner:

```yaml
- run: dependable check . --fail-on vulnerable
```

`--annotations` chooses when: `auto` (the default) turns them on exactly when
`GITHUB_ACTIONS` is `true`, `always` reproduces them locally, `never` silences
both the annotations and the job summary. Annotations go to **stderr**, so
`--format json` and `--format sarif` still put a single valid document on
stdout.

This repository's own GitHub Actions workflow runs format checks, linting, and
tests on pushes to `main` and on pull requests, plus a coverage job that uploads
an `lcov.info` artifact.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
