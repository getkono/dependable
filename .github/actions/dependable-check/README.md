# `dependable-check`

A composite action that installs the released `dependable` binary and runs
`dependable check`, annotating the pull request and writing a job summary.

```yaml
- uses: actions/checkout@v4
- uses: getkono/dependable/.github/actions/dependable-check@v0.1.4
  with:
    fail-on: vulnerable
```

`actions/checkout` must run first — the action checks the workspace, it does not
fetch it.

## What you get

- **Annotations on the diff.** One per vulnerable (`error`), outdated
  (`warning`), and unresolvable (`notice`) dependency, attached to the manifest
  line that declares it.
- **A job summary.** A totals line plus a table per level, written to
  `GITHUB_STEP_SUMMARY`. Uncapped, unlike the annotations.
- **An exit code.** `0` clean, `1` the `fail-on` threshold was met, `2` a tool
  error.

Annotations are written to **stderr**, not stdout. The runner parses workflow
commands on both streams, so `format: json` and `format: sarif` keep stdout a
single valid document while the annotations still reach the pull request.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Project directory to scan. |
| `manifest` | `''` | Check one manifest instead of discovering them. |
| `config` | `.dependable.toml` | Config file path. |
| `fail-on` | `vulnerable` | `none`, `outdated`, `vulnerable`, or `any`. |
| `format` | `table` | `table`, `json`, `text`, or `sarif` — what goes to stdout. |
| `annotations` | `auto` | `auto`, `always`, or `never`. `never` also turns off the job summary. |
| `version` | `latest` | A release tag such as `v0.1.4`, or `latest`. |
| `args` | `''` | Extra arguments appended to `dependable check` verbatim. |

**`fail-on` defaults to `vulnerable`, deviating from the CLI's `none`.** This is
deliberate: an action that never fails is not a gate. Set `fail-on: none` to
report without blocking.

`args` is word-split like a `run:` block and carries the same trust level as
one. Every other input reaches the script through `env:` and is never
interpolated into the script text.

## Outputs

| Output | Meaning |
| --- | --- |
| `exit-code` | The CLI's exit code, always set — captured before the step re-exits with it, so a `continue-on-error` caller can branch on it. |
| `json-path` | Path to the captured JSON document. Set only when `format: json`. |

Counts are deliberately not outputs: they would duplicate the JSON schema and
drift from it.

```yaml
- uses: getkono/dependable/.github/actions/dependable-check@v0.1.4
  id: deps
  continue-on-error: true
  with:
    format: json
- run: jq '.summary' "${{ steps.deps.outputs.json-path }}"
  if: steps.deps.outputs.exit-code != '2'
```

## Permissions

None beyond the default. Annotations are produced by the runner from the
binary's own output and need no token.

`version: latest` reads the releases API and therefore needs `contents: read`
(the default). A workflow that sets `permissions: {}` must pin `version:` to a
tag, which skips the API call entirely.

## Pinning

Releases are tagged `v{version}` only — there is **no floating `v1` tag** — so
pin a full tag:

```yaml
uses: getkono/dependable/.github/actions/dependable-check@v0.1.4
```

`version: latest` resolves the newest release at run time; pinning `version:` to
the same tag as `uses:` makes the run fully reproducible.

## What the checksum does and does not buy

Every archive is downloaded with its sibling `.sha256` and verified before it is
extracted. That buys **integrity, not authenticity**: the checksum is published
in the same release as the archive, so it defends against a corrupted download,
not against a compromised release. Real provenance needs signing and build
attestation, which is deferred (see `docs/INTEGRATIONS.md`). Pin `version:` to a
tag you have reviewed if that distinction matters to you.

## Platforms

| `runner.os` / `runner.arch` | Target |
| --- | --- |
| `Linux` / `X64` | `x86_64-unknown-linux-gnu` |
| `Linux` / `ARM64` | `aarch64-unknown-linux-gnu` |
| `macOS` / `X64` | `x86_64-apple-darwin` |
| `macOS` / `ARM64` | `aarch64-apple-darwin` |
| `Windows` / `X64` | `x86_64-pc-windows-msvc` |

Anything else fails with an `::error::` naming the pair. There is no
`aarch64-pc-windows-msvc` release asset, so that combination fails by name
rather than as a 404.

## Marketplace

This action lives in a subdirectory, which means it **cannot be listed on the
GitHub Marketplace** — that requires an `action.yml` at the repository root. It
is fully usable by path, as above. A root `action.yml` would land in the
crates.io package tarball and would relabel the repository as "an action" in
GitHub's UI, so listing would be better served by a separate repository.

## Not used in this repository's own CI

The action installs a *released* binary, so dogfooding it on a pull request
would test the last release rather than the change under review. `ci.yml` runs
the workspace's own gates instead.
