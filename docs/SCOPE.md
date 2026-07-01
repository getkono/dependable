# Dependable — Scope & Roadmap

This document finalizes what **V1** delivers and enumerates everything deferred from
[`dependable-prd.md`](dependable-prd.md). Every deferred row is tracked as a GitHub
issue under a milestone (`V1.1`, `V2`, `V3`); filter the issue tracker by milestone or
by label (`ecosystem`, `report`, `decision`, …).

For **where `dependable` sits among existing dev tools** — what it complements
(Dependabot/Renovate), supersedes, and deliberately will not build — see
[`INTEGRATIONS.md`](INTEGRATIONS.md).

---

## 1. V1 deliverables (finalized)

V1 is a **working MVP for the Rust / Crates.io ecosystem only**. It proves the library
end-to-end and establishes the type model + traits that later ecosystems plug into.

| Deliverable | Kind | Responsibility |
|---|---|---|
| `dependable-core` | library | Pure, IO-free: parse `Cargo.toml` + `Cargo.lock`, the core data model, and the semver comparison engine. Zero filesystem/network/async. |
| `dependable-fetch` | library | The high-level, public end-to-end entry point: the `Checker` (parse → fetch → evaluate → OSV scan) over the crates.io sparse-index fetcher, OSV vulnerability client, and moka in-process cache. Re-exports the core types so external consumers depend on this crate alone. |
| `dependable` | application | CLI: `check` / `list` / `fix`, with `table` / `json` / `text` output, `.dependable.toml` + `DEPENDABLE_*` config, and `--fail-on` CI exit codes. |

`dependable-report` (the V2 crate) is **not** created in V1.

## 2. V1 feature-complete criteria

V1 is "done" when `dependable check .` runs end-to-end on a real Cargo project and:

- [ ] discovers `Cargo.toml` manifests under a path (depth-limited; skips `target/`, `node_modules/`, `.git/`, `vendor/`);
- [ ] parses `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[dependencies.<name>]`, `[workspace.dependencies]`, recording version **positions** for `--fix`;
- [ ] classifies `path`/`git`/`workspace` deps as `Local`/`Git` and skips them;
- [ ] reads `Cargo.lock` to show the locked version (toggle with `--no-lock-file`);
- [ ] fetches available versions from the crates.io sparse index (yanked filtered out);
- [ ] classifies each dep `UpToDate` / `PatchAvailable` / `UpdateAvailable` / `Outdated` via the semver engine;
- [ ] scans OSV (`querybatch`, ecosystem `crates.io`) and marks `Vulnerable` deps (`--no-vuln`, `--include-ghsa`);
- [ ] renders `table` (colored, TTY-aware), `json`, and `text`;
- [ ] applies in-place upgrades with `fix` (`--dry-run`, `--all`) on `Cargo.toml`;
- [ ] returns the right exit code for `--fail-on none|outdated|vulnerable|any`;
- [ ] core is covered by pure unit tests; fetch is covered by hermetic (wiremock) tests; live network tests are `#[ignore]`d.

---

## 3. Deferred work

### A1 — Deferred ecosystems (9)

Each ecosystem ships as one unit: manifest parser + registry fetcher + lockfile parser (where applicable) + any version-format conversion. All target **V1.1**.

> **Status update:** Go, npm/JS-TS, Deno/JSR, pnpm, PHP, and Python are now implemented
> end-to-end (marked 🧪 Experimental until battle-tested); Dart, C#/.NET, and Elixir remain
> in progress. See the **Supported languages** table in [`README.md`](../README.md) for the
> current, authoritative per-language status.

| Ecosystem | Parser crate | Manifest(s) | Lockfile | Registry endpoint | Version conversion | OSV name | PRD |
|---|---|---|---|---|---|---|---|
| Go | custom line | `go.mod` | — (`go.sum`?, see Q1) | `proxy.golang.org/<mod>/@v/list` (+ `/@latest`) | v-prefix normalize | `Go` | §5.1–5.4 |
| npm (JS/TS) | `serde_json` + scanner | `package.json` | `package-lock.json` | `registry.npmjs.org/<name>` (+ `dist-tags`) | native + alias resolve | `npm` | §5.1–5.4 |
| Deno / JSR | `serde_json` + scanner | `deno.json(c)` | — | `jsr.io/<pkg>/meta.json` | native semver | `npm` | §5.1, 5.2, 5.4 |
| pnpm | `serde_yaml` + scanner | `pnpm-workspace.yaml` | — | `registry.npmjs.org` | native semver | `npm` | §5.1, 5.2 |
| PHP | `serde_json` + scanner | `composer.json` | `composer.lock` | `repo.packagist.org/p2/<name>.json` | native semver | `Packagist` | §5.1–5.4 |
| Python | custom + `toml_edit` | `requirements*.txt`, `pyproject.toml`, `pixi.toml` | — | `pypi.org/pypi/<name>/json` | **PEP 440** | `PyPI` | §5.1, 5.2, 5.4, 5.5 |
| Dart | `serde_yaml` + scanner | `pubspec.yaml` | `pubspec.lock` | `pub.dev/api/packages/<name>` | native semver | `Pub` | §5.1–5.4 |
| C# / NuGet | `roxmltree` | `*.csproj`, `Directory.*.props` | — | `api.nuget.org/v3/registration5-gz-semver2/…` | **NuGet bracket ranges** | `NuGet` | §5.1, 5.2, 5.4 |
| Elixir | `regex` | `mix.exs` | `mix.lock` | `hex.pm/api/packages/<name>` | **Hex `~>`** | `Hex` | §5.1–5.5 |

Cross-cutting enablers (also V1.1): extend `Ecosystem`/`ManifestKind` enums + `detect()`/`osv_name()`/`default_registry()` for all kinds; complete `UnstableFilter` (`IncludeIfCurrent`) + the per-ecosystem pre-release substring matrix.

### A2 — V2 features (reports & enterprise)

| Item | What it covers | Crate / dep | PRD |
|---|---|---|---|
| `dependable-report` crate | New 5th crate (`html/`, `sarif.rs`, `git.rs`, `policy.rs`) | `time` | §2, §3, §6 |
| OSV advisory enrichment | CVSS, severity, fixed versions, descriptions (feeds reports/SARIF/policy) | `POST /v1/query` | §5.6, §6.1 |
| HTML reports | `dependable report`: exec summary, vuln/dep tables, SVG charts, self-contained | `minijinja`, `base64` | §6.1 |
| Git comparative analysis | `--compare-to <ref>`: diff deps + vulns between tree and ref | `gix` | §6.2 |
| SARIF output | `--format sarif` (v2.1.0): `DEP001`/`DEP002`, locations, CVSS | hand-rolled serde | §6.6 |
| Policy enforcement | `[policy]`: `max_cvss`, `max_major_behind`, deny/min-version; exit 0/1/2 | `policy.rs` | §6.4 |
| GitHub Actions integration | PR annotations + job summary + published action | — | §6.3 |
| GitLab Code Quality | Code Quality JSON report | `serde_json` | §6.3 |
| First-party editor integration | Official LSP server and/or VSCode extension over `dependable-fetch`: inline outdated/vulnerable hints + quick-fixes | new crate / extension | §9, [`INTEGRATIONS.md`](INTEGRATIONS.md) §3 |
| Workspace / monorepo | Cross-manifest dedup, rollup, `--manifest-glob`, `workspace = true` inheritance | runner/cache | §6.5 |
| License visibility + allowlist | Show declared license in `list`; enforce `allowed_licenses` | registry fields | §6.4, §8 D6 |
| PDF export | `--pdf` via headless chromium (HTML stays self-contained) — **V3** | system chromium | §6.1, §8 D4 |

### A3 — V1.1 / future polish (non-goals that are real future work)

| Item | What it covers | PRD |
|---|---|---|
| Persistent disk cache | `~/.cache/dependable/…`, 1h TTL, `--no-cache` | §5.10, D1 |
| Cargo alternate registries + auth | `parse_cargo_config` over `$CARGO_HOME`, `Authorization` header | §4.4, §5.2, §9 |
| npm `.npmrc` private auth | Private registry tokens | §9 |
| `--fix` for JSON/YAML | Position-tracked edits to package.json / composer.json / pubspec.yaml | §8 D2 |
| Windows support | Officially tested target (rustls enables it) | §9 |
| `"latest"` resolution | Resolve `"latest"` → `dist-tags.latest` for display | §8 D8 |
| Rust feature-flag visibility | Expose feature names in `list` | §10 Q3 |

### A4 — Open decisions (D1–D9, PRD §8)

| ID | Decision | Disposition | Milestone |
|---|---|---|---|
| D1 | Disk cache in V1 or V1.1 | → V1.1 (disk-cache issue) | V1.1 |
| D2 | `--fix` format scope | Cargo.toml in V1; JSON/YAML in V1.1 | V1.1 |
| D3 | `serde_yaml` vs `marked_yaml` | **`serde_yaml` + line scanner** (shipped for pnpm/Dart); revisit only if its `unsafe` becomes a concern | V1.1 |
| D4 | PDF export approach | shell to chromium | V3 |
| D5 | Policy severity model | named bands + numeric `max_cvss` (numeric wins) | V2 |
| D6 | License checking depth | visibility + allowlist in V2; full graph V3 | V2/V3 |
| D7 | Multi-language output layout | **Grouped per manifest/ecosystem**, ecosystems fetched concurrently, `--depth 3` default (ratifies shipped behavior) | V1.1 |
| D8 | `"latest"` handling | resolve for display, don't rewrite on `--fix` | V1.1 |
| D9 | Telemetry | **None** — no telemetry in V1/V2; documented in [`README.md`](../README.md#privacy) | V1 (doc) |

### A5 — Open questions (Q1–Q8, PRD §10)

| ID | Question | Disposition | Milestone |
|---|---|---|---|
| Q1 | `go.sum` for locked versions | **Use `go.mod` constraints; defer `go.sum`** — it stores module checksums, not one resolved version per module | V1.1 |
| Q2 | pnpm catalog expansion | **Check `catalog:`/`catalogs:` definitions** in `pnpm-workspace.yaml`; **don't expand `catalog:` refs** back into each `package.json` | V1.1 |
| Q3 | Rust feature-flag visibility | feature-flags issue | V1.1 |
| Q4 | `requirements.txt` `-r` includes | tracking issue; informs Python | V1.1 |
| Q5 | `pyproject.toml` extras | tracking issue; informs Python | V1.1 |
| Q6 | NuGet bracket ranges | folded into C# (confirmed needed) | V1.1 |
| Q7 | Dart SDK constraint | folded into Dart (skip it) | V1.1 |
| Q8 | `no_std` core target | architecture issue | V2 / won't-do |

---

## 4. Milestone rollup

- **V1 (shipping):** Rust / crates.io MVP — the deliverables in §1. No issues; this is the baseline.
- **V1.1:** the 9 ecosystems + 2 core enablers (A1), the polish items (A3), and the V1.1 decisions/questions (A4/A5). Suggested order by demand: npm → Go → Python → the rest.
- **V2:** reports & enterprise (A2) + policy/license decisions, plus the first-party
  editor integration (LSP / VSCode extension over `dependable-fetch`; see
  [`INTEGRATIONS.md`](INTEGRATIONS.md)).
- **V3:** PDF automation, full license-compatibility graph, `no_std` resolution, and the PRD §9 supply-chain non-goals.
