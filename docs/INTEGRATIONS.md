# Dependable — Integrations & Positioning

This document finalizes **where `dependable` fits in the existing dependency-tooling
landscape**: the niche it owns, which tools it deliberately overlaps or supersedes,
which it complements, and which it will never try to replace. It is the authoritative
answer to "should `dependable` do X integration?" — the roadmap detail lives in
[`SCOPE.md`](SCOPE.md), the design detail in [`dependable-prd.md`](dependable-prd.md).

The guiding rule: **don't overlap existing tools for its own sake. Cut decisively,
and be the best in the world at one thing.**

---

## 1. The niche

`dependable` is the **fast, local, embeddable dependency check/fix engine**: a single
static binary and an IO-free Rust library that, in one pass across many ecosystems,
reports which of your declared dependencies are **outdated** *and* which have known
**vulnerabilities** (OSV/GHSA) — then optionally rewrites the versions in place with
`fix`.

What makes that a defensible niche rather than a me-too:

- **One tool, many ecosystems, one output schema.** Rust, Go, npm/Deno/pnpm, Python,
  and PHP today — instead of `cargo outdated` + `cargo audit` + `npm outdated` +
  `npm audit` + `pip list --outdated` + … each with its own flags and JSON shape.
- **Outdated *and* vulnerable in the same run.** Most tools do one or the other.
- **No cloud, no key, no account.** Vulnerability data is the public OSV API; every
  feature works offline-ish with a single binary. No dashboard, no SaaS, no telemetry.
- **Library-first and IO-free at the core.** `dependable-core` takes `&str` and
  returns plain data (no filesystem/network/async), and `dependable-fetch` is the
  end-to-end embedding point. Other tools — an editor, a bot, a service — depend on
  the crate, not on scraping our CLI output.
- **On-demand, not a bot.** It runs when *you* run it (locally, in CI, in an editor).
  It is not a hosted service that watches your repo and opens PRs on a schedule.

Everything below follows from that last point in particular: `dependable` is the
**engine and the checker**, not the **automation platform**.

---

## 2. Positioning vs. existing tools

Stances: **Complement** (different job, we stay out of theirs) · **Integrate** (we
emit/consume their format) · **Supersede-broader** (we do their job and more) ·
**Unify** (we replace N per-ecosystem one-offs with one tool) · **Not overlap**
(deliberately out of scope).

| Tool | Category | Our stance | Why |
|---|---|---|---|
| **GitHub Dependabot** | Hosted scheduled auto-update PR bot + alerts | **Complement** | We're the on-demand local/CI check + `fix` + `--fail-on` gate. We do **not** run on a schedule or open PRs. Keep Dependabot for unattended PR automation; reach for `dependable` for a fast, scriptable check and a one-shot local fix. |
| **Renovate** | Scheduled auto-update PR bot (hosted/self-host) | **Complement** | Same boundary as Dependabot — it owns the automated-PR workflow; we own the fast check/fix engine. |
| **Snyk Open Source** | Commercial vuln scan + fix PRs + cloud dashboard | **Not overlap (cloud/commercial)** | We overlap only on the free local vuln + outdated check (via OSV). We will not build a dashboard, a monitoring service, or a proprietary backend. |
| **GitHub Security tab / Advisory DB / Dependency graph** | Vulnerability data + a place to view results | **Integrate** | We *consume* OSV/GHSA advisory data and will *emit* SARIF (V2) so results land in the Security tab. We surface data through their UI rather than build our own. |
| **cargo-audit (RustSec)** | Rust-only vulnerability audit | **Supersede-broader** | We do vuln **and** outdated across many ecosystems in one binary; `cargo-audit` is Rust-only and vuln-only. |
| **cargo-outdated** | Rust-only outdated check | **Supersede-broader** | One tool across ecosystems, with vulnerability scanning folded into the same pass. |
| **npm audit / npm outdated / pip list --outdated / composer outdated / go list -m -u** | Per-ecosystem built-ins | **Unify** | One command and one JSON schema for a polyglot repo instead of a different tool per language. |
| **npm-check-updates (ncu)** | npm manifest version bumping | **Supersede-broader** | `dependable fix` rewrites version constraints in place, format-agnostic and multi-ecosystem — preserving the operator (`^1.0` → `^1.5.0`) so a constraint's meaning isn't silently changed. |
| **Dependi (VSCode extension)** | Inline in-editor version/vuln hints | **Reimplement engine + first-party editor integration (roadmap)** | `dependable` is the clean-slate, open-source engine (no code ported). The in-editor experience is now a committed roadmap item — a **first-party LSP and/or VSCode extension built on `dependable-fetch`** (see §3 and [`SCOPE.md`](SCOPE.md)). |
| **Trivy / Grype** | Container image / SBOM / supply-chain scanners | **Not overlap** | Images, SBOMs, and full transitive graphs are a different niche. We check the **direct** dependencies declared in your manifest. |
| **OWASP dependency-check** | Heavy, Java-centric CVE scanner | **Not overlap** | Different footprint and ecosystem focus; we stay a fast single binary. |

---

## 3. Integration surfaces we ship

These are the seams `dependable` exposes for other tools to build on. Status marks
what exists today vs. what is roadmapped (tracked as GitHub issues; see
[`SCOPE.md`](SCOPE.md)).

| Surface | What it is | Status |
|---|---|---|
| **Library (`dependable-fetch::Checker`)** | The recommended embedding point. `check_manifest(kind, &str, Option<&str>)` accepts in-memory content — ideal for **unsaved editor buffers** — while `check_path` reads from disk. Emits `ProgressEvent`s for UI progress; a `RegistryFetcher` trait makes new ecosystems purely additive; public types are `#[non_exhaustive]` for forward-compatibility. | **Shipping** |
| **CLI JSON output** (`--format json`) | A stable machine schema: a `summary` object plus a `results` array with `status` tokens (`OK`/`PATCH`/`UPDATE`/`OUTDATED`/`VULN`/`ERROR`/`LOCAL`/`GIT`). The generic path for scripting and non-GitHub CI. | **Shipping** |
| **CI exit codes** (`--fail-on none\|outdated\|vulnerable\|any`) | `0` = clean / threshold not met, `1` = threshold met, `2` = tool/fatal error. Also settable via `.dependable.toml` and `DEPENDABLE_FAIL_ON`. | **Shipping** |
| **`fix`** (`--dry-run`, `--all`) | In-place, position-preserving version rewrites of the **manifest only** — no lockfile edits, no PRs, no scheduled runs. The local, opt-in alternative to a bot's automated PR. | **Shipping** |
| **SARIF output** (`--format sarif`) | SARIF v2.1.0 (`DEP001` outdated / `DEP002` vulnerable, with locations + CVSS) so results upload into the GitHub Security tab and VS Code. | **Roadmap — V2** (#16) |
| **GitHub Actions** | A published action with PR annotations (`::error file=…,line=…::`) and a job summary. | **Roadmap — V2** (#18) |
| **GitLab Code Quality** | Code Quality JSON report format. | **Roadmap — V2** (#19) |
| **First-party editor integration** | An official **LSP server and/or VSCode extension** built on `dependable-fetch` — inline outdated/vulnerable hints and quick-fixes, powered by the same engine as the CLI. | **Roadmap — target V2** (new) |

---

## 4. Integrations we will not build

The decisive cut. These are out of scope on purpose — building them would either
duplicate a tool that already does the job well, or drag `dependable` away from being
a fast, local, single-binary engine.

- **A scheduled auto-update PR bot or hosted service.** This is Dependabot's and
  Renovate's job. We do not watch repos, run on a cron, or open pull requests.
- **Package installation or build steps.** We never run `cargo install`, `npm install`,
  etc. We check and optionally rewrite version strings — nothing more.
- **Transitive dependency graphs / SBOMs / container scanning.** We check the direct
  dependencies declared in a manifest. Full-graph and image scanning belong to
  Trivy/Grype/OWASP-style tools.
- **Supply-chain attestation** (Sigstore, provenance verification). V3 at the earliest;
  out of scope today.
- **A proprietary cloud backend, account, or telemetry.** Everything works without an
  API key or paid service, and `dependable` collects no telemetry.

---

## 5. See also

- [`SCOPE.md`](SCOPE.md) — the finalized V1 deliverables and the milestone roadmap
  (V1.1 / V2 / V3), where each surface above is tracked as an issue.
- [`dependable-prd.md`](dependable-prd.md) — the product requirements: §1 principles,
  §6 the V2 report/CI/SARIF designs, and §9 Non-Goals.
- The GitHub issue tracker — filter by the `ci`, `report`, and `ecosystem` labels for
  the concrete integration work items.
