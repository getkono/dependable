# Dependable — Ecosystem candidates

`dependable` supports ten languages today; the [**Supported languages**](../README.md#supported-languages)
table in [`README.md`](../README.md) is authoritative for their status. This document
covers the other question: **why a language you use is not on that list, and what would
put it there.**

It exists because "no Kotlin support" is not itself a reason. Each of the three most
frequently asked-about absences — Swift, the JVM languages, and C/C++ — fails for a
different reason, at a different point in the pipeline, with a different amount of work
between here and there. Writing the bar down makes those answers checkable and gives a
contributor something to build against.

For what is deferred from the PRD, see [`SCOPE.md`](SCOPE.md). For how `dependable` sits
among existing tools, see [`INTEGRATIONS.md`](INTEGRATIONS.md).

---

## 1. The bar

An ecosystem is admitted when it can satisfy the seams the existing ten already run
through. These are not aspirational criteria; each one is a place in the code that will
not compile, or will silently misreport, if the ecosystem cannot meet it.

| Gate | Requirement | The seam it has to pass through |
|---|---|---|
| **G1** | **A declarative manifest** — parseable as `&str` → data, with no code execution | The `Parser` trait (`crates/dependable-core/src/parsers/mod.rs`) is pure by construction, and `dependable-core` is forbidden filesystem, network, and async. A manifest that is a program cannot be read here. |
| **G2** | **An addressable version literal** — a byte span pointing at the version text | `Item::version_line` / `version_col_start` / `version_col_end` (`crates/dependable-core/src/item.rs`) are what `plan_fixes` (`crates/dependable/src/fix.rs`) splices into. No span, no `fix`. |
| **G3** | **A canonical registry** returning a complete version list over HTTP, where a package is one string | `RegistryFetcher::fetch_versions(&str)` (`crates/dependable-fetch/src/registries/mod.rs`). The shape assumes one identifier and a bounded number of requests — the cost model `fetch_all` and the cache are built on. |
| **G4** | **A total version order** expressible as semver | `check_version` (`crates/dependable-core/src/semver/checker.rs`) takes no `Ecosystem` at all. Every dialect is translated *into* semver first (`semver/python.rs`, `nuget.rs`, `elixir.rs`); what cannot be translated is silently dropped. |
| **G5** | **An OSV ecosystem with published advisories** | `Ecosystem::osv_name` (`crates/dependable-core/src/ecosystem.rs`). A name OSV reserves but publishes no data for yields a scanner that is permanently, correctly empty. |
| **G6** | *(optional)* **A lockfile recording edges** | `graph_parser` (`crates/dependable-fetch/src/tree.rs`). Buys the resolved dependency tree, and nothing else. |

**G6 is genuinely optional.** Go and Dart ship without it and report
`GraphSource::Unsupported`, falling back to directly declared dependencies. G1–G5 are the
real bar; G6 only decides how much of the product an ecosystem gets.

### Calibration

The bar is not "as good as Cargo". It is "as good as the weakest thing already shipped",
and several shipped ecosystems clear it narrowly. Advisory counts below were read from
OSV's published data on 2026-08-31:

```
curl -s https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
curl -s https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
```

| Shipped ecosystem | G1 | G2 | G3 | G4 | G5 (advisories) | G6 |
|---|:--:|:--:|:--:|:--:|---|:--:|
| Rust | ✓ | ✓ | ✓ | ✓ native | 2,767 | ✓ |
| npm | ✓ | ✓ | ✓ | ✓ native | 228,449 | ✓ |
| Python | ✓ | ✓ | ✓ | ~ PEP 440 → semver | 25,110 | ✕ |
| Go | ✓ | ✓ | ✓ | ~ v-prefix | 8,982 | ✕ |
| PHP | ✓ | ✓ | ✓ | ✓ native | 7,039 | ✓ |
| C# / NuGet | ✓ | ✓ | ✓ | ~ bracket ranges | 1,877 | ✕ |
| Elixir | ~ `mix.exs` is Elixir code, read by regex | ✓ | ✓ | ~ Hex `~>` | 289 | ✓ |
| Dart | ✓ | ✓ | ✓ | ✓ native | **13** | ✕ |

Two of these are worth holding onto, because they set the floor a candidate is measured
against rather than the ceiling:

- **Dart passes G5 on 13 advisories.** A thin OSV ecosystem is not disqualifying.
- **Elixir passes G1 by regex over source.** `parsers/mix_exs.rs` is explicitly
  best-effort and, by its own doc comment, cannot distinguish a dev dependency from a
  runtime one. So "the manifest is code" is not automatically fatal either — but Elixir's
  `deps` list is a literal list in practice, which is what makes the regex honest. The
  question for a candidate is not *is it code* but *how often does reading it as text
  produce a wrong answer rather than no answer.*

---

## 2. Verdicts

### Swift — no registry, but a lockfile worth reading

**Fails G1, G2, G3, G6. Passes G4. Marginal on G5.**

SwiftPM identifies a package by its **git URL**, and discovers versions by **enumerating
git tags**. There is no canonical registry to query. SE-0292 defines a package registry
API, supported by SwiftPM since 5.7, but no dominant public instance operates one; the
Swift Package Index is a metadata index over git repositories, not a version-list
service. Satisfying G3 would mean a fetcher that enumerates tags against GitHub's
authenticated, rate-limited API — a different cost model from the one-request-per-package
assumption `fetch_all` and the cache are built on.

`Package.swift` is **executable Swift**. Ground truth requires `swift package
dump-package`, which needs a toolchain and a subprocess — exactly what `dependable-core`'s
IO-free invariant exists to forbid. The Elixir regex precedent does not transfer:
dependencies in a `Package.swift` are routinely assembled in loops, behind conditionals,
and from variables, so reading it as text produces *wrong* answers, not merely incomplete
ones.

**But `Package.resolved` is plain JSON** carrying the full flattened pin set — identity,
location URL, revision, and version for every resolved package. That is enough for locked
versions, for `list`, and for OSV scanning by URL against `SwiftURL` (62 advisories),
with **no `Package.swift` parser and no registry client at all**. It records no edges, so
it is the `pubspec.lock` shape: versions without a tree.

**The push-back.** That path ships a `check` that can report *vulnerable* but never
*outdated*, and cannot `fix` anything — you do not rewrite executable code. Half the
product, silently absent, on a per-manifest basis. That is not disqualifying, but it has
to be labelled as loudly as the `UnreadableLockfile` notice is, or a Swift user
reasonably concludes their dependencies are all current.

### JVM (Kotlin / Java / Scala) — the registry is fine; the manifest is the problem

**Passes G3 and G5 outright. Fails G6. Partial on G1, G2, G4.**

Nothing about the registry side is hard. **Maven Central is canonical**,
`maven-metadata.xml` returns the complete version list for an artifact, `groupId:artifactId`
is a single string that fits `fetch_versions` the way npm scopes and Go module paths
already do, and `roxmltree` is already a workspace dependency from the csproj parser.
**`Maven` is the largest language ecosystem in OSV that `dependable` does not cover —
7,058 advisories,** comparable to Packagist (7,039) and Go (8,982), both shipped. Larger
OSV ecosystems exist, but they are OS distributions — Debian, Ubuntu — which are a
different tool's job. On value per unit of work this is the strongest candidate by a wide
margin.

The blocker is G1. `build.gradle` and `build.gradle.kts` are Turing-complete build
scripts, and the versions that actually apply come from version catalogs, `ext`
properties, BOM and platform imports, convention plugins, and the Spring
dependency-management plugin. Ground truth is `./gradlew dependencies` — a JVM daemon,
minutes of wall time, and the execution of untrusted build code. `pom.xml` is declarative
XML, but real POMs need `${property}` interpolation, `<parent>` inheritance where the
parent POM may have to be **fetched from the registry**, `<dependencyManagement>`, and BOM
imports. That is a resolution engine, not a parser.

G4 is real but bounded: Maven's ordering is not semver — its qualifiers sort
`alpha < beta < milestone < rc < snapshot < "" < sp`, `1.0` equals `1.0.0`, and four or
more segments are common — and Gradle adds dynamic versions (`1.+`, `latest.release`) and
rich versions (`require` / `prefer` / `strictly` / `reject`). This needs a `semver/maven.rs`
on the existing `nuget.rs` pattern, lossier than the three translators already there.

**What is admissible is the declarative subset:**

1. **`gradle/libs.versions.toml`** — a Gradle version catalog is pure TOML: `[versions]`
   plus `[libraries]` entries carrying either a literal version or a `version.ref`.
   Explicit literals with byte spans, so G2 is satisfied and `--fix` comes free from the
   existing span machinery. Structurally this is Cargo's `workspace = true`, and that
   machinery already exists (`PackageSource::Inherited`, `resolve_workspace_inheritance`)
   — but `workspace_root_of` in `crates/dependable-fetch/src/discover.rs` hard-gates on
   `ManifestKind::CargoToml`. Generalizing that gate is the one real refactor between here
   and Kotlin support.
2. **`pom.xml`** with literal versions and same-file `<properties>`, no parent resolution.

Explicitly out of scope in both cases: evaluating Groovy or Kotlin build scripts,
fetching parent POMs, and resolving BOMs.

**The push-back.** A Gradle project that declares its dependencies inline in
`build.gradle.kts` — which is most of them — gets **nothing** from the catalog parser. A
partial answer about a build system whose manifest is a program is a support burden:
"dependable missed 40 of my dependencies" is a bug report you cannot close. The mitigation
is precedent rather than novelty. `GraphSource::Unsupported` and
`ManifestKind::unreadable_lockfiles` already exist to say *we saw this and could not read
it*, and a Gradle build script has to be reported that way rather than passed over in
silence, so a short list never reads as a complete one.

### C / C++ — the one to decline

**Fails G3, G4, and G5. Partial on G1. Fails G2 and G6.**

There is **no canonical C++ registry**, and this is not a gap waiting to close — it is
the shape of the ecosystem. A large fraction of real C++ dependencies arrive through
CMake `FetchContent`, CPM, git submodules, or the host distribution's package manager,
none of which is a package registry at all. Of the two contenders:

- **vcpkg has no HTTP registry API.** It is a git repository of ports; version history
  lives in `versions/<letter>-/<port>.json` inside that repository, and a project pins its
  entire dependency set through a single `builtin-baseline` commit SHA rather than
  per-dependency constraints. So `vcpkg.json` parses as JSON perfectly well and then turns
  out to carry **no version per dependency** — nothing for a current-versus-latest column
  to show, and nothing for `fix` to rewrite. That is a G2 failure hiding behind a G1 pass.
- **Conan Center has a real API**, but `conanfile.py` is Python code, and Conan versions
  are free-form strings (`cci.20210101`, `system`, `1.79.0`). `to_semver_versions`
  (`crates/dependable-fetch/src/check.rs`) uses `filter_map`, so unconvertible versions
  vanish from the candidate set without a word.

G4 fails outright rather than expensively: vcpkg's `version-string` scheme is **unordered
by design**. "Is this outdated" has no answer for such a port — not a hard answer, no
answer.

G5 fails on evidence. `vcpkg` and `ConanCenter` appear in the OSV *schema*, which is why
this looks tractable at first glance, but **OSV publishes no data for either**: neither
name appears in `ecosystems.txt`, and `all.zip` returns 404 for both. So the vulnerability
half of the tool would return nothing, correctly, forever. C and C++ advisories live in
NVD keyed by CPE, and name-to-CPE matching is a different product with a false-positive
profile — it is what OWASP dependency-check does, and
[`INTEGRATIONS.md`](INTEGRATIONS.md) already positions `dependable` away from it.

There is also a structural cost worth recording, because it applies to *any* future
ecosystem lacking an OSV name: `osv_name()` currently doubles as the disk-cache directory
name (`crates/dependable-fetch/src/check.rs`, `cache.rs`). Admitting an ecosystem with no
OSV ecosystem means separating "cache namespace" from "OSV query ecosystem" first.

**Verdict: not admitted.** C/C++ is the only candidate that fails a majority of the gates,
and two of those failures (no canonical registry, no total version order) are properties
of the ecosystem rather than of our effort.

---

## 3. Not planned without demand

Everything below is unbuilt for want of a demand signal, not because it was rejected. The
split is between candidates that would clear the bar and ones that would not.

**Would clear the bar today.** These need someone to want them:

| Language | Registry | OSV advisories | Note |
|---|---|---|---|
| Ruby | RubyGems | 4,657 | Passes every gate including G6 — `Gemfile.lock` records edges. Would score higher than several shipped ecosystems. |
| Julia | General registry | 1,717 | Declarative `Project.toml`, semver-native. |
| Haskell | Hackage | 32 | Declarative `.cabal` / `package.yaml`; thin advisory data, but thicker than Dart's. |
| OCaml | opam | 26 | Declarative `opam` files. |
| R | CRAN | 14 | `DESCRIPTION` is declarative; version ordering is CRAN's own. |

**Would not clear the bar.** Blocked for the reasons above:

| Language | Blocked on |
|---|---|
| Swift / CocoaPods | G5 — OSV publishes no CocoaPods data (the `SwiftURL` ecosystem covers SwiftPM only). |
| Zig | G3 and G5 — no canonical registry (`build.zig.zon` names URLs and hashes), no OSV ecosystem. |
| Perl / CPAN, Lua / LuaRocks, Nim | G5 — no published OSV ecosystem. |
| C / C++ | See §2. |

**The demand signal is an issue.** Open one with the `ecosystem` label describing the
project you would run this against. Ecosystems in the first table are a parser, a fetcher,
and a fixture away.

---

## 4. What would change our mind

Each trigger below is falsifiable and cheap to re-check, so this document can be revisited
on evidence rather than on argument.

| Candidate | Trigger | How to check |
|---|---|---|
| **JVM** | Nothing — it is admitted. The declarative slices are tracked as issues. | — |
| **Swift** | Either a public SE-0292 registry with meaningful adoption, or acceptance that a vulnerability-only `check` is worth shipping when clearly labelled. | Adoption is a judgement call; the `Package.resolved`-only path is tracked as an issue and needs no trigger. |
| **C / C++** | OSV publishing `vcpkg` or `ConanCenter` advisory data. That alone does not fix G3 or G4, but it is the gate that makes the rest worth reconsidering. | `curl -s https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt \| grep -iE 'vcpkg\|conan'` — currently returns nothing. |
| **Any language in §3** | An issue describing a real project. | — |

Open work arising from this evaluation is filed under the
[`ecosystem` label](https://github.com/getkono/dependable/labels/ecosystem).
