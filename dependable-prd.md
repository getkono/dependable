# Dependable — Product Requirements Document

**Version:** 0.1 (Draft for Human Review)  
**Status:** Open for Feedback  
**Project:** `dependable` — a clean-slate, fully open-source dependency version checker and vulnerability scanner  

---

## Table of Contents

1. [Project Goals & Principles](#1-project-goals--principles)
2. [Architecture Overview](#2-architecture-overview)
3. [Cargo Workspace Layout](#3-cargo-workspace-layout)
4. [Core Data Structures](#4-core-data-structures)
5. [V1 Scope — Core Dependency Management](#5-v1-scope--core-dependency-management)
   - 5.1 [Supported Ecosystems](#51-supported-ecosystems)
   - 5.2 [Parser Design per Ecosystem](#52-parser-design-per-ecosystem)
   - 5.3 [Lock File Parsers](#53-lock-file-parsers)
   - 5.4 [Registry Fetcher Design](#54-registry-fetcher-design)
   - 5.5 [Version Comparison Engine](#55-version-comparison-engine)
   - 5.6 [Vulnerability Scanning (OSV)](#56-vulnerability-scanning-osv)
   - 5.7 [CLI Interface](#57-cli-interface)
   - 5.8 [Output Formats](#58-output-formats)
   - 5.9 [Configuration System](#59-configuration-system)
   - 5.10 [Caching Strategy](#510-caching-strategy)
6. [V2 Scope — Enterprise & Reports](#6-v2-scope--enterprise--reports)
   - 6.1 [HTML Vulnerability Reports](#61-html-vulnerability-reports)
   - 6.2 [Git-Based Comparative Analysis](#62-git-based-comparative-analysis)
   - 6.3 [CI/CD Integration](#63-cicd-integration)
   - 6.4 [Policy Enforcement](#64-policy-enforcement)
   - 6.5 [Workspace / Monorepo Support](#65-workspace--monorepo-support)
   - 6.6 [SARIF Output](#66-sarif-output)
7. [External Dependency Decisions](#7-external-dependency-decisions)
   - 7.1 [Core Crates (no_std compatible where noted)](#71-core-crates)
   - 7.2 [IO / CLI Crates](#72-io--cli-crates)
   - 7.3 [V2 Crates](#73-v2-crates)
   - 7.4 [Crates Explicitly Rejected and Why](#74-crates-explicitly-rejected-and-why)
8. [Design Decisions Requiring Human Feedback](#8-design-decisions-requiring-human-feedback)
9. [Non-Goals](#9-non-goals)
10. [Open Questions](#10-open-questions)

---

## 1. Project Goals & Principles

### What Dependable Is

Dependable is a command-line tool and Rust library for checking dependency versions and known vulnerabilities across 10 package ecosystems. It is a clean-slate open-source rewrite with no dependency on any proprietary backend.

### Core Principles

| Principle | Implication |
|---|---|
| **IO-independent core** | The parsing and version logic crate takes `&str` / `&[u8]` and returns plain data structs — zero file system or network calls. This makes the core fully unit-testable without mocking. |
| **Open-source complete** | All features work without an API key or cloud service. Vulnerability data is pulled from the public OSV API only. |
| **Clean-slate** | No code is ported from Dependi/crates. All parsing logic is reimplemented using appropriate Rust crates instead of hand-rolling tokenizers where a library exists. |
| **Composable** | The library crate is a first-class citizen. Other tools (editors, CI plugins, build scripts) can depend on `dependable-core` without pulling in the CLI or network stack. |
| **Predictable performance** | Registry fetches run concurrently. Parse + check a 200-dependency project in under 5 seconds on a warm cache. |
| **Minimal footprint** | No Electron, no Node, no Python. A single static binary. |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   dependable-core                        │
│  (pure library — no IO, no network, no filesystem)      │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ Parsers  │  │  Semver  │  │   Data Structures    │  │
│  │ (10 eco) │  │ Engine   │  │  Item, Dependency,   │  │
│  └──────────┘  └──────────┘  │  ParsedManifest, ... │  │
│                               └──────────────────────┘  │
└─────────────────────────────────────────────────────────┘
           ▲ depends on
┌─────────────────────────────────────────────────────────┐
│                   dependable-fetch                       │
│  (async IO layer — HTTP registries, file reading)       │
│                                                         │
│  ┌────────────────┐  ┌───────────────┐  ┌───────────┐  │
│  │ Registry       │  │ OSV Vuln      │  │  Cache    │  │
│  │ Adapters (10)  │  │ Client        │  │  (moka)   │  │
│  └────────────────┘  └───────────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────┘
           ▲ depends on
┌─────────────────────────────────────────────────────────┐
│                   dependable (CLI binary)                │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  clap    │  │  Output  │  │  Config  │  │  Fix   │  │
│  │  CLI     │  │ (table/  │  │  loader  │  │ writer │  │
│  │  args    │  │  json/   │  │          │  │        │  │
│  │          │  │  text)   │  │          │  │        │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
└─────────────────────────────────────────────────────────┘
           ▲ depends on (V2 only)
┌─────────────────────────────────────────────────────────┐
│                   dependable-report (V2)                 │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  minijinja   │  │  Git diff    │  │  SARIF       │  │
│  │  HTML        │  │  (gix)       │  │  writer      │  │
│  │  templates   │  │              │  │              │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Key invariant:** `dependable-core` has zero async code, zero network code, and zero filesystem calls. It compiles to `no_std` (with `alloc`) if required in future for embedded tooling contexts.

---

## 3. Cargo Workspace Layout

```
dependable/
├── Cargo.toml                   # workspace manifest
├── crates/
│   ├── dependable-core/         # pure parsing + version logic (lib only)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ecosystem.rs     # Ecosystem enum + ecosystem-specific constants
│   │       ├── item.rs          # Item struct
│   │       ├── dependency.rs    # Dependency struct
│   │       ├── manifest.rs      # ParsedManifest + ManifestKind
│   │       ├── parsers/
│   │       │   ├── mod.rs
│   │       │   ├── cargo_toml.rs
│   │       │   ├── go_mod.rs
│   │       │   ├── package_json.rs
│   │       │   ├── deno_json.rs
│   │       │   ├── pnpm_workspace.rs
│   │       │   ├── composer_json.rs
│   │       │   ├── requirements_txt.rs
│   │       │   ├── pyproject_toml.rs
│   │       │   ├── pubspec_yaml.rs
│   │       │   ├── mix_exs.rs
│   │       │   └── csproj.rs
│   │       ├── lockfiles/
│   │       │   ├── mod.rs
│   │       │   ├── cargo_lock.rs
│   │       │   ├── package_lock_json.rs
│   │       │   ├── composer_lock.rs
│   │       │   ├── pubspec_lock.rs
│   │       │   └── mix_lock.rs
│   │       └── semver/
│   │           ├── mod.rs
│   │           ├── checker.rs   # checkVersion() equivalent
│   │           ├── python.rs    # PEP 440 → semver conversion
│   │           ├── elixir.rs    # Hex requirements → semver
│   │           └── normalize.rs # operator/v-prefix normalization
│   │
│   ├── dependable-fetch/        # async IO layer (lib only)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── cache.rs         # moka-based TTL cache
│   │       ├── registries/
│   │       │   ├── mod.rs       # RegistryFetcher trait
│   │       │   ├── crates_io.rs
│   │       │   ├── npm.rs
│   │       │   ├── go_proxy.rs
│   │       │   ├── pypi.rs
│   │       │   ├── packagist.rs
│   │       │   ├── pub_dev.rs
│   │       │   ├── nuget.rs
│   │       │   ├── hex.rs
│   │       │   └── jsr.rs
│   │       └── osv/
│   │           ├── mod.rs
│   │           ├── client.rs    # OSV API calls
│   │           └── types.rs     # OSV response types
│   │
│   ├── dependable/              # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs           # clap definitions
│   │       ├── config.rs        # .dependable.toml loader
│   │       ├── runner.rs        # orchestration
│   │       ├── output/
│   │       │   ├── mod.rs
│   │       │   ├── table.rs
│   │       │   ├── json.rs
│   │       │   └── text.rs
│   │       └── fix.rs           # in-place version updater
│   │
│   └── dependable-report/       # V2: HTML/SARIF reports (lib + optional bin)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── html/
│           │   ├── mod.rs
│           │   └── templates/
│           ├── sarif.rs
│           ├── git.rs           # gix integration
│           └── policy.rs        # enterprise policy enforcement
│
├── .dependable.toml             # example project config
└── README.md
```

---

## 4. Core Data Structures

All defined in `dependable-core`. These are the foundational types all other crates build upon.

### 4.1 `Ecosystem`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Rust,
    Go,
    Npm,           // package.json, deno.json, pnpm-workspace.yaml
    Python,        // requirements.txt, pyproject.toml, pixi.toml
    Php,
    Dart,
    CSharp,
    Elixir,
}

impl Ecosystem {
    /// OSV ecosystem string for vulnerability queries
    pub fn osv_name(&self) -> &'static str { ... }
    
    /// Human-readable name
    pub fn display_name(&self) -> &'static str { ... }
    
    /// Default registry base URL
    pub fn default_registry(&self) -> &'static str { ... }
}
```

### 4.2 `ManifestKind`

```rust
/// Distinguishes between manifest files within the same ecosystem
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestKind {
    CargoToml,
    GoMod,
    PackageJson,
    DenoJson,         // deno.json / deno.jsonc
    PnpmWorkspaceYaml,
    ComposerJson,
    RequirementsTxt,  // requirements.txt / requirements.in / requirements-dev.txt
    PyprojectToml,    // pyproject.toml / pixi.toml
    PubspecYaml,
    MixExs,
    Csproj,           // *.csproj / Directory.Build.props / Directory.Packages.props
}

impl ManifestKind {
    pub fn ecosystem(&self) -> Ecosystem { ... }
    pub fn has_lockfile_support(&self) -> bool { ... }
    pub fn lockfile_name(&self) -> Option<&'static str> { ... }
    
    /// Detect from a file path
    pub fn detect(path: &Path) -> Option<Self> { ... }
}
```

### 4.3 `Item`

The fundamental unit representing a single dependency as it appears in the manifest. Carries position information to enable in-place `--fix` editing.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Package name as declared in the manifest
    pub name: String,

    /// Version constraint as written in the file (e.g. "^1.2.3", "~>1.0", ">=2,<3")
    pub version_constraint: String,

    /// Source qualifier for special package types (e.g. PackageSource::Jsr)
    pub source: PackageSource,

    /// Zero-indexed line where the version VALUE starts
    pub version_line: usize,

    /// Byte offset of version value start within that line
    pub version_col_start: usize,

    /// Byte offset of version value end within that line (exclusive)
    pub version_col_end: usize,

    /// For Rust: alternate registry name (e.g. "my-registry")
    pub registry: Option<String>,

    /// Resolved locked version from lock file (populated by lock file parser)
    pub locked_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PackageSource {
    #[default]
    Registry,
    Jsr,        // JSR-hosted packages in package.json / deno.json
    Local,      // file:, path:, workspace: — skipped for version checks
    Git,        // git:, github:, git+ — skipped for version checks
}
```

### 4.4 `ParsedManifest`

Return type of all parsers.

```rust
#[derive(Debug, Clone)]
pub struct ParsedManifest {
    pub kind: ManifestKind,
    pub items: Vec<Item>,
    /// Alternate registry declarations (Rust only)
    pub alternate_registries: Vec<AlternateRegistryDecl>,
}

#[derive(Debug, Clone)]
pub struct AlternateRegistryDecl {
    pub name: String,             // registry alias in Cargo.toml
    pub index_url: Option<String>,
    pub auth_token: Option<String>,
}
```

### 4.5 `Dependency`

Enriched `Item` after fetching — lives in `dependable-fetch`.

```rust
#[derive(Debug, Clone)]
pub struct Dependency {
    pub item: Item,
    pub available_versions: Vec<String>,     // sorted newest-first
    pub vulnerabilities: HashMap<String, Vec<VulnerabilityId>>,  // version → IDs
    pub fetch_error: Option<String>,
    pub latest_version: Option<String>,      // explicit "dist-tags.latest" where available
}
```

### 4.6 `CheckResult`

Output of the version checker for a single dependency.

```rust
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub item: Item,
    pub status: DependencyStatus,
    pub latest_compatible: Option<String>,   // best version satisfying the constraint
    pub latest_available: Option<String>,    // absolute latest (may not satisfy constraint)
    pub patch_available: bool,               // patch update exists within constraint
    pub current_vulnerabilities: Vec<String>, // vuln IDs affecting current locked/pinned version
    pub all_vulnerabilities: HashMap<String, Vec<String>>, // version → vuln IDs
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyStatus {
    UpToDate,
    PatchAvailable,   // within constraint, patch update exists
    UpdateAvailable,  // latest != current
    Outdated,         // current version does not satisfy latest
    Vulnerable,       // current version has known vulnerabilities
    Error(String),
    Local,            // file:, workspace: — not checked
    Git,              // git-sourced — not checked
}
```

---

## 5. V1 Scope — Core Dependency Management

V1 delivers a fully functional `dependable check` command that covers all 10 ecosystems with vulnerability scanning. It is feature-complete for open-source developers and CI pipelines.

### 5.1 Supported Ecosystems

| Ecosystem | Manifest Files | Lock Files | Registry |
|---|---|---|---|
| Rust | `Cargo.toml` | `Cargo.lock` | `https://index.crates.io` (sparse) |
| Go | `go.mod` | — | `https://proxy.golang.org` |
| JavaScript/TypeScript | `package.json` | `package-lock.json` | `https://registry.npmjs.org` |
| JavaScript (JSR) | `package.json`, `deno.json` | — | `https://jsr.io` |
| JavaScript (Deno) | `deno.json`, `deno.jsonc` | — | `https://jsr.io` + `https://registry.npmjs.org` |
| JavaScript (pnpm) | `pnpm-workspace.yaml` | — | `https://registry.npmjs.org` |
| PHP | `composer.json` | `composer.lock` | `https://repo.packagist.org` |
| Python | `requirements.txt`, `requirements-dev.txt`, `requirements.in`, `pyproject.toml`, `pixi.toml` | — | `https://pypi.org/pypi` |
| Dart | `pubspec.yaml` | `pubspec.lock` | `https://pub.dev` |
| C# | `*.csproj`, `Directory.Build.props`, `Directory.Packages.props` | — | `https://api.nuget.org` |
| Elixir | `mix.exs` | `mix.lock` | `https://hex.pm` |

---

### 5.2 Parser Design per Ecosystem

All parsers implement the `Parser` trait from `dependable-core`:

```rust
pub trait Parser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError>;
}
```

Parsers receive only a `&str`. They are pure functions with no side effects.

---

#### **Rust — `CargoTomlParser`**

**Crate used:** `toml_edit v0.22`

`toml_edit` parses TOML into a document tree that preserves all formatting, whitespace, and comments. It exposes `Span` information (byte offsets) for every value, which we use to record `version_col_start` / `version_col_end` for in-place fixes.

**Sections parsed:**
- `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` — key-value pairs
- `[dependencies.name]` — single-crate expanded form
- `[workspace.dependencies]` — workspace-inherited deps
- `[registries.*]` — alternate registry index URLs

**Version extraction rules:**
- String value: `serde = "1.0"` → version = `"1.0"`
- Inline table: `serde = { version = "1.0", features = [...] }` → extract `version` key
- Table section: multi-line expanded form → read `version` key
- `path`, `git`, `workspace = true` entries → `PackageSource::Local` / `PackageSource::Git` / skip

**Pinned version detection:**
- Constraint starting with `=` (no `==`, just `=`) → `isPinned = true`, exclude from `--update-all`

**Alternate registry parsing:**  
Separate function `parse_cargo_config(content: &str) -> Vec<AlternateRegistryDecl>` — called by the IO layer after reading `$CARGO_HOME/config.toml` and `credentials.toml`. Uses `toml_edit` for consistency.

---

#### **Go — `GoModParser`**

**Crate used:** None — custom line-oriented parser.

`go.mod` is a trivially simple format. No external crate is warranted.

**Rules:**
- `require (<newline>...<newline>)` block: each line is `<module-path> <version>`
- `require <module-path> <version>` single-line form
- Lines starting with `//` are comments → skip
- Version column starts at the space after the module path
- `replace` directives: skip for version checking (module is redirected locally)
- `exclude` directives: skip

---

#### **JavaScript/TypeScript — `PackageJsonParser`**

**Crate used:** `serde_json v1` for structural parse; custom line scanner for positions.

**Two-phase approach:**
1. Parse with `serde_json` into a `serde_json::Value` to extract dependency sections
2. Line-scan the raw `content: &str` to find the exact byte offset of each version string

This avoids building a full position-tracking JSON parser while still getting accurate positions.

**Dependency sections extracted:** `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `catalog`, `catalogs`

**Alias resolution (`convertAliasToPackageName`):**
- `"npm:@jsr/scope__name@^1.0"` → name = `@scope/name`, version = `^1.0`, source = `Jsr`
- `"npm:real-pkg@^1.0"` → name = `real-pkg`, version = `^1.0`
- `"jsr:@scope/name@^1.0"` → name = `@scope/name`, version = `^1.0`, source = `Jsr`
- `"link:"`, `"catalog:"`, `"workspace:"` prefixes → `PackageSource::Local`

---

#### **JavaScript (Deno) — `DenoJsonParser`**

**Crate used:** `serde_json v1` + custom line scanner.

Parses `imports` and `scopes` sections. `.jsonc` files strip `//` comments before JSON parse.

**Skip rules:**
- Keys that are URLs (`http://`, `https://`) → skip
- Values with `link:`, `file:`, `node:`, `https:`, `http:`, `data:` prefixes → skip
- JSR packages: `jsr:@scope/name@version` or `npm:@jsr/` prefixes → source = `Jsr`

---

#### **JavaScript (pnpm) — `PnpmWorkspaceYamlParser`**

**Crate used:** `serde_yaml v0.9`

Parses `catalog:` (single) and `catalogs:` (multiple named catalogs) sections.

For position information, a line scanner follows the structural parse.

---

#### **PHP — `ComposerJsonParser`**

**Crate used:** `serde_json v1` + custom line scanner.

Parses `require` and `require-dev` keys. Skips the `"php"` key (it is a runtime constraint, not a package).

---

#### **Python — `RequirementsTxtParser`**

**Crate used:** None — custom line parser.

`requirements.txt` is a one-dependency-per-line format.

**Rules:**
- Skip lines starting with `#`, `-`, `.`
- Skip lines containing `dependi: disable-check` (compatibility) or `dependable: disable-check`
- Operator detection: scan for first of `>`, `<`, `~`, `!`, `=` to find end of package name
- Version starts after the operator
- Operator offsets: `==`, `>=`, `<=`, `~=` → skip 2 chars; `>`, `<`, `!` → skip 1 char
- Strip extras: `name[extra]` → name is everything before `[`
- Multi-constraint: `name>=1.0,<2.0` — store the full constraint string; the semver engine resolves it

---

#### **Python — `PyprojectTomlParser`**

**Crate used:** `toml_edit v0.22`

Handles `pyproject.toml` (PEP 517/518/621 format) and `pixi.toml`.

**Sections parsed:**
- `[tool.poetry.dependencies]`
- `[tool.poetry.dev-dependencies]`
- `[project.dependencies]` (PEP 621)
- `[project.optional-dependencies.*]`
- `[dependency-groups.*]` (PEP 735)
- `[dependencies]` in `pixi.toml`

**Skip:**
- Key `"python"` and `"requires-python"` — these are runtime constraints
- Table entries that are inline tables with `{path=...}` or `{git=...}` keys

---

#### **Dart — `PubspecYamlParser`**

**Crate used:** `serde_yaml v0.9`

Parses `dependencies:` and `dev_dependencies:` sections. Only 2-space-indented (direct) entries are parsed; nested map entries (SDK constraints, path/git deps) are skipped.

**Valid version values:** `"any"` or matches `/^[<>~=^]?=?\s*\d+(\.\d+)*([\-+]?\w+)*$/`

For position info: line scanner after `serde_yaml` structural parse.

---

#### **Elixir — `MixExsParser`**

**Crate used:** None — regex-based parser.

`mix.exs` is Elixir source code. A full Elixir parser is not warranted. The dependency format is highly regular:

```elixir
{:dep_name, "~> 1.0"}
{:dep_name, "~> 1.0", only: [:dev, :test]}
```

**Pattern:** `\{:(\w+),\s*(['"])([^'"]+)\2`

**Skip lines containing:** `path:`, `git:`, `github:`, `in_umbrella:`

**Valid version patterns:** each constraint must match `/^(~>\s*|>=\s*|>\s*|==?\s*)?\d+(\.\d+)*([\-+]?\w+)*$/`, supporting `or` separators.

**> Decision point:** Using `regex` crate (compiled once via `std::sync::OnceLock`). See §7.

---

#### **C# — `CsprojParser`**

**Crate used:** `roxmltree v0.20`

`roxmltree` provides a read-only DOM with `TextPos` (line + column) for every node and attribute.

**Elements parsed:**
- `<PackageReference Include="Name" Version="1.0.0" />`
- `<PackageVersion Include="Name" Version="1.0.0" />`

**Skip:**
- Packages whose `Version` attribute is not a valid semver string (e.g. `$(VersionVar)` MSBuild expressions)
- `<PackageReference>` entries without a `Version` attribute (version is managed centrally)

**Position recording:** `roxmltree` provides `attr.value_range()` returning a byte range in the original document string, which maps directly to column start/end.

---

### 5.3 Lock File Parsers

Lock files are parsed entirely within `dependable-core` (they are strings → data). They populate `Item::locked_version` to enable showing the actually-installed version vs. the latest.

| Lock File | Parser Strategy | Crate |
|---|---|---|
| `Cargo.lock` | `toml_edit` — find `[[package]]` sections, read `name` + `version` | `toml_edit` |
| `package-lock.json` | `serde_json` — iterate `packages` object, strip `node_modules/` prefix | `serde_json` |
| `composer.lock` | `serde_json` — iterate `packages` + `packages-dev` arrays | `serde_json` |
| `pubspec.lock` | Custom line scanner — `name:` / `version:` fields | none |
| `mix.lock` | Custom line scanner — `"name": {` block with `"version":` field | none |

**Lock file validation:** `satisfies(locked_version, version_constraint)` from the semver engine. If `locked_version` does not satisfy the declared constraint (e.g. after a manual constraint change), mark as `DependencyStatus::Outdated`.

---

### 5.4 Registry Fetcher Design

Defined in `dependable-fetch`. All registry fetchers implement:

```rust
#[async_trait]
pub trait RegistryFetcher: Send + Sync {
    async fn fetch_versions(&self, name: &str) -> Result<FetchedVersions, FetchError>;
}

pub struct FetchedVersions {
    pub versions: Vec<String>,       // all available, newest-first after sorting
    pub latest_tag: Option<String>,  // explicit "latest" dist-tag where available
    pub error: Option<String>,       // deprecation notice etc.
}
```

**HTTP client:** `reqwest v0.12` with:
- `rustls` TLS backend (no OpenSSL system dependency)
- `gzip` decompression (via `reqwest`'s built-in feature)
- Redirect following (up to 10 hops, `reqwest` default)
- Timeout: 10 seconds per request
- User-Agent: `Dependable/<version> (<OS>)`
- Connection pool shared across all fetchers

---

#### **Crates.io**

URL: `https://index.crates.io/<prefix>/<name>`

Prefix computation (same as Dependi):
- Name length 1-2: `<length>/<name>`
- Length 3: `3/<name[0]>/<name>`
- Length 4+: `<name[0..2]>/<name[2..4]>/<name>`

Response: newline-delimited JSON. Each line: `{"vers":"x.y.z","yanked":false,...}`. Filter `yanked == false`.

**Alternate registries:** fetcher receives optional `(index_url, auth_token)`. Auth token sent as `Authorization: <token>` header. Skips gracefully if no index URL for a declared registry.

---

#### **NPM**

Two modes:
1. **Full fetch:** `GET <registry>/<name>` with `Accept: application/vnd.npm.install-v1+json` — returns all versions; filters deprecated entries
2. **Latest-only:** `GET <registry>/-/package/<name>/dist-tags` — cheaper request when only checking if current is latest

Decision logic: use full fetch on first check; use latest-only for cache refresh.

**Pre-release detection:** version strings containing `-` anywhere (e.g. `1.0.0-alpha.1`).

---

#### **Go Proxy**

- Primary: `GET <proxy>/<lowercase-module>/@v/list` → newline-separated version list
- Fallback (empty list): `GET <proxy>/<lowercase-module>/@latest` → JSON `{"Version":"vX.Y.Z"}`

---

#### **PyPI**

`GET https://pypi.org/pypi/<name>/json` → `response.releases` object. Filter releases where any file entry has `"yanked": true`.

---

#### **Packagist**

`GET https://repo.packagist.org/p2/<name>.json` → `packages[name][].version`. Strip leading `v`.

---

#### **pub.dev**

`GET https://pub.dev/api/packages/<name>` → `versions[].version`.

---

#### **NuGet**

Two-level paginated API:
1. `GET https://api.nuget.org/v3/registration5-gz-semver2/<lowercase-name>/index.json` (gzip)
2. If page items are not inline: fetch each `@id` page URL and extract `catalogEntry.version`
3. `tokio::task::JoinSet` for concurrent page fetches

---

#### **hex.pm (Elixir)**

`GET https://hex.pm/api/packages/<name>` → `releases[].version`. Filter empty strings.

---

#### **JSR**

`GET https://jsr.io/<package>/meta.json` with `Accept: application/json` → `versions` object (keys = version strings, filter non-yanked). `latest` field available.

---

#### **Unstable Version Filtering**

Controlled by `UnstableFilter` enum, configurable per ecosystem:

```rust
pub enum UnstableFilter {
    Exclude,          // default — hide pre-releases
    IncludeAlways,    // show all versions
    IncludeIfCurrent, // include pre-releases only if current version is also a pre-release
}
```

Pre-release detection checks (case-insensitive substrings):
`-alpha`, `-beta`, `-rc`, `-snapshot`, `-dev`, `-preview`, `-experimental`, `-canary`, `-pre`, `-next`, `-nightly`, `-nullsafety`, `-nnbd`

Python additionally checks: `.alpha`, `.beta`, `.rc`, `.dev`, `.SNAPSHOT`, `.preview`, `.experimental`, `.canary`, `.pre`, `.post`, `rc` standalone, `/[ab]\d/` regex pattern.

---

### 5.5 Version Comparison Engine

Located in `dependable-core::semver`. Uses the `semver v1` crate as the foundation.

#### `check_version(constraint, versions, locked_at) -> CheckResult`

1. Normalize constraint to semver via `to_semver_constraint(constraint, ecosystem)`
2. If `locked_at` is set: validate `locked_at` satisfies constraint; if not, return `Outdated`
3. Compute `max_satisfying = semver::VersionReq::parse(constraint)?.matches(versions.max())`
4. `up_to_date = max == versions[0]`
5. `patch_available` = if informPatchUpdates enabled: `versions[0] > min_version(constraint)`
6. Return `CheckResult`

#### Version Normalization

`normalize(v: &str) -> String`:
- Extract operator prefix (`^`, `~`, `>=`, `<=`, `>`, `<`, `=`) and optional `v`/`V` prefix
- If version has 0 dots: append `.0.0`
- If version has 1 dot: append `.0`
- Return `operator + v_prefix + normalized_version`

If no operator prefix on current version, prepend `^` before passing to `semver::VersionReq`.

#### Python PEP 440 → Semver Conversion

Handles all PEP 440 pre-release forms:
- `.dev<N>` → `-dev.<N>`
- `.post<N>` → `-post.<N>`
- `.a<N>` or `a<N>` → `-alpha.<N>`
- `.b<N>` or `b<N>` → `-beta.<N>`
- `.rc<N>` or `rc<N>` → `-rc.<N>`
- `.c<N>` → `-c.<N>`

Multi-constraint (`>=1.0,<2.0`): split by `,`, strip `;` env markers, convert each constraint independently, join with semver `||` or range intersection logic.

Wildcard handling: `==1.0.*` → `>=1.0.0, <1.1.0`.

`possibleLatestVersion(constraints, versions) -> Option<String>`: custom resolution matching all constraints, returns highest satisfying version. This must be reimplemented from Dependi's logic (which handles the `==X.*` wildcard case).

#### Elixir Hex → Semver Conversion

- `~> X.Y` → `>=X.Y.0, <X.(Y+1).0`
- `~> X.Y.Z` → `>=X.Y.Z, <X.(Y+1).0`
- `~X` (shorthand) → same as `~>`
- `>= X`, `> X`, `== X` → direct mapping
- `A or B` → `semver_a || semver_b`

---

### 5.6 Vulnerability Scanning (OSV)

#### Client (`dependable-fetch::osv`)

**Batch endpoint:** `POST https://api.osv.dev/v1/querybatch`

```json
{
  "queries": [
    {"version": "1.0.0", "package": {"name": "pkg", "ecosystem": "npm"}}
  ]
}
```

**Chunking:** maximum 500 total version-entries per batch request (`chunkDataArray` equivalent). For a dependency with 200 versions, it counts as 200 entries.

**GHSA filtering:** configurable. When `include_ghsa = false`, strip vulnerability IDs starting with `GHSA-`.

**Cache:** 10-minute TTL via `moka`. Cache key = `(ecosystem, package_name, version)` → `Vec<VulnerabilityId>`.

**Single query endpoint** (`POST https://api.osv.dev/v1/query`): used for detailed vulnerability info (V2 reports).

#### Vulnerability Check Scope per Dependency

For each dependency, query all versions from `versions[0]` down to the current version by index. This surfaces vulnerabilities in all versions between current and latest, enabling reports like "upgrading from 1.0 to 2.0 fixes 3 known vulnerabilities."

---

### 5.7 CLI Interface

**Binary name:** `dependable`

**Commands:**

```
dependable check [OPTIONS] [PATH]
dependable fix [OPTIONS] [PATH]
dependable list [OPTIONS] [PATH]
dependable help
```

#### `dependable check`

Checks all discovered manifest files in `[PATH]` (default: current directory).

```
OPTIONS:
  --ecosystem <eco>        Only check specified ecosystem(s) [default: all]
  --manifest <file>        Check a specific manifest file
  --config <file>          Config file path [default: .dependable.toml]
  --unstable <filter>      exclude|include-always|include-if-current
  --no-lock-file           Ignore lock files
  --no-vuln                Skip vulnerability checks
  --include-ghsa           Include GHSA advisories in vuln check
  --format <fmt>           table|json|text [default: table]
  --fail-on <level>        none|outdated|vulnerable|any — exit 1 on match
  --depth <n>              How many directories deep to search [default: 3]
  --concurrency <n>        Max concurrent HTTP requests [default: 20]
  -q, --quiet              Only print errors
  -v, --verbose            Print HTTP request details
```

#### `dependable fix`

Updates dependency versions in-place to latest compatible version.

```
OPTIONS:
  --all                    Update all, including breaking changes
  --dry-run                Print what would change, don't write
  --ecosystem <eco>        Limit to ecosystem(s)
  --manifest <file>        Fix specific manifest
```

#### `dependable list`

Lists all discovered dependencies without checking versions.

```
OPTIONS:
  --format <fmt>           table|json|text
  --ecosystem <eco>
```

---

### 5.8 Output Formats

#### Table (default)

```
Cargo.toml — Rust (23 dependencies)

Package            Current     Latest      Status
─────────────────────────────────────────────────────────
serde              1.0.195     1.0.203     ⚠  patch available
tokio              1.35.0      1.36.0      ❌ update available
reqwest            0.11.24     0.12.4      ❌ update available
rand               0.8.5       0.8.5       ✅ up to date
openssl            0.10.62     0.10.66     🚨 3 vulnerabilities

Totals: 1 up to date · 1 patch · 2 updates · 1 vulnerable
```

Colors: green (up to date), yellow (patch), red (outdated/vulnerable). Disabled when not a TTY.

#### JSON

```json
{
  "summary": {
    "total": 23,
    "up_to_date": 1,
    "patch_available": 1,
    "update_available": 2,
    "vulnerable": 1,
    "error": 0
  },
  "results": [
    {
      "name": "serde",
      "ecosystem": "Rust",
      "manifest": "Cargo.toml",
      "current": "1.0.195",
      "latest_compatible": "1.0.203",
      "latest_available": "1.0.203",
      "status": "PatchAvailable",
      "vulnerabilities": [],
      "locked_at": "1.0.195"
    }
  ]
}
```

#### Text (machine-readable, one line per dep)

```
PATCH  serde      1.0.195  1.0.203  Cargo.toml
UPDATE tokio      1.35.0   1.36.0   Cargo.toml
VULN   openssl    0.10.62  0.10.66  Cargo.toml  [GHSA-xxxx-yyyy-zzzz]
OK     rand       0.8.5    0.8.5    Cargo.toml
```

---

### 5.9 Configuration System

Project-level config at `.dependable.toml` (or `dependable.toml`). Layered with CLI flags (CLI wins).

```toml
[global]
# Registry fetch concurrency
concurrency = 20
# Include pre-releases globally?
unstable_filter = "exclude"   # "exclude" | "include-always" | "include-if-current"
# Include GHSA advisories?
include_ghsa = false
# Fail the process on these statuses (for CI)
fail_on = "none"              # "none" | "outdated" | "vulnerable" | "any"

[rust]
enabled = true
registry = "https://index.crates.io"
unstable_filter = "exclude"
inform_patch_updates = false
lock_file = true
silence_version_overflows = false

[npm]
enabled = true
registry = "https://registry.npmjs.org"
jsr_enabled = true
jsr_registry = "https://jsr.io"
lock_file = true

[go]
enabled = true
registry = "https://proxy.golang.org"

[python]
enabled = true
registry = "https://pypi.org/pypi"
lock_file = false

[php]
enabled = true
registry = "https://repo.packagist.org"
lock_file = true

[dart]
enabled = true
registry = "https://pub.dev"
lock_file = true

[csharp]
enabled = true
registry = "https://api.nuget.org"

[elixir]
enabled = true
registry = "https://hex.pm"
lock_file = true

[vulnerability]
enabled = true
osv_batch_url = "https://api.osv.dev/v1/querybatch"
osv_single_url = "https://api.osv.dev/v1/query"

# Per-project ignore patterns (same glob syntax as .gitignore)
[ignore]
patterns = ["internal-*", "*-legacy"]

# Dependency-level overrides
[[override]]
name = "old-package"
ecosystem = "npm"
ignore = true     # never check this package

[[override]]
name = "pinned-dep"
ecosystem = "rust"
max_version = "1.5.0"   # don't suggest versions above this
```

**Environment variable overrides** (for CI):
- `DEPENDABLE_FAIL_ON=vulnerable`
- `DEPENDABLE_NO_VULN=1`
- `DEPENDABLE_CONCURRENCY=10`

---

### 5.10 Caching Strategy

**In-process cache (`moka`):**
- Registry versions: 5-minute TTL per `(ecosystem, package_name)` key
- OSV vulnerability results: 10-minute TTL per `(ecosystem, package_name, version)` key
- Cache is populated on first fetch; reused for all subsequent checks in the same run

**Persistent disk cache (V1.1 optional feature):**  
A `~/.cache/dependable/` directory storing registry responses as JSON files, keyed by `<ecosystem>/<hash(name)>`. On-disk cache TTL: 1 hour. Opt-out via `--no-cache`.

> **⚠ Decision for human feedback:** Whether to include disk cache in V1 or V1.1.

---

## 6. V2 Scope — Enterprise & Reports

V2 builds on V1 without changing the core architecture. All V2 features are opt-in and either gated behind a separate command or compiled as optional features.

### 6.1 HTML Vulnerability Reports

**Command:** `dependable report [OPTIONS] [PATH]`

Generates a self-contained HTML file containing a full vulnerability and dependency status report.

**Report sections:**

1. **Executive Summary** — total deps, up-to-date %, vulnerable count, critical CVE count
2. **Vulnerability Detail Table** — one row per affected dep/version: CVE ID, CVSS score, severity, affected versions, fixed versions, description, link to advisory
3. **Dependency Status Table** — all deps with current version, latest, status indicator
4. **Version History Comparison** (when `--compare-to-commit` is used) — what changed
5. **Ecosystem Breakdown** — pie chart (SVG, no JS required) of dep health per ecosystem

**Template engine:** `minijinja v2` (runtime Jinja2-compatible templates)

Templates are embedded in the binary via `include_str!()`. Users can override by placing a `dependable-templates/` directory in the project root.

**Self-contained output:** All CSS is inlined. SVG charts are inline. No external resource loading (works offline, safe to email).

**PDF export:** V2 will not bundle headless Chrome. Instead:
- Generate HTML as above
- Provide `--pdf` flag which calls `chromium --headless --print-to-pdf` if available
- Document the `wkhtmltopdf` alternative
- Pure-Rust PDF remains out of scope (complexity/quality tradeoff)

> **⚠ Decision for human feedback:** Whether to support PDF at all in V2, or defer to V3.

---

### 6.2 Git-Based Comparative Analysis

**Command:** `dependable report --compare-to HEAD~1`

Compares dependency state at current working tree vs. a git ref.

**Crate:** `gix v0.66` (pure Rust git library, no system `git` required)

**Flow:**
1. Read current manifest(s)
2. Read manifest(s) at target git ref via `gix::Repository::rev_parse(ref)?.peel_to_commit()?.tree()?.find_entry(path)?`
3. Parse both versions
4. Diff: added deps, removed deps, version changes, new vulnerabilities introduced, vulnerabilities fixed

**Report output:** "Between HEAD~1 and HEAD, 2 new vulnerabilities were introduced in `openssl` (CVE-xxxx, CVE-yyyy). 1 vulnerability was resolved by upgrading `tokio`."

---

### 6.3 CI/CD Integration

**GitHub Actions:**
- Publish a `dependable-check` action using the `dependable` binary
- Annotations on PRs via GitHub Actions output commands (`::error file=Cargo.toml,line=12::`)
- Job summary (GitHub step summary markdown)

**GitLab CI:**
- Support GitLab Code Quality report format (JSON)

**Generic CI:**
- `--fail-on vulnerable` exits with code 1 (already in V1)
- `--format json` for parsing in scripts

---

### 6.4 Policy Enforcement

**File:** `.dependable.toml` (extended in V2)

```toml
[policy]
# Fail if any dep has a CVSS score >= this value
max_cvss = 7.0

# Fail if any dep is more than N major versions behind latest
max_major_behind = 2

# Allowed licenses (SPDX identifiers) — requires license fetching
allowed_licenses = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"]

# Deny specific packages entirely
denied_packages = [
  { ecosystem = "npm", name = "left-pad" },
]

# Required minimum versions
[[policy.minimum_versions]]
ecosystem = "rust"
name = "openssl"
min_version = "0.10.64"
reason = "CVE-2023-xxxx fix"
```

**Exit codes:**
- `0` = pass
- `1` = policy violation
- `2` = error (network, parse, etc.)

---

### 6.5 Workspace / Monorepo Support

`dependable check` in V1 already discovers multiple manifest files via directory traversal. V2 adds:

- **Deduplication:** same package checked across 5 `package.json` files → single HTTP request, merged results
- **Workspace summary report:** rollup across all manifests
- **Manifest filter:** `--manifest-glob "services/*/Cargo.toml"`
- **Cargo workspace awareness:** parse `[workspace.dependencies]` and resolve `workspace = true` inheritance

---

### 6.6 SARIF Output

SARIF (Static Analysis Results Interchange Format) v2.1.0 — consumed by GitHub Security tab, VS Code, and many enterprise tools.

**Command:** `dependable check --format sarif`

**Output:** Each outdated/vulnerable dependency becomes a SARIF `result` with:
- `ruleId` = `DEP001` (outdated) / `DEP002` (vulnerable)
- `locations[]` pointing to the manifest file + line number
- `message` with human-readable description
- `properties.cvssScore` for vulnerabilities

This is built as a `serde` serialization of the SARIF schema structs — no external SARIF crate needed (none mature enough).

---

## 7. External Dependency Decisions

### 7.1 Core Crates

These appear in `dependable-core/Cargo.toml`. They must be minimal, well-maintained, and preferably `no_std`-compatible in future.

| Crate | Version | Purpose | Why this one |
|---|---|---|---|
| `toml_edit` | `^0.22` | TOML parse + position-preserving edit | Only mature TOML crate with span info; used by Cargo itself |
| `serde` | `^1` | Deserialization framework | Ubiquitous; `derive` macros |
| `serde_json` | `^1` | JSON parse + serialization | Standard; used everywhere |
| `serde_yaml` | `^0.9` | YAML parse (pubspec.yaml, pnpm-workspace.yaml) | Stable API; `serde` integration |
| `roxmltree` | `^0.20` | Read-only XML DOM with positions | Lightweight (no unsafe in public API), provides attribute position |
| `semver` | `^1` | Semver constraint evaluation | Used by Cargo itself; `VersionReq::matches()` |
| `regex` | `^1` | Pattern matching for mix.exs, ignore patterns | Compiled once; `OnceLock<Regex>` per pattern |
| `thiserror` | `^2` | Error type derivation | Ergonomic, zero cost |

> **Note:** There is no YAML crate in Rust with position info comparable to `roxmltree`. `serde_yaml` provides structural parse only. Position info for YAML is obtained by post-hoc line scanning of the raw string (same approach as for JSON). This is acceptable because the YAML formats we handle (pubspec.yaml, pnpm-workspace.yaml) are simple enough for line scanning.

> **⚠ Decision for human feedback:** `serde_yaml v0.9` has some `unsafe` code internally. Alternative is `marked_yaml` (positions built-in, pure safe Rust) or `yaml-rust2`. `marked_yaml` is less widely used. Recommend `serde_yaml` for now and revisit if unsafe becomes a concern.

---

### 7.2 IO / CLI Crates

These appear in `dependable-fetch` and `dependable` (CLI binary).

| Crate | Version | Purpose | Why this one |
|---|---|---|---|
| `reqwest` | `^0.12` | Async HTTP client | Mature, feature-rich, rustls support, built-in gzip/deflate, connection pooling |
| `tokio` | `^1` | Async runtime | Required by `reqwest`; standard choice |
| `rustls` | via reqwest feature `rustls-tls` | TLS without OpenSSL system dep | Enables fully static binary with no system library requirements |
| `moka` | `^0.12` | Concurrent TTL in-memory cache | Thread-safe, TTL support, `async` aware, used by production services |
| `clap` | `^4` | CLI argument parsing | Derive macros, completions, strong ecosystem |
| `indicatif` | `^0.17` | Progress bars | Standard choice, works on TTY and non-TTY |
| `owo-colors` | `^4` | Terminal colors | Lighter than `colored`; respects `NO_COLOR` env var |
| `tabled` | `^0.15` | Terminal table rendering | Multiple styles, color support, Unicode-aware |
| `tokio-stream` | `^0.1` | Stream utilities for concurrent fetch | Integrates with tokio |
| `futures` | `^0.3` | `futures::future::join_all`, `FuturesUnordered` | Concurrent batch fetch coordination |
| `tracing` | `^0.1` | Structured logging | Replaces `println!` debug; `--verbose` flag wires to subscriber |
| `tracing-subscriber` | `^0.3` | Tracing output (in CLI binary only) | Formats tracing events for human consumption |
| `figment` | `^0.10` | Layered config (file + env vars + defaults) | Handles `.dependable.toml` + `DEPENDABLE_*` env overrides cleanly |

---

### 7.3 V2 Crates

| Crate | Version | Purpose | Why this one |
|---|---|---|---|
| `minijinja` | `^2` | HTML report templating | Jinja2-compatible, runtime templates, `include_str!` compatible, no C deps |
| `gix` | `^0.66` | Git repository access (comparative reports) | Pure Rust git; no `libgit2` C dependency; actively maintained |
| `time` | `^0.3` | Date/time for report timestamps | `serde` support; `no_std` compatible |
| `base64` | `^0.22` | Inline image embedding in HTML reports | Simple utility |

---

### 7.4 Crates Explicitly Rejected and Why

| Rejected | Reason | Alternative Used |
|---|---|---|
| `git2` | Requires `libgit2` C library → breaks static binary | `gix` (pure Rust) |
| `toml` (not `toml_edit`) | No position/span information → cannot do in-place `--fix` | `toml_edit` |
| `openssl` (reqwest feature) | Requires system OpenSSL → breaks cross-compilation and Alpine builds | `rustls` (reqwest feature) |
| `quick-xml` for reading | No DOM API → requires manual state machine for our read pattern | `roxmltree` (DOM with positions) |
| `tera` | Larger, more complex template engine not needed for our single-purpose reports | `minijinja` |
| `askama` | Compile-time templates → prevents user-overridable templates | `minijinja` |
| `rayon` | Thread-pool parallelism — we need async/await for HTTP concurrency, not CPU parallelism | `tokio` + `futures` |
| `anyhow` | Fine for binaries but we want typed errors in library crates | `thiserror` in libs, `anyhow` acceptable in binary crate if desired |
| `marked_yaml` | Less mature than `serde_yaml`; niche crate | `serde_yaml` with post-hoc line scanner |
| Any JS/npm runtime | This is a Rust tool — no Node.js dependency | native Rust |

---

## 8. Design Decisions Requiring Human Feedback

The following decisions are deliberate open questions. Each has a recommendation but needs sign-off before implementation.

---

### D1 — Disk Cache in V1 or V1.1?

**Question:** Should `~/.cache/dependable/` persistent disk cache be in V1 or deferred?

**Impact:** Without disk cache, every invocation of `dependable check` fetches all registries from scratch (~1–5s for a large project on a cold network). With it, repeat runs are nearly instant.

**Recommendation:** Include in V1. Disk cache is a user-visible performance feature that affects CI experience. It can be implemented as a simple directory of JSON files with a `fetched_at` timestamp.

**Alternative:** Ship V1 with only in-process cache (fast within a single run, cold on every invocation). Add disk cache in V1.1.

---

### D2 — `--fix` In-Place Editing Scope

**Question:** Which file formats should support in-place version fixes in V1?

`toml_edit` gives us safe in-place edits for Cargo.toml / pyproject.toml / pixi.toml.  
For JSON files (package.json, composer.json), in-place editing without a position-preserving JSON library risks reformatting user files.

**Recommendation:** For V1, support `--fix` only for:
- Cargo.toml (via `toml_edit`) ✅
- go.mod (line replacement is trivial — format is `module v1.2.3`) ✅
- requirements.txt (line replacement — simple format) ✅
- mix.exs (targeted regex replacement) ✅

For JSON/YAML files (package.json, pubspec.yaml), V1 outputs the suggested versions but requires manual editing or delegates to the ecosystem's native tool (`npm install`, `flutter pub upgrade`). V1.1 adds position-tracked JSON fixes.

**Alternative:** Use a line-based approach for all files: find the version string at the recorded column offset, do a byte-level replacement. This is fragile but works for simple cases.

---

### D3 — `serde_yaml` vs `marked_yaml` for YAML Parsing

**Question:** Accept the `unsafe` code in `serde_yaml` or use `marked_yaml` which is pure safe Rust but less mature?

**Recommendation:** `serde_yaml v0.9`. The `unsafe` is limited to the YAML/C binding in older versions; `serde_yaml` v0.9 uses `unsafe_libyaml` crate which is a careful unsafe wrapper. The maturity gap is significant.

**Alternative:** `yaml-rust2` + manual deserialization (more code, more maintainability burden).

---

### D4 — PDF Export in V2

**Question:** How should PDF export work?

Options:
1. **Call system `chromium --headless --print-to-pdf`** — best quality, requires Chrome installed
2. **Call `wkhtmltopdf`** — older, good quality, separate install
3. **`printpdf` crate** — pure Rust, but complex to produce well-formatted reports
4. **Out of scope** — HTML only, document that users can print-to-PDF from browser

**Recommendation:** Option 4 for V2. The HTML report is self-contained and any browser prints it well. If enterprise customers specifically need automated PDF generation, add option 1 as a plugin in V3.

---

### D5 — Policy Enforcement Severity Levels

**Question:** How granular should CVSS-based policy be?

CVSS scores range 0–10. Common severity bands:
- Critical: 9.0–10.0
- High: 7.0–8.9
- Medium: 4.0–6.9
- Low: 0.1–3.9

**Recommendation:** Support both named severity levels (`fail_on_severity = "high"`) and a raw CVSS threshold (`max_cvss = 7.0`). Numeric threshold takes precedence.

---

### D6 — License Checking

**Question:** Should V2 include license compatibility checking?

This would require fetching license metadata from each registry (npm includes `license` in package metadata; PyPI has a classifier; Crates.io has `license` field).

**Recommendation:** Include basic license visibility (show declared license in `dependable list`) in V2. Policy enforcement against an allowlist (`allowed_licenses`) also in V2. Full compatibility graph analysis (GPL copyleft detection) is V3.

---

### D7 — Multi-Language Single-Run Behavior

**Question:** When a project has both `Cargo.toml` and `package.json`, should the output be interleaved or grouped by ecosystem?

**Recommendation:** Grouped by ecosystem with a section header per file. All ecosystems run concurrently. Default `--depth 3` to avoid accidentally scanning `node_modules/` or `vendor/`.

---

### D8 — Handling `"latest"` as a Version Constraint

**Question:** Some `package.json` files specify `"latest"` as a version. Should we resolve it and display the actual installed version?

**Recommendation:** Resolve `"latest"` to the actual latest version from the registry's `dist-tags.latest` on first fetch, and display it. Do not substitute into the file on `--fix` (keep `"latest"` as-is).

---

### D9 — Telemetry

**Question:** Should Dependable include any telemetry?

**Recommendation:** No telemetry. Dependable is a clean-slate open-source tool. Usage data collection requires explicit opt-in consent with a clear privacy policy. This adds maintenance burden and user friction. Skip entirely for V1 and V2.

---

## 9. Non-Goals

The following are explicitly out of scope to keep the project focused:

- **VSCode extension** — Dependable is a CLI tool and library. A VSCode extension could use `dependable-core` and `dependable-fetch` as library crates, but that extension is a separate project.
- **Automatic dependency installation** — we do not run `cargo install`, `npm install`, etc. We only check and optionally update version strings in manifest files.
- **Private registry authentication for non-Rust ecosystems** — Cargo alternate registries (with tokens) are supported. npm private registries via `.npmrc` auth tokens are V1.1+. Other ecosystems: deferred.
- **Dependency graph / transitive vulnerabilities** — we only check direct dependencies as declared in manifest files.
- **Package verification / supply chain** (Sigstore, etc.) — V3 at earliest.
- **Proprietary cloud backend** — all features work without an API key or paid service.
- **Windows cross-compilation** — `rustls` makes this possible but we will test and officially support only Linux and macOS in V1. Windows support in V1.1.
- **Language servers (LSP)** — out of scope, but `dependable-core`'s IO-independence makes a future LSP integration straightforward.

---

## 10. Open Questions

These are unresolved technical questions that need answers before work begins:

1. **`go.sum` support** — Go's `go.sum` file contains checksums, not version info. Should we use it for locked version display? It doesn't directly contain the resolved version for each module.

2. **pnpm catalog versions** — pnpm `pnpm-workspace.yaml` catalogs define reusable version constraints. Should `dependable check` expand catalog references in individual `package.json` files, or only check the catalog definitions?

3. **Rust feature flag visibility** — Crates.io sparse index includes feature flag names (from `features` field). Should `dependable list` expose feature flags for Rust packages? Dependi does. This adds complexity to the `Item` struct.

4. **`requirements.txt` with `-r` includes** — `requirements.txt` supports `-r other-requirements.txt` include directives. Should we follow these recursively?

5. **pyproject.toml extras** — `name[extra]>=1.0` syntax. The extras affect which transitive deps are installed but we only check the package itself. Current plan: strip extras and check the base package. Is this the right call?

6. **NuGet version ranges** — NuGet supports bracket/paren notation: `[1.0, 2.0)`. The `semver` crate does not understand this. We need a conversion layer (similar to Python/Elixir). Confirm we need this.

7. **Dart SDK constraint** — `pubspec.yaml` contains `environment: sdk: ">=3.0.0 <4.0.0"`. Should we skip or handle this? Current plan: skip (it is not a fetchable package).

8. **`dependable-core` `no_std` compatibility** — Is this a real requirement? It adds constraints (no `HashMap` unless using `hashbrown`, no `String` without `alloc`). If we do not actually target embedded or WASM, it adds friction without benefit.

---

*This document is a living draft. All sections marked ⚠ are open for discussion. Feedback should be given per section number or decision number (D1–D9).*
