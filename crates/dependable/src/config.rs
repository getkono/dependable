//! `.dependable.toml` configuration, layered with `DEPENDABLE_*` env + CLI flags.
//!
//! Precedence (highest wins): CLI flags → env vars → config file → defaults.
//! CLI/env merging happens in [`crate::runner`]; this module loads the file and
//! supplies defaults.

use std::path::Path;

use figment::Figment;
use figment::providers::{Format as _, Serialized, Toml};
use serde::{Deserialize, Serialize};

use crate::cli::{FailOn, UnstableFilter};

/// The full configuration, with sane defaults when the file is absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub rust: RustConfig,
    #[serde(default)]
    pub npm: NpmConfig,
    #[serde(default)]
    pub php: PhpConfig,
    #[serde(default)]
    pub vulnerability: VulnConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub concurrency: usize,
    pub include_ghsa: bool,
    pub lock_file: bool,
    pub fail_on: FailOn,
    pub unstable: UnstableFilter,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            concurrency: 20,
            include_ghsa: false,
            lock_file: true,
            fail_on: FailOn::None,
            unstable: UnstableFilter::Exclude,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RustConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for RustConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://index.crates.io".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NpmConfig {
    pub enabled: bool,
    pub registry: String,
    /// JSR registry for Deno `jsr:` dependencies (npm-ecosystem sub-registry).
    pub jsr_registry: String,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://registry.npmjs.org".to_string(),
            jsr_registry: "https://jsr.io".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PhpConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for PhpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://repo.packagist.org".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnConfig {
    pub enabled: bool,
    pub osv_batch_url: String,
}

impl Default for VulnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            osv_batch_url: "https://api.osv.dev/v1/querybatch".to_string(),
        }
    }
}

/// Load configuration: defaults overlaid with `path` (if present).
///
/// A missing file is not an error — defaults are used. A malformed file falls
/// back to defaults as well (the runner surfaces nothing fatal for config).
#[must_use]
pub fn load_config(path: &Path) -> Config {
    Figment::from(Serialized::defaults(Config::default()))
        .merge(Toml::file(path))
        .extract()
        .unwrap_or_default()
}
