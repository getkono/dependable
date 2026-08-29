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
#[cfg(feature = "report")]
use dependable_report::policy::Policy;

/// The full configuration, with sane defaults when the file is absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub rust: RustConfig,
    #[serde(default)]
    pub go: GoConfig,
    #[serde(default)]
    pub npm: NpmConfig,
    #[serde(default)]
    pub python: PythonConfig,
    #[serde(default)]
    pub php: PhpConfig,
    #[serde(default)]
    pub dart: DartConfig,
    #[serde(default)]
    pub csharp: CsharpConfig,
    #[serde(default)]
    pub elixir: ElixirConfig,
    #[serde(default)]
    pub vulnerability: VulnConfig,
    /// CI gating rules. Empty by default, so policy gates nothing until a
    /// `[policy]` block is written.
    ///
    /// By construction this is the same value [`load_policy`] returns — same
    /// figment, same key — so there is one schema and no way for the two to
    /// disagree.
    #[cfg(feature = "report")]
    #[serde(default)]
    pub policy: Policy,
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
pub struct GoConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for GoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://proxy.golang.org".to_string(),
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
pub struct PythonConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for PythonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://pypi.org/pypi".to_string(),
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
pub struct DartConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for DartConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://pub.dev".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CsharpConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for CsharpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://api.nuget.org".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ElixirConfig {
    pub enabled: bool,
    pub registry: String,
}

impl Default for ElixirConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registry: "https://hex.pm".to_string(),
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

/// Where a `[policy]` block came from — or why there is none.
///
/// [`load_config`] is deliberately lenient: a malformed file falls back to
/// defaults so a typo in an unrelated key never breaks a check. A security gate
/// cannot afford that, so policy is loaded separately and the three cases are
/// kept apart. `#[non_exhaustive]`: match with a wildcard arm.
#[cfg(feature = "report")]
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PolicySource {
    /// No `[policy]` table — the file is absent, or declares none. No gate.
    Absent,
    /// The config file exists but cannot be parsed at all, so nothing in it
    /// (policy included) can be read. Carries the parser's complaint.
    Unreadable(String),
    /// A `[policy]` table was found and is valid.
    Configured(Policy),
}

/// Load the `[policy]` block from `path`.
///
/// The distinction this draws is the whole point: a policy that *exists* is
/// either enforced or it is an error — it is never quietly dropped, which is the
/// difference between a gate that runs and one that only appears to.
///
/// - No `[policy]` table at all → [`PolicySource::Absent`]: no gate, exit code
///   unchanged. This is every existing user.
/// - The file itself is unparseable → [`PolicySource::Unreadable`]: the caller
///   warns and runs ungated, matching [`load_config`]'s leniency, because no
///   policy could be read either.
/// - A `[policy]` table that is present but invalid → `Err`: the caller must
///   fail the run rather than pretend a gate is in force.
///
/// # Errors
///
/// Returns the figment error, naming the offending key, when a `[policy]` table
/// exists but does not deserialize. Boxed because a `figment::Error` dwarfs the
/// success value.
#[cfg(feature = "report")]
pub fn load_policy(path: &Path) -> Result<PolicySource, Box<figment::Error>> {
    match Figment::from(Toml::file(path)).find_value("policy") {
        // A missing file yields an empty provider, so "no such key" covers both
        // "no config" and "config without a [policy] block".
        Err(e) if e.missing() => Ok(PolicySource::Absent),
        // Anything else from `find_value` is the file failing to parse at all.
        Err(e) => Ok(PolicySource::Unreadable(e.to_string())),
        Ok(_) => Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(path))
            .extract_inner::<Policy>("policy")
            .map(PolicySource::Configured)
            .map_err(Box::new),
    }
}

/// Whether `path` declares a `[policy]` table at all.
///
/// Used only in builds without the `report` feature, where the policy types do
/// not exist: the CLI can still tell that a gate was *asked for* and say it is
/// being ignored, rather than passing silently.
#[cfg(not(feature = "report"))]
#[must_use]
pub fn has_policy_table(path: &Path) -> bool {
    Figment::from(Toml::file(path)).find_value("policy").is_ok()
}

#[cfg(all(test, feature = "report"))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use dependable_fetch::core::result::Severity;

    use super::*;

    /// A scratch directory of our own, so the tests never read the repository's
    /// real `.dependable.toml`.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("dependable-config-tests")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    fn write(name: &str, content: &str) -> PathBuf {
        let path = scratch(name).join("dependable.toml");
        fs::write(&path, content).expect("write the config");
        path
    }

    #[test]
    fn a_missing_file_declares_no_policy() {
        let path = scratch("missing").join("nope.toml");
        assert_eq!(load_policy(&path), Ok(PolicySource::Absent));
    }

    #[test]
    fn a_file_without_a_policy_block_declares_no_policy() {
        let path = write("no_block", "[global]\nconcurrency = 4\n");
        assert_eq!(load_policy(&path), Ok(PolicySource::Absent));
    }

    #[test]
    fn an_unparseable_file_is_reported_as_unreadable_not_as_a_policy() {
        let path = write("broken", "this is not = = toml\n");
        assert!(
            matches!(load_policy(&path), Ok(PolicySource::Unreadable(_))),
            "expected Unreadable, got {:?}",
            load_policy(&path)
        );
    }

    #[test]
    fn a_valid_policy_block_is_loaded() {
        let path = write(
            "valid",
            "[policy]\nmax_cvss = 7.0\ndenied_packages = [{ name = \"left-pad\" }]\n",
        );

        let Ok(PolicySource::Configured(policy)) = load_policy(&path) else {
            panic!("expected a configured policy, got {:?}", load_policy(&path));
        };
        assert_eq!(policy.max_cvss, Some(7.0));
        assert_eq!(policy.denied_packages.len(), 1);
    }

    #[test]
    fn a_policy_that_exists_but_is_invalid_is_an_error() {
        // The hole this closes: `load_config` would swallow this into defaults,
        // leaving a gate that looks configured and enforces nothing.
        let path = write("wrong_type", "[policy]\nmax_cvss = \"high\"\n");
        assert!(load_policy(&path).is_err());
        assert_eq!(load_config(&path).policy, Policy::default());
    }

    #[test]
    fn a_mistyped_policy_key_is_an_error_that_names_the_key() {
        let path = write("typo", "[policy]\nmax_cvvs = 7.0\n");
        let error = load_policy(&path)
            .expect_err("a typo is an error")
            .to_string();
        assert!(error.contains("max_cvvs"), "{error}");
    }

    #[test]
    fn an_unknown_severity_is_an_error_that_lists_the_bands() {
        let path = write("band", "[policy]\nfail_on_severity = \"nope\"\n");
        let error = load_policy(&path)
            .expect_err("an unknown band is an error")
            .to_string();
        assert!(error.contains("nope"), "{error}");
        assert!(error.contains("critical"), "{error}");
    }

    #[test]
    fn the_config_field_and_load_policy_agree() {
        // One schema, one figment: the embedded field cannot drift from the
        // separately loaded one.
        let path = write(
            "agree",
            "[policy]\nfail_on_severity = \"high\"\nmax_major_behind = 2\n",
        );

        let Ok(PolicySource::Configured(policy)) = load_policy(&path) else {
            panic!("expected a configured policy");
        };
        assert_eq!(load_config(&path).policy, policy);
        assert_eq!(policy.fail_on_severity, Some(Severity::High));
    }
}
