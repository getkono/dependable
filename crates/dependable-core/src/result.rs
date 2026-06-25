//! The output of the version checker for a single dependency.

use std::collections::HashMap;

use crate::item::Item;

/// The result of checking one dependency against the registry + OSV.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub item: Item,
    pub status: DependencyStatus,
    /// Best version satisfying the declared constraint.
    pub latest_compatible: Option<String>,
    /// Absolute latest available version (may be outside the constraint).
    pub latest_available: Option<String>,
    /// Whether a patch-level update exists within the constraint.
    pub patch_available: bool,
    /// Vulnerability IDs affecting the current/locked version.
    pub current_vulnerabilities: Vec<String>,
    /// All vulnerabilities by version, for "upgrading fixes N issues" reporting.
    pub all_vulnerabilities: HashMap<String, Vec<String>>,
}

/// The status of a single dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyStatus {
    UpToDate,
    PatchAvailable,
    UpdateAvailable,
    Outdated,
    Vulnerable,
    Error(String),
    Local,
    Git,
}

impl DependencyStatus {
    /// A short human-readable label.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            DependencyStatus::UpToDate => "up to date",
            DependencyStatus::PatchAvailable => "patch available",
            DependencyStatus::UpdateAvailable => "update available",
            DependencyStatus::Outdated => "outdated",
            DependencyStatus::Vulnerable => "vulnerable",
            DependencyStatus::Error(_) => "error",
            DependencyStatus::Local => "local",
            DependencyStatus::Git => "git",
        }
    }

    /// A stable uppercase token for machine-readable output.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            DependencyStatus::UpToDate => "OK",
            DependencyStatus::PatchAvailable => "PATCH",
            DependencyStatus::UpdateAvailable => "UPDATE",
            DependencyStatus::Outdated => "OUTDATED",
            DependencyStatus::Vulnerable => "VULN",
            DependencyStatus::Error(_) => "ERROR",
            DependencyStatus::Local => "LOCAL",
            DependencyStatus::Git => "GIT",
        }
    }
}
