//! The output of the version checker for a single dependency.

use std::collections::HashMap;

use crate::item::Item;
use crate::semver::Evaluation;

/// The result of checking one dependency against the registry + OSV.
///
/// `#[non_exhaustive]`: construct via [`CheckResult::new`] or
/// [`CheckResult::from_evaluation`] so future fields don't break callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CheckResult {
    /// The dependency this result describes.
    pub item: Item,
    /// The classified status of the dependency.
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

impl CheckResult {
    /// A bare result carrying only an item and a status (the `Local`/`Git`/`Error`
    /// cases, where no version data is available).
    #[must_use]
    pub fn new(item: Item, status: DependencyStatus) -> Self {
        Self {
            item,
            status,
            latest_compatible: None,
            latest_available: None,
            patch_available: false,
            current_vulnerabilities: Vec::new(),
            all_vulnerabilities: HashMap::new(),
        }
    }

    /// Build a result from a registry [`Evaluation`]. Vulnerability fields start
    /// empty; the fetch layer fills them after querying OSV.
    #[must_use]
    pub fn from_evaluation(item: Item, eval: Evaluation) -> Self {
        Self {
            item,
            status: eval.status,
            latest_compatible: eval.latest_compatible,
            latest_available: eval.latest_available,
            patch_available: eval.patch_available,
            current_vulnerabilities: Vec::new(),
            all_vulnerabilities: HashMap::new(),
        }
    }
}

/// The status of a single dependency.
///
/// `#[non_exhaustive]`: match with a wildcard arm so new statuses are additive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
