//! Report rendering for `dependable` — the V2 report layer.
//!
//! This crate turns check results into presentable artifacts: a self-contained
//! HTML report, SARIF for code-scanning tooling, and policy evaluation for CI.
//!
//! # Design
//!
//! - **It depends on [`dependable_core`] only.** Every type a report consumes
//!   ([`CheckResult`](dependable_core::CheckResult), [`Item`](dependable_core::Item),
//!   [`Ecosystem`](dependable_core::Ecosystem)) is defined there, and
//!   `dependable-fetch` merely re-exports them — so a caller can hand a
//!   `dependable_fetch::CheckResult` straight to a function here with no
//!   conversion, while this crate stays free of an async runtime.
//! - **It does no network IO**, and no filesystem IO of its own.
//! - **Renderers return owned `String`s.** The caller owns writing them
//!   anywhere, which keeps rendering tests hermetic.
//!
//! # Status
//!
//! Round 1 is a scaffold: [`Report`] and [`ReportError`] are real, and the
//! [`html`], [`sarif`], and [`policy`] modules are documented slots whose
//! contracts are fixed but whose implementations land later.

pub mod error;
pub mod html;
pub mod model;
pub mod policy;
pub mod sarif;
pub mod summary;

pub use error::ReportError;
pub use model::{ManifestResults, Report};
pub use summary::{EcosystemSummary, SeverityCounts, Summary};

/// The version of this crate, for report provenance
/// (HTML footer, SARIF `tool.driver.version`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
