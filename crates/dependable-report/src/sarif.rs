//! SARIF v2.1.0 output for code-scanning tooling.
//!
//! **Slot — no implementation yet.** This module's contract is fixed so the SARIF
//! renderer can be dropped in without changing anything around it.
//!
//! # Contract
//!
//! ```text
//! pub fn render(report: &Report) -> Result<String, ReportError>
//! ```
//!
//! - Emits SARIF v2.1.0 as an owned `String`, from hand-rolled `serde` structs
//!   rather than a SARIF crate, so the schema stays visible and pinned.
//! - Rule IDs: `DEP001` for an outdated dependency, `DEP002` for a vulnerable one.
//! - `tool.driver.version` is [`crate::VERSION`].
//! - Surfaced through the CLI as `dependable check --format sarif`.
//!
//! # Off-by-one — read before writing `region`
//!
//! [`Item::version_line`](dependable_core::Item::version_line),
//! [`version_col_start`](dependable_core::Item::version_col_start), and
//! [`version_col_end`](dependable_core::Item::version_col_end) are
//! **zero-indexed**, while SARIF's `region.startLine` / `startColumn` /
//! `endColumn` are **one-based**. Every one of them must have 1 added before it
//! goes into a SARIF region, or every reported location lands one line and one
//! column short of the version it points at.
