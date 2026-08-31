//! Policy evaluation for CI gating.
//!
//! **Slot — no implementation yet.** This module's contract is fixed so policy
//! evaluation can be dropped in without changing anything around it.
//!
//! # Contract
//!
//! ```text
//! pub fn evaluate(report: &Report, policy: &Policy) -> PolicyOutcome
//! ```
//!
//! - `Policy` is defined **here**, deriving `serde::Deserialize`, and is embedded
//!   by the CLI as a field on its `config::Config`. One definition of the schema,
//!   in the crate that enforces it — the config file and the evaluator can never
//!   drift apart. (`serde` is added by the change that defines `Policy`.)
//! - `PolicyOutcome` reports whether the report passed and which rules it violated.
//! - Exit-code mapping, which the CLI already implements for `--fail-on`: pass
//!   exits `0`, a policy violation exits `1`, an error exits `2`.
//! - License policy (`allowed_licenses`, plus the license carrier on
//!   [`ManifestResults`](crate::ManifestResults)) extends this module later. It
//!   must **not** introduce a `dependable-fetch` dependency: this crate renders
//!   strings and stays free of an async runtime.
