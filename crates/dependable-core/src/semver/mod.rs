//! The version comparison engine (built on the `semver` crate).

pub mod checker;
pub mod normalize;

pub use checker::{Evaluation, check_version, to_version_req};
pub use normalize::{UnstableFilter, is_prerelease, normalize_constraint, normalize_version};
