//! The version comparison engine (built on the `semver` crate).

pub mod checker;
pub mod elixir;
pub mod maven;
pub mod normalize;
pub mod nuget;
pub mod python;

pub use checker::{Evaluation, check_version, check_version_for, to_version_req};
pub use normalize::{
    UnstableFilter, is_prerelease, normalize_constraint, normalize_version, to_semver_constraint,
    try_to_semver_constraint,
};
