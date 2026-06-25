//! Pure, IO-free parsing and version-checking core for `dependable`.
//!
//! This crate takes `&str` manifest content and returns plain data structures.
//! It performs zero filesystem and zero network access, which keeps it fully
//! unit-testable without mocking.
//!
//! The type model, parsers, and semver engine land with the Rust/Crates.io MVP.

/// Short identifier for this crate. Placeholder until the type model lands.
#[must_use]
pub fn name() -> &'static str {
    "dependable-core"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_stable() {
        assert_eq!(name(), "dependable-core");
    }
}
