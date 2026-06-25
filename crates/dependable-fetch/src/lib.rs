//! Async IO layer for `dependable`: registry adapters, the OSV client, and caching.
//!
//! This crate depends on [`dependable_core`] for the pure data model and adds the
//! network and concurrency concerns. The crates.io fetcher, OSV client, and moka
//! cache land with the Rust/Crates.io MVP.

/// Short identifier for this crate. Placeholder until the fetch layer lands.
#[must_use]
pub fn name() -> &'static str {
    "dependable-fetch"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_stable() {
        assert_eq!(name(), "dependable-fetch");
    }
}
