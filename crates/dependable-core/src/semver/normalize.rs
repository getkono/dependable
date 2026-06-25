//! Version / constraint normalization helpers.

/// Normalize a version requirement string into something `semver::VersionReq`
/// accepts.
///
/// For Rust this is largely a pass-through — the `semver` crate already
/// understands Cargo's syntax (`1`, `1.2`, `^1.2.3`, `=1.0.0`, `>=1, <2`) — so we
/// only trim surrounding whitespace. Other ecosystems will translate their own
/// constraint dialects in dedicated modules.
#[must_use]
pub fn normalize_constraint(constraint: &str) -> String {
    constraint.trim().to_string()
}

/// Normalize a concrete version string: strip a leading `v`/`V` and pad partial
/// versions (`1` → `1.0.0`, `1.2` → `1.2.0`) so they parse as `semver::Version`.
#[must_use]
pub fn normalize_version(version: &str) -> String {
    let trimmed = version.trim();
    let stripped = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    let core = stripped.split(['-', '+']).next().unwrap_or(stripped);
    let suffix = &stripped[core.len()..];
    match core.bytes().filter(|&b| b == b'.').count() {
        0 => format!("{core}.0.0{suffix}"),
        1 => format!("{core}.0{suffix}"),
        _ => stripped.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_partial_versions() {
        assert_eq!(normalize_version("1"), "1.0.0");
        assert_eq!(normalize_version("1.2"), "1.2.0");
        assert_eq!(normalize_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn strips_v_prefix() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("V2.0"), "2.0.0");
    }

    #[test]
    fn trims_constraint() {
        assert_eq!(normalize_constraint("  ^1.0 "), "^1.0");
    }
}
