//! Turning the URLs a registry stored into ones a person can read and a
//! browser can open.
//!
//! Kept apart from the rendering that draws them, and from the launcher that
//! opens them, because it is pure string work: every registry writes URLs in
//! its own ecosystem's shape, and none of that is anyone else's problem.

/// The readable form of a URL: what a person would say out loud.
///
/// Registries publish URLs in whatever shape their ecosystem writes them, and
/// the noise is never the informative part. npm in particular stores
/// `git+https://github.com/facebook/react.git`, of which only the middle
/// twenty characters tell the reader anything.
///
/// The full URL is still what the link points at; only the label is shortened.
#[must_use]
pub fn display_url(url: &str) -> String {
    let trimmed = url
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git://")
        .trim_start_matches("ssh://")
        .trim_start_matches("www.")
        .trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    if trimmed.is_empty() {
        url.to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// The URL a hyperlink should point at, normalised from what a registry stored.
///
/// The label may be shortened for reading, but the target has to remain
/// something a browser can open: npm's `git+…` prefix is a package-manager
/// convention, not a scheme any browser knows.
#[must_use]
pub fn target_url(url: &str) -> String {
    let trimmed = url.trim().trim_start_matches("git+");
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_owned();
    }
    if let Some(rest) = trimmed.strip_prefix("git://") {
        return format!("https://{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@") {
        return format!("https://{rest}");
    }
    // A bare `github:owner/repo` shorthand, or a bare host and path.
    if let Some(rest) = trimmed.strip_prefix("github:") {
        return format!("https://github.com/{rest}");
    }
    format!("https://{trimmed}")
}

/// A URL a registry may have recorded as nothing at all.
///
/// Registries store an unset field as an empty string as readily as they omit
/// it, and the two mean the same thing. Left alone, `Some("")` wins over a
/// field that *was* published and renders as a label with nothing after it —
/// which is exactly what the detail pane promises never to show.
#[must_use]
pub fn published(url: Option<&str>) -> Option<&str> {
    url.map(str::trim).filter(|url| !url.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_reads_as_the_part_that_identifies_it() {
        assert_eq!(
            display_url("https://github.com/serde-rs/serde"),
            "github.com/serde-rs/serde"
        );
        assert_eq!(
            display_url("git+https://github.com/facebook/react.git"),
            "github.com/facebook/react",
            "npm stores a git+ prefix and a .git suffix that say nothing"
        );
        assert_eq!(display_url("https://www.example.com/"), "example.com");
    }
    #[test]
    fn a_shortened_label_still_points_at_something_openable() {
        assert_eq!(
            target_url("git+https://github.com/facebook/react.git"),
            "https://github.com/facebook/react",
            "git+ is a package-manager convention, not a browser scheme"
        );
        assert_eq!(target_url("git://github.com/a/b"), "https://github.com/a/b");
        assert_eq!(
            target_url("github:owner/repo"),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            target_url("https://example.com"),
            "https://example.com",
            "an ordinary URL is left alone"
        );
    }
    #[test]
    fn a_url_that_is_only_noise_is_kept_verbatim() {
        // Better to show something odd than to show nothing at all.
        assert_eq!(display_url("https://"), "https://");
    }

    #[test]
    fn a_url_a_registry_left_blank_counts_as_unpublished() {
        // Registries store an unset field as "" as readily as they omit it.
        assert_eq!(published(Some("")), None);
        assert_eq!(published(Some("   ")), None);
        assert_eq!(published(None), None);
        assert_eq!(published(Some(" https://e.com ")), Some("https://e.com"));
    }
}
