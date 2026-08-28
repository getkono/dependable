//! Glob matching for the search box.
//!
//! Patterns match **package names**, not paths, so `*` deliberately spans `/`:
//! `@types/*` and `*/monolog` have to work for npm scoped names and Composer
//! vendor names. A bare word with no glob metacharacter is treated as a substring
//! search, because typing `serde` and being shown nothing is never what was meant.

use globset::{Glob, GlobBuilder, GlobMatcher};

/// A compiled search pattern.
#[derive(Debug, Clone)]
pub enum Filter {
    /// A glob, compiled once per query and matched against every candidate name.
    Glob(Box<GlobMatcher>),
    /// A case-insensitive substring, used when the query contains no glob syntax.
    Substring(String),
}

impl Filter {
    /// Compile `query`, or `None` when it is blank.
    ///
    /// An unparseable glob falls back to a substring search rather than failing:
    /// the query box is being typed into, so half-written patterns are the norm.
    #[must_use]
    pub fn new(query: &str) -> Option<Self> {
        let query = query.trim();
        if query.is_empty() {
            return None;
        }
        if !has_glob_syntax(query) {
            return Some(Self::Substring(query.to_lowercase()));
        }
        Some(compile(query).map_or_else(
            || Self::Substring(query.to_lowercase()),
            |m| Self::Glob(Box::new(m)),
        ))
    }

    /// Whether `name` matches.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Glob(m) => m.is_match(name),
            Self::Substring(needle) => name.to_lowercase().contains(needle),
        }
    }
}

/// Whether the query uses any glob metacharacter.
fn has_glob_syntax(query: &str) -> bool {
    query.contains(['*', '?', '[', '{'])
}

/// Compile a glob that treats `/` as an ordinary character.
fn compile(query: &str) -> Option<GlobMatcher> {
    GlobBuilder::new(query)
        // Package names are not paths: `*` must span `/` so `@types/*` works.
        .literal_separator(false)
        .case_insensitive(true)
        .build()
        .ok()
        .or_else(|| Glob::new(query).ok())
        .map(|g| g.compile_matcher())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(query: &str, name: &str) -> bool {
        Filter::new(query).expect("non-empty query").matches(name)
    }

    #[test]
    fn a_blank_query_is_not_a_filter() {
        assert!(Filter::new("").is_none());
        assert!(Filter::new("   ").is_none());
    }

    #[test]
    fn a_trailing_star_matches_a_prefix() {
        assert!(matches("serde*", "serde"));
        assert!(matches("serde*", "serde_json"));
        assert!(!matches("serde*", "tokio"));
    }

    #[test]
    fn a_star_spans_a_slash_for_scoped_names() {
        assert!(matches("@types/*", "@types/node"));
        assert!(matches("*monolog*", "monolog/monolog"));
        assert!(matches("*/monolog", "monolog/monolog"));
    }

    #[test]
    fn alternation_matches_any_branch() {
        assert!(matches("{tokio,hyper}*", "tokio-util"));
        assert!(matches("{tokio,hyper}*", "hyper"));
        assert!(!matches("{tokio,hyper}*", "serde"));
    }

    #[test]
    fn a_bare_word_is_a_substring_search() {
        // Nobody typing `serde` means "the package named exactly serde".
        assert!(matches("serde", "serde_json"));
        assert!(matches("log", "monolog/monolog"));
        assert!(!matches("serde", "tokio"));
    }

    #[test]
    fn matching_ignores_case() {
        assert!(matches("SERDE", "serde_json"));
        assert!(matches("Ser*", "serde"));
    }

    #[test]
    fn a_half_written_glob_still_searches() {
        // `[` opens a character class; on its own it does not compile.
        let filter = Filter::new("serde[").expect("a filter");
        assert!(!filter.matches("tokio"), "it must not match everything");
    }

    #[test]
    fn a_question_mark_matches_one_character() {
        assert!(matches("serde?", "serdeX"));
        assert!(!matches("serde?", "serde"));
    }
}
