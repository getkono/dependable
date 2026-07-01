//! Parser for npm's `.npmrc` configuration (registries + auth tokens).
//!
//! `.npmrc` is an INI-like `key = value` file. This IO-free parser extracts the
//! three things a private-registry version check needs: the default `registry`,
//! per-scope (`@scope:registry`) registries, and per-registry `_authToken`s. The
//! CLI reads the file(s) (and expands `${VAR}`); the fetcher sends the token as
//! `Authorization: Bearer <token>`.

use std::collections::BTreeMap;

/// The relevant contents of one or more merged `.npmrc` files.
///
/// `#[non_exhaustive]`: build via [`parse_npmrc`]; future fields stay additive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NpmrcConfig {
    /// The default `registry = <url>`, if set.
    pub default_registry: Option<String>,
    /// `@scope` → registry URL, from `@scope:registry = <url>` lines.
    pub scope_registries: BTreeMap<String, String>,
    /// Auth tokens keyed by canonical nerf-dart (`//host/path/`), from
    /// `//host/path/:_authToken = <token>` lines.
    pub tokens: BTreeMap<String, String>,
}

impl NpmrcConfig {
    /// The bearer token configured for `registry_url`, matched by nerf-dart — the
    /// scheme-less `//host/path/` form npm keys `_authToken` on.
    #[must_use]
    pub fn token_for(&self, registry_url: &str) -> Option<&str> {
        self.tokens
            .get(&nerf_dart(registry_url))
            .map(String::as_str)
    }

    /// Merge a `higher`-precedence config over `self` (e.g. project over user):
    /// a present `default_registry` and any map entries in `higher` win; the rest
    /// fall through to `self`.
    #[must_use]
    pub fn merge(mut self, higher: NpmrcConfig) -> NpmrcConfig {
        if higher.default_registry.is_some() {
            self.default_registry = higher.default_registry;
        }
        self.scope_registries.extend(higher.scope_registries);
        self.tokens.extend(higher.tokens);
        self
    }
}

/// Parse `.npmrc` content into an [`NpmrcConfig`]. Unknown keys are ignored; blank
/// lines and `#`/`;` comments are skipped; quoted values are unquoted. IO-free —
/// the caller reads the file and performs any `${VAR}` expansion beforehand.
#[must_use]
pub fn parse_npmrc(content: &str) -> NpmrcConfig {
    let mut config = NpmrcConfig::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            continue;
        }
        if key == "registry" {
            config.default_registry = Some(value.to_owned());
        } else if let Some(scope) = key.strip_suffix(":registry")
            && scope.starts_with('@')
        {
            config
                .scope_registries
                .insert(scope.to_owned(), value.to_owned());
        } else if let Some(dart) = key.strip_suffix(":_authToken")
            && dart.starts_with("//")
        {
            config.tokens.insert(nerf_dart(dart), value.to_owned());
        }
    }
    config
}

/// Canonicalize a registry URL or nerf-dart to npm's `//host/path/` form (no
/// scheme, exactly one trailing slash) so registries and token keys compare equal.
fn nerf_dart(s: &str) -> String {
    let rest = match s.split_once("://") {
        Some((_, rest)) => rest,
        None => s.trim_start_matches("//"),
    };
    format!("//{}/", rest.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_registry_scopes_and_tokens() {
        let content = concat!(
            "registry=https://registry.npmjs.org/\n",
            "@corp:registry=https://npm.corp.example/\n",
            "//npm.corp.example/:_authToken=corp-secret\n",
            "//registry.npmjs.org/:_authToken=public-secret\n",
            "; a comment\n",
            "# another\n",
            "save-exact=true\n",
        );
        let c = parse_npmrc(content);
        assert_eq!(
            c.default_registry.as_deref(),
            Some("https://registry.npmjs.org/")
        );
        assert_eq!(
            c.scope_registries.get("@corp").map(String::as_str),
            Some("https://npm.corp.example/")
        );
        assert_eq!(
            c.token_for("https://npm.corp.example/"),
            Some("corp-secret")
        );
        // A registry URL without a trailing slash still resolves its token.
        assert_eq!(
            c.token_for("https://registry.npmjs.org"),
            Some("public-secret")
        );
    }

    #[test]
    fn ignores_blank_comment_and_unknown_lines() {
        let c = parse_npmrc("\n\n; comment\nsave-exact=true\nnot-a-pair\n");
        assert_eq!(c, NpmrcConfig::default());
    }

    #[test]
    fn merge_lets_higher_precedence_win() {
        let user = parse_npmrc("registry=https://user.example/\n//user.example/:_authToken=u\n");
        let project =
            parse_npmrc("registry=https://project.example/\n@x:registry=https://x.example/\n");
        let merged = user.merge(project);
        assert_eq!(
            merged.default_registry.as_deref(),
            Some("https://project.example/")
        );
        // The user-scoped token survives the merge.
        assert_eq!(merged.token_for("https://user.example/"), Some("u"));
        assert_eq!(
            merged.scope_registries.get("@x").map(String::as_str),
            Some("https://x.example/")
        );
    }

    #[test]
    fn nerf_dart_normalizes_scheme_and_trailing_slash() {
        assert_eq!(nerf_dart("https://host/path"), "//host/path/");
        assert_eq!(nerf_dart("//host/path/"), "//host/path/");
        assert_eq!(nerf_dart("http://host"), "//host/");
    }
}
