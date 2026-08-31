//! A deliberately small SPDX expression evaluator, for one question only:
//! **does every license this expression obliges me to accept lie inside the
//! allowlist?**
//!
//! # What it understands
//!
//! Atoms, `OR`, `AND`, `WITH`, and parentheses — the grammar crates.io, npm,
//! Packagist, and Hex actually publish. Operators and identifiers are matched
//! ASCII-case-insensitively, because no two SPDX identifiers differ only by case
//! while a user typing `apache-2.0` into their allowlist is entirely likely. A
//! bare `/` is additionally accepted as `OR`: it is the legacy crates.io spelling
//! (`MIT/Apache-2.0`), still present on older crates, and rejecting it would
//! manufacture violations.
//!
//! # The four judgement calls
//!
//! - **`AND` is conjunction.** `(MIT OR Apache-2.0) AND Unicode-DFS-2016` is
//!   *denied* by an allowlist of `MIT, Apache-2.0`: there is no way to take that
//!   package without also taking `Unicode-DFS-2016`.
//! - **`WITH` is satisfied by the bare base license.** `Apache-2.0 WITH
//!   LLVM-exception` passes an allowlist containing plain `Apache-2.0`, because an
//!   SPDX exception is by definition a grant of *additional permission* and can
//!   never be more restrictive than the license it modifies. Writing the whole
//!   `A WITH B` string in the allowlist also works. This is more permissive than
//!   `cargo-deny`, which requires the exception to be named.
//! - **`+` is part of the identifier.** `GPL-2.0+` matches only an allowlist entry
//!   written `GPL-2.0+`, never `GPL-2.0` — "or later" can pull in GPL-3.0, which
//!   the user did not allow.
//! - **There is no identifier registry.** This module knows the allowlist and
//!   nothing else, so an atom that parses but is not listed is denied whether it
//!   is a real SPDX identifier or a typo. No deprecated-ID aliasing
//!   (`GPL-2.0` is not `GPL-2.0-only`) and no compatibility reasoning.
//!
//! Anything the grammar rejects — adjacent atoms, unbalanced parentheses, an
//! embedded newline, a pasted license body — is [`Verdict::Unparsed`]. It is
//! never silently treated as allowed.

/// What an allowlist has to say about one license expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Every license combination the expression permits is inside the allowlist.
    Allowed,
    /// The expression parsed, and no combination it permits is inside the
    /// allowlist.
    Denied,
    /// The text is not an SPDX expression this module can read.
    Unparsed,
}

/// Evaluate `expression` against `allowed`.
///
/// `allowed` holds bare identifiers (or a full `A WITH B` pair); each entry is
/// trimmed, its internal whitespace collapsed, and compared case-insensitively.
/// An empty `allowed` denies everything that parses — callers who mean "no
/// license rule" must not call this at all.
pub(crate) fn evaluate(expression: &str, allowed: &[String]) -> Verdict {
    let Some(tokens) = tokenize(expression) else {
        return Verdict::Unparsed;
    };
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        allowed,
    };
    let value = parser.expression();
    // A trailing token means the text only *starts* like an expression
    // (`MIT License`), which is prose, not a denial.
    if parser.pos != tokens.len() {
        return Verdict::Unparsed;
    }
    match value {
        Some(true) => Verdict::Allowed,
        Some(false) => Verdict::Denied,
        None => Verdict::Unparsed,
    }
}

/// One lexical unit of an expression.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Or,
    And,
    With,
    Open,
    Close,
    Atom(String),
}

/// Split `input` into tokens, or `None` if it contains anything an SPDX
/// expression cannot.
///
/// Only space and tab separate tokens: a newline is *rejected* rather than
/// treated as whitespace, because a value containing one is a pasted license
/// body rather than an expression, and saying so is more honest than parsing its
/// first line.
fn tokenize(input: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for ch in input.chars() {
        match ch {
            ' ' | '\t' => flush(&mut word, &mut tokens),
            '(' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Open);
            }
            ')' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Close);
            }
            '/' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Or);
            }
            c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_') => word.push(c),
            _ => return None,
        }
    }
    flush(&mut word, &mut tokens);
    (!tokens.is_empty()).then_some(tokens)
}

/// Emit the pending word as an operator or an atom, and clear it.
fn flush(word: &mut String, tokens: &mut Vec<Token>) {
    if word.is_empty() {
        return;
    }
    let token = if word.eq_ignore_ascii_case("or") {
        Token::Or
    } else if word.eq_ignore_ascii_case("and") {
        Token::And
    } else if word.eq_ignore_ascii_case("with") {
        Token::With
    } else {
        Token::Atom(word.clone())
    };
    word.clear();
    tokens.push(token);
}

/// A recursive-descent parser that evaluates as it goes: each production returns
/// whether the sub-expression is satisfied by the allowlist, or `None` if the
/// tokens do not form one.
struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    allowed: &'a [String],
}

impl Parser<'_> {
    /// `expression := term (OR term)*` — a disjunction: any branch will do.
    fn expression(&mut self) -> Option<bool> {
        let mut value = self.term()?;
        while matches!(self.tokens.get(self.pos), Some(Token::Or)) {
            self.pos += 1;
            // Evaluated eagerly rather than short-circuited: the right-hand side
            // still has to parse for the whole expression to be an expression.
            let rhs = self.term()?;
            value = value || rhs;
        }
        Some(value)
    }

    /// `term := factor (AND factor)*` — a conjunction: every side is obligatory.
    fn term(&mut self) -> Option<bool> {
        let mut value = self.factor()?;
        while matches!(self.tokens.get(self.pos), Some(Token::And)) {
            self.pos += 1;
            let rhs = self.factor()?;
            value = value && rhs;
        }
        Some(value)
    }

    /// `factor := '(' expression ')' | atom (WITH atom)?`
    fn factor(&mut self) -> Option<bool> {
        match self.tokens.get(self.pos)? {
            Token::Open => {
                self.pos += 1;
                let value = self.expression()?;
                if !matches!(self.tokens.get(self.pos), Some(Token::Close)) {
                    return None;
                }
                self.pos += 1;
                Some(value)
            }
            Token::Atom(name) => {
                let name = name.clone();
                self.pos += 1;
                if !matches!(self.tokens.get(self.pos), Some(Token::With)) {
                    return Some(self.is_allowed(&name));
                }
                self.pos += 1;
                let Some(Token::Atom(exception)) = self.tokens.get(self.pos) else {
                    return None;
                };
                let pair = format!("{name} WITH {exception}");
                self.pos += 1;
                Some(self.is_allowed(&pair) || self.is_allowed(&name))
            }
            _ => None,
        }
    }

    /// Whether the allowlist names this license.
    fn is_allowed(&self, license: &str) -> bool {
        self.allowed
            .iter()
            .any(|entry| normalize(entry).eq_ignore_ascii_case(license))
    }
}

/// An allowlist entry with its surrounding whitespace trimmed and any internal
/// run collapsed to one space, so `"  Apache-2.0   WITH  LLVM-exception "` and
/// `"Apache-2.0 WITH LLVM-exception"` are the same entry.
fn normalize(entry: &str) -> String {
    entry.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|e| (*e).to_string()).collect()
    }

    #[test]
    fn the_grammar_is_evaluated_against_the_allowlist() {
        let permissive = allowlist(&["MIT", "Apache-2.0"]);
        let cases: &[(&str, &[String], Verdict)] = &[
            // The plain cases.
            ("MIT", &permissive, Verdict::Allowed),
            ("GPL-3.0", &permissive, Verdict::Denied),
            // Disjunction: one acceptable branch is enough.
            ("MIT OR Apache-2.0", &permissive, Verdict::Allowed),
            ("MIT OR GPL-3.0", &permissive, Verdict::Allowed),
            ("GPL-3.0 OR LGPL-3.0", &permissive, Verdict::Denied),
            // The legacy crates.io slash is OR.
            ("MIT/Apache-2.0", &permissive, Verdict::Allowed),
            ("GPL-3.0/LGPL-3.0", &permissive, Verdict::Denied),
            // Conjunction: an unavoidable extra license denies the whole thing.
            (
                "(MIT OR Apache-2.0) AND Unicode-DFS-2016",
                &permissive,
                Verdict::Denied,
            ),
            ("MIT AND Apache-2.0", &permissive, Verdict::Allowed),
            // Nesting, and mixed case operators.
            (
                "((MIT or Apache-2.0) AND (MIT))",
                &permissive,
                Verdict::Allowed,
            ),
            // Case-insensitive identifiers, in the expression and the allowlist.
            ("mit", &permissive, Verdict::Allowed),
            // Not an expression at all.
            ("MIT License", &permissive, Verdict::Unparsed),
            ("", &permissive, Verdict::Unparsed),
            ("   ", &permissive, Verdict::Unparsed),
            ("(MIT OR Apache-2.0", &permissive, Verdict::Unparsed),
            ("MIT OR", &permissive, Verdict::Unparsed),
            ("OR MIT", &permissive, Verdict::Unparsed),
            ("MIT\nApache-2.0", &permissive, Verdict::Unparsed),
            ("Apache 2.0", &permissive, Verdict::Unparsed),
            ("MIT WITH", &permissive, Verdict::Unparsed),
        ];
        for &(expression, allowed, expected) in cases {
            assert_eq!(
                evaluate(expression, allowed),
                expected,
                "`{expression}` against {allowed:?}"
            );
        }
    }

    #[test]
    fn an_exception_is_satisfied_by_its_base_license() {
        // An SPDX exception only ever *adds* permission, so allowing the base
        // license allows it with an exception attached.
        let base = allowlist(&["Apache-2.0"]);
        assert_eq!(
            evaluate("Apache-2.0 WITH LLVM-exception", &base),
            Verdict::Allowed
        );
        // Naming the whole pair works too, and does not allow the bare license's
        // siblings.
        let pair = allowlist(&["Apache-2.0 WITH LLVM-exception"]);
        assert_eq!(
            evaluate("Apache-2.0 WITH LLVM-exception", &pair),
            Verdict::Allowed
        );
        assert_eq!(
            evaluate("Apache-2.0 WITH  llvm-exception", &pair),
            Verdict::Allowed,
            "entries are whitespace- and case-normalized"
        );
        assert_eq!(evaluate("Apache-2.0", &pair), Verdict::Denied);
        assert_eq!(
            evaluate("GPL-2.0 WITH Classpath-exception-2.0", &base),
            Verdict::Denied
        );
    }

    #[test]
    fn or_later_is_a_distinct_identifier() {
        // "or later" can pull in GPL-3.0, which allowing GPL-2.0 did not.
        assert_eq!(
            evaluate("GPL-2.0+", &allowlist(&["GPL-2.0"])),
            Verdict::Denied
        );
        assert_eq!(
            evaluate("GPL-2.0+", &allowlist(&["GPL-2.0+"])),
            Verdict::Allowed
        );
        assert_eq!(
            evaluate("GPL-2.0", &allowlist(&["GPL-2.0+"])),
            Verdict::Denied
        );
    }

    #[test]
    fn an_empty_allowlist_denies_everything_that_parses() {
        // The caller is responsible for not running the rule at all; this module
        // must not invent a pass.
        assert_eq!(evaluate("MIT", &[]), Verdict::Denied);
        assert_eq!(evaluate("MIT License", &[]), Verdict::Unparsed);
    }
}
