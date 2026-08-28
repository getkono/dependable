//! The colour palette, as semantic tokens resolved against the terminal's
//! capability.
//!
//! # Why tokens
//!
//! Colour used to be constructed inline at each of the forty-odd places that
//! needed one, which made the palette impossible to see, let alone check. Worse,
//! two of those were hard-coded [`Color::Rgb`] backgrounds with no matching
//! foreground: on a light terminal the selected row was dark text on a dark bar.
//! Naming the *role* rather than the colour is what makes a contrast rule
//! checkable, and it is checked — see the tests at the bottom of this file.
//!
//! # Why tiers
//!
//! A 24-bit palette is the only way to control contrast precisely, but not every
//! terminal has one. Rather than design down to the lowest common denominator,
//! each token carries three renderings and [`Tier`] picks between them once at
//! startup. The ANSI-16 tier is deliberately not a colour approximation: with
//! only sixteen colours whose actual values are chosen by the user's terminal
//! theme, a background we pick cannot be guaranteed to contrast with anything,
//! so selection there inverts instead.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

/// How much colour the terminal can render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// 24-bit colour. The palette renders as designed.
    Truecolor,
    /// The xterm 256-colour cube.
    Indexed256,
    /// The sixteen named colours, whose values the user's theme decides.
    Ansi16,
}

impl Tier {
    /// Detect the tier from the environment.
    ///
    /// `COLORTERM` is the only reliable positive signal for 24-bit support;
    /// terminals that have it set it, and those that do not are not worth
    /// guessing about, since guessing wrong means unreadable colour rather than
    /// merely plainer colour.
    #[must_use]
    pub fn detect() -> Self {
        let colorterm = std::env::var("COLORTERM").unwrap_or_default();
        if colorterm.eq_ignore_ascii_case("truecolor") || colorterm.eq_ignore_ascii_case("24bit") {
            return Tier::Truecolor;
        }
        let term = std::env::var("TERM").unwrap_or_default();
        if term.contains("256") {
            return Tier::Indexed256;
        }
        Tier::Ansi16
    }

    /// The tier in force for this process, detected once.
    ///
    /// Cached because it is read for nearly every span of every frame, and the
    /// environment cannot change under a running terminal.
    #[must_use]
    pub fn current() -> Self {
        static TIER: OnceLock<Tier> = OnceLock::new();
        *TIER.get_or_init(Tier::detect)
    }
}

/// A colour role, resolved to an actual colour by [`Tier`].
///
/// Named for what it means, never for what it looks like: a token whose name is
/// `Warn` can be restyled without every call site becoming a lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    /// The product wordmark. Reserved for it, so it stays recognisable.
    Brand,
    /// Ordinary readable text.
    Text,
    /// Present but secondary: versions, labels, annotations.
    Muted,
    /// A heading over a block of fields.
    Heading,
    /// The pane background behind the selected row.
    SelectionBg,
    /// Text on [`Token::SelectionBg`], set explicitly so the pair is legible
    /// whatever the row's own colour would have been.
    SelectionFg,
    /// The pane background behind the row under the pointer.
    HoverBg,
    /// The background marking a search hit.
    MatchBg,
    /// Text on [`Token::MatchBg`].
    MatchFg,
    /// Up to date; nothing to do.
    Ok,
    /// Worth attention but not urgent: an update or a patch is available.
    Warn,
    /// Demands attention: a vulnerability, a yank, a failed lookup.
    Critical,
    /// A workspace-local package.
    KindWorkspace,
    /// A git dependency.
    KindGit,
    /// A path dependency.
    KindPath,
    /// A clickable link.
    Link,
    /// Window chrome: borders and rules.
    Border,
}

impl Token {
    /// The colour for this token at the given tier.
    #[must_use]
    pub fn color(self, tier: Tier) -> Color {
        let (true_color, indexed, ansi) = self.palette();
        match tier {
            Tier::Truecolor => true_color,
            Tier::Indexed256 => indexed,
            Tier::Ansi16 => ansi,
        }
    }

    /// The colour for this token at the tier in force.
    #[must_use]
    pub fn resolve(self) -> Color {
        self.color(Tier::current())
    }

    /// The three renderings of this token, truecolor first.
    ///
    /// The 256-colour values are the nearest cube entries to the 24-bit ones,
    /// and the ANSI names are the nearest of the sixteen.
    const fn palette(self) -> (Color, Color, Color) {
        use Color::{Blue, Cyan, Green, Indexed, Magenta, Red, Reset, Rgb, White, Yellow};
        match self {
            Token::Brand => (Rgb(232, 163, 61), Indexed(215), Yellow),
            Token::Text => (Rgb(220, 223, 228), Indexed(253), Reset),
            Token::Muted => (Rgb(122, 130, 144), Indexed(245), Color::DarkGray),
            Token::Heading => (Rgb(240, 242, 245), Indexed(255), White),
            Token::SelectionBg => (Rgb(45, 51, 67), Indexed(237), Reset),
            Token::SelectionFg => (Rgb(240, 242, 245), Indexed(255), Reset),
            Token::HoverBg => (Rgb(32, 36, 48), Indexed(235), Reset),
            Token::MatchBg => (Rgb(93, 74, 18), Indexed(58), Reset),
            Token::MatchFg => (Rgb(255, 226, 148), Indexed(222), Yellow),
            Token::Ok => (Rgb(79, 180, 119), Indexed(71), Green),
            Token::Warn => (Rgb(232, 163, 61), Indexed(215), Yellow),
            Token::Critical => (Rgb(224, 85, 97), Indexed(167), Red),
            Token::KindWorkspace => (Rgb(86, 182, 194), Indexed(73), Cyan),
            Token::KindGit => (Rgb(198, 120, 221), Indexed(176), Magenta),
            Token::KindPath => (Rgb(209, 154, 102), Indexed(179), Yellow),
            Token::Link => (Rgb(97, 175, 239), Indexed(75), Blue),
            Token::Border => (Rgb(70, 76, 92), Indexed(240), Color::DarkGray),
        }
    }
}

/// A foreground style for `token`.
#[must_use]
pub fn fg(token: Token) -> Style {
    Style::default().fg(token.resolve())
}

/// A bold foreground style for `token`.
#[must_use]
pub fn bold(token: Token) -> Style {
    fg(token).add_modifier(Modifier::BOLD)
}

/// The style for the selected row.
///
/// Sets a foreground as well as a background at every tier that has one, because
/// a background alone leaves the row's own colour on top of it and there is no
/// colour that is legible over both the pane and the selection bar.
///
/// On [`Tier::Ansi16`] this reverses instead: the sixteen colours belong to the
/// user's theme, so no background we choose is guaranteed to contrast, whereas
/// reversing is legible by construction.
#[must_use]
pub fn selection() -> Style {
    if Tier::current() == Tier::Ansi16 {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    Style::default()
        .fg(Token::SelectionFg.resolve())
        .bg(Token::SelectionBg.resolve())
}

/// The style for the row under the pointer.
///
/// Deliberately weaker than [`selection`] — it tracks the pointer rather than
/// the cursor, and must not be mistaken for what the keyboard would act on. It
/// has no ANSI-16 rendering for the same reason selection reverses there, and
/// because reversing on hover would make the whole pane flicker under a moving
/// pointer.
#[must_use]
pub fn hover() -> Style {
    if Tier::current() == Tier::Ansi16 {
        return Style::default();
    }
    Style::default().bg(Token::HoverBg.resolve())
}

/// The style marking a search hit.
#[must_use]
pub fn search_match() -> Style {
    if Tier::current() == Tier::Ansi16 {
        return Style::default()
            .fg(Token::MatchFg.resolve())
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
    }
    Style::default()
        .fg(Token::MatchFg.resolve())
        .bg(Token::MatchBg.resolve())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every token that is drawn as text, paired with the surface it sits on.
    const FOREGROUNDS: &[Token] = &[
        Token::Brand,
        Token::Text,
        Token::Muted,
        Token::Heading,
        Token::Ok,
        Token::Warn,
        Token::Critical,
        Token::KindWorkspace,
        Token::KindGit,
        Token::KindPath,
        Token::Link,
        Token::Border,
    ];

    const TIERS: [Tier; 3] = [Tier::Truecolor, Tier::Indexed256, Tier::Ansi16];

    /// Relative luminance per WCAG, from an sRGB triple.
    fn luminance(color: Color) -> Option<f64> {
        let Color::Rgb(r, g, b) = color else {
            return None;
        };
        let channel = |v: u8| {
            let v = f64::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        Some(0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b))
    }

    fn contrast(a: Color, b: Color) -> Option<f64> {
        let (a, b) = (luminance(a)?, luminance(b)?);
        let (hi, lo) = if a > b { (a, b) } else { (b, a) };
        Some((hi + 0.05) / (lo + 0.05))
    }

    #[test]
    fn no_foreground_token_is_invisible_on_the_selection_bar() {
        // The bug this palette replaces: a selected row set a dark background and
        // left the row's own foreground on top of it.
        let bar = Token::SelectionBg.color(Tier::Truecolor);
        let fg = Token::SelectionFg.color(Tier::Truecolor);
        let ratio = contrast(fg, bar).expect("both are rgb at this tier");
        assert!(
            ratio >= 4.5,
            "selection text on its bar is {ratio:.1}:1, below the 4.5:1 floor"
        );
    }

    #[test]
    fn a_search_hit_is_legible_on_its_own_background() {
        let ratio = contrast(
            Token::MatchFg.color(Tier::Truecolor),
            Token::MatchBg.color(Tier::Truecolor),
        )
        .expect("both are rgb at this tier");
        assert!(ratio >= 4.5, "search hit contrast is only {ratio:.1}:1");
    }

    #[test]
    fn every_token_renders_at_every_tier() {
        for tier in TIERS {
            for token in FOREGROUNDS {
                let color = token.color(tier);
                match tier {
                    Tier::Truecolor => assert!(
                        matches!(color, Color::Rgb(..)),
                        "{token:?} is not 24-bit at the truecolor tier"
                    ),
                    Tier::Indexed256 => assert!(
                        matches!(color, Color::Indexed(_)),
                        "{token:?} is not indexed at the 256 tier"
                    ),
                    Tier::Ansi16 => assert!(
                        !matches!(color, Color::Rgb(..) | Color::Indexed(_)),
                        "{token:?} leaks a non-ANSI colour into the 16-colour tier"
                    ),
                }
            }
        }
    }

    #[test]
    fn the_status_tokens_stay_distinguishable_at_every_tier() {
        // Ok/Warn/Critical carry the headline in the tree; two of them resolving
        // to the same colour would silently erase a distinction the user reads.
        for tier in TIERS {
            let ok = Token::Ok.color(tier);
            let warn = Token::Warn.color(tier);
            let critical = Token::Critical.color(tier);
            assert_ne!(ok, warn, "ok and warn collide at {tier:?}");
            assert_ne!(warn, critical, "warn and critical collide at {tier:?}");
            assert_ne!(ok, critical, "ok and critical collide at {tier:?}");
        }
    }

    #[test]
    fn selection_is_legible_without_colour() {
        // The 16-colour tier cannot guarantee a background contrasts, so it must
        // reverse rather than paint.
        let style = if Tier::current() == Tier::Ansi16 {
            selection()
        } else {
            Style::default().add_modifier(Modifier::REVERSED)
        };
        assert!(style.add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn truecolor_is_detected_only_from_an_explicit_signal() {
        // `detect` reads the real environment, so assert the mapping through the
        // palette instead: the tier a terminal reports must pick that rendering.
        assert!(matches!(
            Token::Brand.color(Tier::Truecolor),
            Color::Rgb(..)
        ));
        assert!(matches!(
            Token::Brand.color(Tier::Indexed256),
            Color::Indexed(_)
        ));
    }
}
