//! A small JSON / JSONC scanner that yields every string *value* with its dotted
//! path and the byte span of its content (excluding the surrounding quotes).
//!
//! The JS-family parsers (`package.json`, `deno.json[c]`) need both the structure
//! *and* exact value positions (for in-place `--fix`), and `deno.jsonc` allows
//! comments — neither of which `serde_json` provides. This single pass covers all
//! of it: object keys build the path, array elements use their index, and `//`
//! and `/* */` comments are skipped.
//!
//! The scan is total: every reachable input either yields values or stops. Malformed
//! input yields whatever was scanned up to the error, and never panics or loops —
//! manifests arrive half-written from editors often enough that both were reachable.
//! Nesting deeper than 256 objects and arrays is treated the same way: the scan
//! stops there and keeps what it found, because the recursion that walks containers
//! would otherwise overflow the stack, and an overflow aborts the process outright.

/// The deepest nesting of objects and arrays the scan descends into.
///
/// A container opened beyond it ends the scan, as malformed input does: the values
/// already found are kept and the document is reported not well-formed. Real
/// manifests nest a handful of levels; the bound exists so that crafted input — a
/// pull request's `package.json` of fifty thousand `[` — cannot exhaust the stack.
const MAX_DEPTH: usize = 256;

/// A string value found in a JSON(C) document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonStringValue {
    /// The path of object keys (and array indices) leading to this value.
    pub path: Vec<String>,
    /// The (unescaped) string content.
    pub value: String,
    /// Byte offset *into the source document* of the first content byte (just after
    /// the opening quote). Always a character boundary of the source.
    ///
    /// This and [`content_end`](Self::content_end) index the raw text, escapes and
    /// all, never [`value`](Self::value). An offset found by searching `value` lands
    /// on the same source byte only when [`escaped`](Self::escaped) is `false`.
    pub content_start: usize,
    /// Byte offset *into the source document* just past the last content byte (the
    /// closing quote). Always a character boundary of the source, so
    /// `&src[content_start..content_end]` is the raw, still-escaped content.
    pub content_end: usize,
    /// Whether the raw text carried backslash escapes, so [`value`](Self::value) is
    /// shorter than — and not byte-aligned with — the `content_start..content_end`
    /// span.
    ///
    /// Callers map offsets found in `value` back onto the source span. That mapping is
    /// only valid when the two agree byte for byte, so an escaped string must not be
    /// rewritten in place; the flag is what lets a caller decline rather than splice at
    /// an offset that has drifted.
    pub escaped: bool,
}

/// A whole-document scan: the string values found, and whether the document was
/// structurally sound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedJson {
    /// Every string value found, in document order.
    pub values: Vec<JsonStringValue>,
    /// Whether the document parsed to its end with nothing unexpected. `false`
    /// means [`values`](Self::values) is a *prefix* of the document's strings,
    /// which is a different thing from the document's strings.
    pub well_formed: bool,
}

/// Scan JSON or JSONC `src`, returning every string value with its path, in
/// document order. Malformed input yields whatever was scanned up to the error.
///
/// A caller that cannot tell a short list from a complete one — because the file
/// *is* the list rather than an annotation on one — wants [`scan_document`]
/// instead, which says whether the scan reached the end.
#[must_use]
pub fn scan_strings(src: &str) -> Vec<JsonStringValue> {
    scan_document(src).values
}

/// Scan JSON or JSONC `src`, reporting both the string values and whether the
/// document was well-formed.
///
/// Well-formedness is judged structurally: every object and array closed, every
/// string terminated, every key followed by a `:`, every bare scalar a real JSON
/// literal, and nothing left over after the top-level value. It is deliberately
/// not a validator — duplicate keys, JSONC comments, and lone surrogates all
/// pass — it answers only "did the scan see the whole document".
#[must_use]
pub fn scan_document(src: &str) -> ScannedJson {
    let mut scanner = Scanner {
        bytes: src.as_bytes(),
        src,
        i: 0,
        out: Vec::new(),
        well_formed: true,
        path: Vec::new(),
        depth: 0,
    };
    scanner.skip_trivia();
    scanner.parse_value();
    scanner.skip_trivia();
    // Anything after the top-level value belongs to no value at all.
    if scanner.i < scanner.bytes.len() {
        scanner.well_formed = false;
    }
    ScannedJson {
        values: scanner.out,
        well_formed: scanner.well_formed,
    }
}

/// One parsed string: its unescaped content, its raw span, and whether the two differ.
struct ParsedString {
    value: String,
    start: usize,
    end: usize,
    escaped: bool,
}

struct Scanner<'a> {
    bytes: &'a [u8],
    src: &'a str,
    i: usize,
    out: Vec<JsonStringValue>,
    /// Cleared the moment the document departs from JSON's grammar. Never
    /// consulted by the scan itself, which always keeps going.
    well_formed: bool,
    /// The path to the value at the cursor: a key or index is pushed on entering
    /// a member and popped on leaving it, so descending costs no copy of the path.
    path: Vec<String>,
    /// How many containers enclose the cursor, bounded by [`MAX_DEPTH`].
    depth: usize,
}

impl Scanner<'_> {
    /// The bytes from the cursor on, or empty once the cursor has passed the end.
    ///
    /// The cursor is advanced past a delimiter by several callers, so it can sit one
    /// beyond the input; slicing `bytes[i..]` directly panics there.
    fn rest(&self) -> &[u8] {
        self.bytes.get(self.i..).unwrap_or(&[])
    }

    /// Skip whitespace and `//` line / `/* */` block comments.
    fn skip_trivia(&mut self) {
        loop {
            while self.i < self.bytes.len() && self.bytes[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
            if self.rest().starts_with(b"//") {
                self.i += 2;
                while self.i < self.bytes.len() && self.bytes[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.rest().starts_with(b"/*") {
                self.i += 2;
                while self.i < self.bytes.len() && !self.rest().starts_with(b"*/") {
                    self.i += 1;
                }
                self.i = (self.i + 2).min(self.bytes.len());
            } else {
                break;
            }
        }
    }

    /// Parse a value (object, array, string, or scalar) at the cursor, recording
    /// any string values reachable under the current path.
    fn parse_value(&mut self) {
        match self.bytes.get(self.i) {
            Some(b'{' | b'[') if self.depth >= MAX_DEPTH => self.stop(),
            Some(b'{') => {
                self.depth += 1;
                self.parse_object();
                self.depth -= 1;
            }
            Some(b'[') => {
                self.depth += 1;
                self.parse_array();
                self.depth -= 1;
            }
            Some(b'"') => {
                if let Some(s) = self.parse_string() {
                    self.out.push(JsonStringValue {
                        path: self.path.clone(),
                        value: s.value,
                        content_start: s.start,
                        content_end: s.end,
                        escaped: s.escaped,
                    });
                } else {
                    self.well_formed = false;
                }
            }
            // Nothing at all where a value belongs: the document ended early.
            None => self.well_formed = false,
            _ => self.skip_scalar(),
        }
    }

    /// End the scan where it stands: the document is not well-formed, and every
    /// enclosing frame finds the input exhausted and returns, so the values already
    /// recorded are the scan's result.
    fn stop(&mut self) {
        self.well_formed = false;
        self.i = self.bytes.len();
    }

    fn parse_object(&mut self) {
        self.i += 1; // consume '{'
        loop {
            self.skip_trivia();
            match self.bytes.get(self.i) {
                Some(b'}') => {
                    self.i += 1;
                    return;
                }
                // End of input: stop *without* advancing. Stepping past the end here is
                // what left the cursor at `len + 1`, so the enclosing container's next
                // `skip_trivia` sliced out of range. The object is truncated.
                None => {
                    self.well_formed = false;
                    return;
                }
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                Some(b'"') => {}
                // A stray `]` closes the array we are nested in, not this object; leave
                // it for that frame rather than consuming it.
                Some(b']') => {
                    self.well_formed = false;
                    return;
                }
                _ => {
                    // Unexpected; skip it rather than looping forever.
                    self.well_formed = false;
                    self.i += 1;
                    continue;
                }
            }
            let before = self.i;
            let Some(key) = self.parse_string() else {
                self.well_formed = false;
                return;
            };
            self.skip_trivia();
            if self.bytes.get(self.i) != Some(&b':') {
                self.well_formed = false;
                // Guarantee progress even if `parse_string` consumed nothing.
                if self.i == before {
                    self.i += 1;
                }
                continue;
            }
            self.i += 1; // consume ':'
            self.skip_trivia();
            self.path.push(key.value);
            self.parse_value();
            self.path.pop();
        }
    }

    fn parse_array(&mut self) {
        self.i += 1; // consume '['
        let mut index = 0usize;
        loop {
            self.skip_trivia();
            match self.bytes.get(self.i) {
                Some(b']') => {
                    self.i += 1;
                    return;
                }
                // End of input before the closing bracket: the array is truncated.
                None => {
                    self.well_formed = false;
                    return;
                }
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                // A stray `}` closes the object we are nested in. `parse_value` would
                // route it to `skip_scalar`, which breaks on `}` without advancing —
                // an infinite loop. Hand it back to the enclosing frame instead.
                Some(b'}') => {
                    self.well_formed = false;
                    return;
                }
                _ => {}
            }
            self.path.push(index.to_string());
            let before = self.i;
            self.parse_value();
            self.path.pop();
            // Nothing below is allowed to stall: a scalar that begins with a byte
            // `skip_scalar` treats as a terminator would otherwise spin here forever.
            if self.i == before {
                self.i += 1;
            }
            index += 1;
        }
    }

    /// Parse a string at the cursor (which must be on the opening quote), leaving the
    /// cursor just past the closing quote.
    fn parse_string(&mut self) -> Option<ParsedString> {
        debug_assert_eq!(self.bytes.get(self.i), Some(&b'"'));
        let content_start = self.i + 1;
        let mut j = content_start;
        let mut escaped = false;
        while j < self.bytes.len() {
            match self.bytes[j] {
                b'\\' => {
                    escaped = true;
                    // A trailing backslash, or one before a multi-byte character, must
                    // not carry `j` past the end or onto a continuation byte — the
                    // `src[..j]` slice below would panic on either.
                    j += 2;
                    while j < self.bytes.len() && !self.src.is_char_boundary(j) {
                        j += 1;
                    }
                }
                b'"' => {
                    let raw = self.src.get(content_start..j)?;
                    let value = if escaped {
                        unescape(raw)
                    } else {
                        raw.to_string()
                    };
                    self.i = j + 1;
                    return Some(ParsedString {
                        value,
                        start: content_start,
                        end: j,
                        escaped,
                    });
                }
                _ => j += 1,
            }
        }
        self.i = self.bytes.len();
        None
    }

    /// Skip a non-string scalar (`number`, `true`, `false`, `null`).
    fn skip_scalar(&mut self) {
        let start = self.i;
        while self.i < self.bytes.len() {
            match self.bytes[self.i] {
                b',' | b'}' | b']' => break,
                c if c.is_ascii_whitespace() => break,
                _ => self.i += 1,
            }
        }
        // An empty token is a delimiter where a value belongs. The cursor stays on
        // it, for the enclosing frame to consume, but the document is not JSON.
        if !is_json_literal(&self.bytes[start..self.i]) {
            self.well_formed = false;
        }
    }
}

/// Whether `token` is one of JSON's bare literals or a number.
///
/// Only [`ScannedJson::well_formed`] reads this; the scan itself skips the token
/// either way.
fn is_json_literal(token: &[u8]) -> bool {
    matches!(token, b"true" | b"false" | b"null")
        || std::str::from_utf8(token).is_ok_and(|text| text.parse::<f64>().is_ok())
}

/// Unescape a JSON string body.
///
/// `\uXXXX` is decoded, including surrogate pairs, because npm and Deno both emit
/// escaped scoped names (`@scope/pkg`) and a mangled key silently fails to match
/// the dependency it names.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => match take_hex4(&mut chars) {
                // A high surrogate is only meaningful paired with the low surrogate
                // that follows it; either half alone is not a character.
                Some(hi @ 0xD800..=0xDBFF) => match take_low_surrogate(&mut chars) {
                    Some(lo) => {
                        let combined =
                            0x1_0000 + ((u32::from(hi) - 0xD800) << 10) + (u32::from(lo) - 0xDC00);
                        out.push(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                    }
                    None => out.push('\u{FFFD}'),
                },
                Some(unit) => out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}')),
                None => out.push('\u{FFFD}'),
            },
            Some(other) => out.push(other), // \" \\ \/ and the rest
            None => {}
        }
    }
    out
}

/// Read exactly four hex digits as a UTF-16 code unit, or `None` if they are not there.
fn take_hex4(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u16> {
    let mut unit: u16 = 0;
    for _ in 0..4 {
        let digit = chars.peek().copied()?.to_digit(16)?;
        chars.next();
        unit = unit * 16 + u16::try_from(digit).ok()?;
    }
    Some(unit)
}

/// Read a following `\uXXXX` escape that is a low surrogate, completing a pair.
///
/// Anything else — no escape, a malformed one, or a well-formed `\uXXXX` that is not
/// a low surrogate — is left unconsumed, so the caller emits U+FFFD for the lone high
/// surrogate and the next escape is decoded on its own. Consuming it here dropped a
/// valid character from the decoded value.
fn take_low_surrogate(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u16> {
    if chars.peek() != Some(&'\\') {
        return None;
    }
    let mut lookahead = chars.clone();
    lookahead.next();
    if lookahead.peek() != Some(&'u') {
        return None;
    }
    lookahead.next();
    let unit = take_hex4(&mut lookahead)?;
    if !(0xDC00..=0xDFFF).contains(&unit) {
        return None;
    }
    *chars = lookahead;
    Some(unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(values: &[JsonStringValue]) -> Vec<(Vec<&str>, &str)> {
        values
            .iter()
            .map(|v| {
                (
                    v.path.iter().map(String::as_str).collect(),
                    v.value.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn scans_nested_string_values_with_paths() {
        let src = r#"{
            "name": "demo",
            "dependencies": { "react": "^18.0.0" },
            "scopes": { "https://x/": { "@std/a": "jsr:@std/a@1" } }
        }"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(got.contains(&(vec!["name"], "demo")));
        assert!(got.contains(&(vec!["dependencies", "react"], "^18.0.0")));
        assert!(got.contains(&(vec!["scopes", "https://x/", "@std/a"], "jsr:@std/a@1")));
    }

    #[test]
    fn content_span_slices_back_to_value() {
        let src = r#"{ "dependencies": { "react": "^18.0.0" } }"#;
        let v = scan_strings(src)
            .into_iter()
            .find(|v| v.path == ["dependencies", "react"])
            .unwrap();
        assert_eq!(&src[v.content_start..v.content_end], "^18.0.0");
    }

    #[test]
    fn skips_line_and_block_comments() {
        let src = r#"{
            // a line comment
            "imports": {
                /* block */ "lodash": "npm:lodash@^4"
            }
        }"#;
        let values = scan_strings(src);
        assert!(paths(&values).contains(&(vec!["imports", "lodash"], "npm:lodash@^4")));
    }

    /// Truncated input used to carry the cursor to `len + 1`, and the next
    /// `skip_trivia` sliced `bytes[len + 1..]` — a panic on a half-written manifest.
    #[test]
    fn truncated_containers_terminate_without_panicking() {
        for src in [
            "{",
            "[",
            "[{",
            r#"{"a":{"#,
            r#"{"dependencies":{"#,
            r#"{"dependencies":{"react""#,
            r#"{"dependencies":{"react":"#,
            r#"{"a":["#,
            r#"{"a":"unterminated"#,
            "",
        ] {
            let _ = scan_strings(src);
        }
    }

    /// A stray closer inside the other kind of container reached `skip_scalar`, which
    /// breaks on `}` and `]` *without* advancing — the scan spun forever.
    #[test]
    fn stray_closers_terminate() {
        for src in ["[}", "{]", r#"{"a":[}]}"#, r#"[}{]"#, "[[}]]", r#"{"a":}"#] {
            let _ = scan_strings(src);
        }
    }

    /// Everything scanned *before* a malformation is still returned. The scanner
    /// promises to stop at the error, not to resynchronise past it, so this pins the
    /// half it does guarantee — truncation is the common case and the prefix is what a
    /// half-written manifest has to offer.
    #[test]
    fn values_before_a_malformation_are_kept() {
        let src = r#"{"dependencies": {"react": "^18.0.0"}, "bad": [}"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(
            got.contains(&(vec!["dependencies", "react"], "^18.0.0")),
            "got {got:?}"
        );
    }

    #[test]
    fn decodes_unicode_escapes_including_surrogate_pairs() {
        // `@scope/pkg` is how a scoped name arrives from generated manifests; the
        // old unescape dropped the backslash and yielded `u0040scope/pkg`.
        //
        // The escapes are assembled at run time from a backslash code point, so the
        // test source cannot be decoded ahead of the scanner by anything that edits
        // or renders it: what reaches `scan_strings` is the six ASCII bytes of each
        // escape, and the assertions hold only if the scanner decodes them.
        let esc = |hex: &str| format!("{}u{hex}", char::from(92u8));
        let src = format!(
            r#"{{"dependencies":{{"{}scope\/pkg":"^1.0.0"}}}}"#,
            esc("0040")
        );
        assert!(!src.contains('@'), "the `@` must reach the scanner escaped");
        let values = scan_strings(&src);
        let got = paths(&values);
        assert!(
            got.contains(&(vec!["dependencies", "@scope/pkg"], "^1.0.0")),
            "got {got:?}"
        );

        // An escaped surrogate pair is one character, not two replacement chars. The
        // source holds only ASCII escapes; the emoji exists only once they combine.
        let src = format!(r#"{{"a":"{}{}"}}"#, esc("D83D"), esc("DE00"));
        assert!(src.is_ascii());
        let v = scan_strings(&src);
        assert_eq!(v[0].value, "\u{1F600}");

        // A BMP escape in a value decodes too.
        let src = format!(r#"{{"a":"caf{}"}}"#, esc("00e9"));
        assert!(src.is_ascii());
        let v = scan_strings(&src);
        assert_eq!(v[0].value, "caf\u{e9}");

        // A lone high surrogate has no completion and must not panic.
        let src = r#"{"a":"\uD83D"}"#;
        let v = scan_strings(src);
        assert_eq!(v[0].value, "\u{FFFD}");

        // A truncated escape is not four hex digits.
        let src = r#"{"a":"\u00"}"#;
        let v = scan_strings(src);
        assert_eq!(v[0].value, "\u{FFFD}");
    }

    /// A lone high surrogate becomes U+FFFD, and the escape after it is decoded on its
    /// own rather than swallowed as the pair's would-be low half.
    #[test]
    fn a_lone_high_surrogate_does_not_eat_the_next_escape() {
        let esc = |hex: &str| format!("{}u{hex}", char::from(92u8));
        // A BMP escape after the lone surrogate survives.
        let src = format!(r#"{{"a":"{}{}b"}}"#, esc("D83D"), esc("0041"));
        assert_eq!(scan_strings(&src)[0].value, "\u{FFFD}Ab");
        // So does a whole surrogate pair: the second high surrogate starts the pair.
        let src = format!(r#"{{"a":"{}{}{}"}}"#, esc("D83D"), esc("D83D"), esc("DE00"));
        assert_eq!(scan_strings(&src)[0].value, "\u{FFFD}\u{1F600}");
        // A lone low surrogate is no character either, and the pair after it holds.
        let src = format!(r#"{{"a":"{}{}{}"}}"#, esc("DE00"), esc("D83D"), esc("DE00"));
        assert_eq!(scan_strings(&src)[0].value, "\u{FFFD}\u{1F600}");
    }

    /// The span is a *source* span: for an escaped value it slices the raw escapes,
    /// not the decoded text, and it stays on character boundaries either way.
    #[test]
    fn an_escaped_values_span_is_its_raw_source_text() {
        let src = r#"{"a":"é\/x"}"#;
        let v = &scan_strings(src)[0];
        assert_eq!(v.value, "é/x");
        assert_eq!(&src[v.content_start..v.content_end], r"é\/x");
    }

    /// An escaped value's decoded offsets do not line up with its source span, so the
    /// scanner flags it and the parsers withhold the rewrite span.
    #[test]
    fn escapes_are_flagged_and_plain_values_are_not() {
        let plain = scan_strings(r#"{"a":"^1.0.0"}"#);
        assert!(!plain[0].escaped);
        let escaped = scan_strings(r#"{"a":"^1.0.0\/x"}"#);
        assert!(escaped[0].escaped);
    }

    /// Every span the scanner reports must slice back out of the source. A backslash
    /// before a multi-byte character used to land the cursor mid-UTF-8.
    #[test]
    fn spans_stay_on_character_boundaries_with_multibyte_content() {
        for src in [
            r#"{"名前":"^1.0.0","déps":{"café":"~2.0"}}"#,
            r#"{"a":"café","b":"naïve"}"#,
            r#"{"a":"\é"}"#,
            r#"{"a":"x\"#,
        ] {
            for v in scan_strings(src) {
                assert!(
                    src.get(v.content_start..v.content_end).is_some(),
                    "span {}..{} does not slice {src:?}",
                    v.content_start,
                    v.content_end
                );
            }
        }
    }

    /// Non-ASCII keys shift every later byte offset; the recorded span must follow the
    /// bytes, not the characters.
    #[test]
    fn spans_are_byte_offsets_after_multibyte_keys() {
        let src = r#"{"café": { "react": "^18.0.0" } }"#;
        let v = scan_strings(src)
            .into_iter()
            .find(|v| v.path == ["café", "react"])
            .unwrap();
        assert_eq!(&src[v.content_start..v.content_end], "^18.0.0");
    }

    /// A truncated document used to walk the cursor off the end of the buffer and
    /// panic on the next slice — a crash on `dependable list`, from nothing worse
    /// than a half-written file. Every prefix of a real document must scan.
    #[test]
    fn every_prefix_of_a_document_scans_without_panicking() {
        let src = r#"{
            "pins": [
                { "identity": "swift-nio", "location": "https://github.com/apple/swift-nio.git",
                  "state": { "version": "2.65.0" } }
            ],
            "version": 2
        }"#;
        for cut in 0..=src.len() {
            let _ = scan_document(&src[..cut]);
        }
    }

    /// A closing delimiter where a value belongs used to hand the same byte back to
    /// the enclosing loop forever. Terminating matters more than what it returns.
    #[test]
    fn a_delimiter_where_a_value_belongs_terminates() {
        for src in ["[ } ]", "{ \"a\": }", "{ \"a\": ] }", "[[[", "{{{"] {
            let scanned = scan_document(src);
            assert!(!scanned.well_formed, "{src}");
        }
    }

    /// The signal a reader of a file that *is* a dependency list depends on: a
    /// document that did not scan to its end must not pass as one that did.
    #[test]
    fn well_formedness_separates_a_whole_document_from_a_prefix() {
        let src = r#"{ "a": [1, 2, {"b": "c"}], "d": null, "e": true }"#;
        assert!(scan_document(src).well_formed);
        assert!(scan_document(&src[..src.len() - 1]).well_formed.eq(&false));

        // JSONC still counts as well-formed: comments are this scanner's business.
        assert!(scan_document("{ /* hi */ \"a\": 1 } // done").well_formed);

        // Trailing content after the top-level value belongs to no value at all.
        assert!(!scan_document("not json at all {{{").well_formed);
        assert!(!scan_document("{} garbage").well_formed);
        assert!(!scan_document("").well_formed);

        // An unterminated string, and a key with no value.
        assert!(!scan_document(r#"{ "a": "unterminated "#).well_formed);
        assert!(!scan_document(r#"{ "a" 1 }"#).well_formed);

        // A bare token that is no JSON literal.
        assert!(!scan_document(r#"{ "a": nope }"#).well_formed);
        assert!(scan_document(r#"{ "a": -1.5e3 }"#).well_formed);
    }

    /// `depth` arrays nested inside one another, holding a single string.
    fn nested_arrays(depth: usize) -> String {
        format!("{}\"deep\"{}", "[".repeat(depth), "]".repeat(depth))
    }

    /// Nesting up to the bound scans like any other document: the innermost value
    /// is found under its full path, and the document is whole.
    #[test]
    fn nesting_at_the_depth_bound_scans_whole() {
        let scanned = scan_document(&nested_arrays(MAX_DEPTH));
        assert!(scanned.well_formed);
        assert_eq!(scanned.values.len(), 1);
        assert_eq!(scanned.values[0].value, "deep");
        assert_eq!(scanned.values[0].path, vec!["0"; MAX_DEPTH]);

        let objects = format!(
            "{}\"deep\"{}",
            "{\"k\":".repeat(MAX_DEPTH),
            "}".repeat(MAX_DEPTH)
        );
        let scanned = scan_document(&objects);
        assert!(scanned.well_formed);
        assert_eq!(scanned.values[0].path, vec!["k"; MAX_DEPTH]);
    }

    /// One container past the bound stops the scan instead of descending: what came
    /// before is kept, nothing after is invented, and the document is not whole.
    #[test]
    fn nesting_past_the_depth_bound_stops_and_keeps_the_prefix() {
        let scanned = scan_document(&nested_arrays(MAX_DEPTH + 1));
        assert!(!scanned.well_formed);
        assert!(scanned.values.is_empty());

        let src = format!(
            r#"{{"name": "demo", "deep": {}, "after": "unreached"}}"#,
            nested_arrays(MAX_DEPTH)
        );
        let scanned = scan_document(&src);
        assert!(!scanned.well_formed);
        let got = paths(&scanned.values);
        assert_eq!(got, vec![(vec!["name"], "demo")]);
    }

    /// Unbounded recursion overflowed the stack here, and an overflow aborts the
    /// process rather than panicking. The scan must return.
    #[test]
    fn hostile_nesting_returns_rather_than_overflowing_the_stack() {
        for src in [
            "[".repeat(100_000),
            "{\"a\":".repeat(100_000),
            nested_arrays(100_000),
        ] {
            let scanned = scan_document(&src);
            assert!(!scanned.well_formed);
            assert!(scanned.values.is_empty());
        }
    }

    #[test]
    fn handles_arrays_with_indices() {
        let src = r#"{ "project": { "dependencies": ["flask>=2.0", "requests"] } }"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(got.contains(&(vec!["project", "dependencies", "0"], "flask>=2.0")));
        assert!(got.contains(&(vec!["project", "dependencies", "1"], "requests")));
    }
}
