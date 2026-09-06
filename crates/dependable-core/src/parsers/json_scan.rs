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

/// A string value found in a JSON(C) document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonStringValue {
    /// The path of object keys (and array indices) leading to this value.
    pub path: Vec<String>,
    /// The (unescaped) string content.
    pub value: String,
    /// Byte offset of the first content byte (just after the opening quote).
    pub content_start: usize,
    /// Byte offset just past the last content byte (the closing quote).
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

/// Scan JSON or JSONC `src`, returning every string value with its path, in
/// document order. Malformed input yields whatever was scanned up to the error.
#[must_use]
pub fn scan_strings(src: &str) -> Vec<JsonStringValue> {
    let mut scanner = Scanner {
        bytes: src.as_bytes(),
        src,
        i: 0,
        out: Vec::new(),
    };
    scanner.skip_trivia();
    scanner.parse_value(&[]);
    scanner.out
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
    /// any string values reachable under `path`.
    fn parse_value(&mut self, path: &[String]) {
        match self.bytes.get(self.i) {
            Some(b'{') => self.parse_object(path),
            Some(b'[') => self.parse_array(path),
            Some(b'"') => {
                if let Some(s) = self.parse_string() {
                    self.out.push(JsonStringValue {
                        path: path.to_vec(),
                        value: s.value,
                        content_start: s.start,
                        content_end: s.end,
                        escaped: s.escaped,
                    });
                }
            }
            _ => self.skip_scalar(),
        }
    }

    fn parse_object(&mut self, path: &[String]) {
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
                // `skip_trivia` sliced out of range.
                None => return,
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                Some(b'"') => {}
                // A stray `]` closes the array we are nested in, not this object; leave
                // it for that frame rather than consuming it.
                Some(b']') => return,
                _ => {
                    // Unexpected; skip it rather than looping forever.
                    self.i += 1;
                    continue;
                }
            }
            let before = self.i;
            let Some(key) = self.parse_string() else {
                return;
            };
            self.skip_trivia();
            if self.bytes.get(self.i) != Some(&b':') {
                // Guarantee progress even if `parse_string` consumed nothing.
                if self.i == before {
                    self.i += 1;
                }
                continue;
            }
            self.i += 1; // consume ':'
            self.skip_trivia();
            let mut child = path.to_vec();
            child.push(key.value);
            self.parse_value(&child);
        }
    }

    fn parse_array(&mut self, path: &[String]) {
        self.i += 1; // consume '['
        let mut index = 0usize;
        loop {
            self.skip_trivia();
            match self.bytes.get(self.i) {
                Some(b']') => {
                    self.i += 1;
                    return;
                }
                None => return,
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                // A stray `}` closes the object we are nested in. `parse_value` would
                // route it to `skip_scalar`, which breaks on `}` without advancing —
                // an infinite loop. Hand it back to the enclosing frame instead.
                Some(b'}') => return,
                _ => {}
            }
            let mut child = path.to_vec();
            child.push(index.to_string());
            let before = self.i;
            self.parse_value(&child);
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
        while self.i < self.bytes.len() {
            match self.bytes[self.i] {
                b',' | b'}' | b']' => break,
                c if c.is_ascii_whitespace() => break,
                _ => self.i += 1,
            }
        }
    }
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
                Some(hi @ 0xD800..=0xDBFF) => {
                    let low = take_surrogate_escape(&mut chars);
                    match low {
                        Some(lo @ 0xDC00..=0xDFFF) => {
                            let combined = 0x1_0000
                                + ((u32::from(hi) - 0xD800) << 10)
                                + (u32::from(lo) - 0xDC00);
                            out.push(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                        }
                        _ => out.push('\u{FFFD}'),
                    }
                }
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

/// Read a following `\uXXXX` escape, used to complete a surrogate pair.
fn take_surrogate_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u16> {
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
        let src = r#"{"dependencies":{"@scope\/pkg":"^1.0.0"}}"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(
            got.contains(&(vec!["dependencies", "@scope/pkg"], "^1.0.0")),
            "got {got:?}"
        );

        // A surrogate pair is one character, not two replacement chars.
        let src = r#"{"a":"😀"}"#;
        let v = scan_strings(src);
        assert_eq!(v[0].value, "\u{1F600}");

        // A lone high surrogate has no completion and must not panic.
        let src = r#"{"a":"\uD83D"}"#;
        let v = scan_strings(src);
        assert_eq!(v[0].value, "\u{FFFD}");

        // A truncated escape is not four hex digits.
        let src = r#"{"a":"\u00"}"#;
        let v = scan_strings(src);
        assert_eq!(v[0].value, "\u{FFFD}");
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

    #[test]
    fn handles_arrays_with_indices() {
        let src = r#"{ "project": { "dependencies": ["flask>=2.0", "requests"] } }"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(got.contains(&(vec!["project", "dependencies", "0"], "flask>=2.0")));
        assert!(got.contains(&(vec!["project", "dependencies", "1"], "requests")));
    }
}
