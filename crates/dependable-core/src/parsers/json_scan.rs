//! A small JSON / JSONC scanner that yields every string *value* with its dotted
//! path and the byte span of its content (excluding the surrounding quotes).
//!
//! The JS-family parsers (`package.json`, `deno.json[c]`) need both the structure
//! *and* exact value positions (for in-place `--fix`), and `deno.jsonc` allows
//! comments — neither of which `serde_json` provides. This single pass covers all
//! of it: object keys build the path, array elements use their index, and `//`
//! and `/* */` comments are skipped.

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
    };
    scanner.skip_trivia();
    scanner.parse_value(&[]);
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

struct Scanner<'a> {
    bytes: &'a [u8],
    src: &'a str,
    i: usize,
    out: Vec<JsonStringValue>,
    /// Cleared the moment the document departs from JSON's grammar. Never
    /// consulted by the scan itself, which always keeps going.
    well_formed: bool,
}

impl Scanner<'_> {
    /// The bytes from the cursor on, empty once the cursor has run off the end.
    ///
    /// The cursor is advanced past a delimiter that turned out not to be there —
    /// a truncated document ends mid-object — so it can sit *beyond* the last
    /// byte, and `self.bytes[self.i..]` panics there rather than yielding the
    /// empty slice every caller here means.
    fn rest(&self) -> &[u8] {
        self.bytes.get(self.i..).unwrap_or_default()
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
                if let Some((value, start, end)) = self.parse_string() {
                    self.out.push(JsonStringValue {
                        path: path.to_vec(),
                        value,
                        content_start: start,
                        content_end: end,
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

    fn parse_object(&mut self, path: &[String]) {
        self.i += 1; // consume '{'
        loop {
            self.skip_trivia();
            match self.bytes.get(self.i) {
                Some(b'}') => {
                    self.i += 1;
                    return;
                }
                // End of input before the closing brace: the object is truncated.
                None => {
                    self.well_formed = false;
                    self.i += 1;
                    return;
                }
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                Some(b'"') => {}
                _ => {
                    // Unexpected; bail to avoid looping forever.
                    self.well_formed = false;
                    self.i += 1;
                    continue;
                }
            }
            let Some((key, ..)) = self.parse_string() else {
                self.well_formed = false;
                return;
            };
            self.skip_trivia();
            if self.bytes.get(self.i) != Some(&b':') {
                self.well_formed = false;
                continue;
            }
            self.i += 1; // consume ':'
            self.skip_trivia();
            let mut child = path.to_vec();
            child.push(key);
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
                // End of input before the closing bracket: the array is truncated.
                None => {
                    self.well_formed = false;
                    self.i += 1;
                    return;
                }
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                _ => {}
            }
            let mut child = path.to_vec();
            child.push(index.to_string());
            self.parse_value(&child);
            index += 1;
        }
    }

    /// Parse a string at the cursor (which must be on the opening quote),
    /// returning `(content, content_start, content_end)` and leaving the cursor
    /// just past the closing quote.
    fn parse_string(&mut self) -> Option<(String, usize, usize)> {
        debug_assert_eq!(self.bytes.get(self.i), Some(&b'"'));
        let content_start = self.i + 1;
        let mut j = content_start;
        let mut escaped = false;
        while j < self.bytes.len() {
            match self.bytes[j] {
                b'\\' => {
                    escaped = true;
                    j += 2;
                }
                b'"' => {
                    let raw = &self.src[content_start..j];
                    let value = if escaped {
                        unescape(raw)
                    } else {
                        raw.to_string()
                    };
                    self.i = j + 1;
                    return Some((value, content_start, j));
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
        if self.i == start {
            // A closing delimiter where a value belongs. Consuming it is what
            // keeps the walk finite: the enclosing loop would otherwise hand the
            // same byte back to this function forever.
            self.well_formed = false;
            self.i += 1;
            return;
        }
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

/// Unescape the common JSON string escapes (enough for package names, versions,
/// and URLs).
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other), // \" \\ \/ and the rest
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
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

    #[test]
    fn handles_arrays_with_indices() {
        let src = r#"{ "project": { "dependencies": ["flask>=2.0", "requests"] } }"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(got.contains(&(vec!["project", "dependencies", "0"], "flask>=2.0")));
        assert!(got.contains(&(vec!["project", "dependencies", "1"], "requests")));
    }
}
