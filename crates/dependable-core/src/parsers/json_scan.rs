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

struct Scanner<'a> {
    bytes: &'a [u8],
    src: &'a str,
    i: usize,
    out: Vec<JsonStringValue>,
}

impl Scanner<'_> {
    /// Skip whitespace and `//` line / `/* */` block comments.
    fn skip_trivia(&mut self) {
        loop {
            while self.i < self.bytes.len() && self.bytes[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
            if self.bytes[self.i..].starts_with(b"//") {
                self.i += 2;
                while self.i < self.bytes.len() && self.bytes[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.bytes[self.i..].starts_with(b"/*") {
                self.i += 2;
                while self.i < self.bytes.len() && !self.bytes[self.i..].starts_with(b"*/") {
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
                Some(b'}') | None => {
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
                    self.i += 1;
                    continue;
                }
            }
            let Some((key, ..)) = self.parse_string() else {
                return;
            };
            self.skip_trivia();
            if self.bytes.get(self.i) != Some(&b':') {
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
                Some(b']') | None => {
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
        while self.i < self.bytes.len() {
            match self.bytes[self.i] {
                b',' | b'}' | b']' => break,
                c if c.is_ascii_whitespace() => break,
                _ => self.i += 1,
            }
        }
    }
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

    #[test]
    fn handles_arrays_with_indices() {
        let src = r#"{ "project": { "dependencies": ["flask>=2.0", "requests"] } }"#;
        let values = scan_strings(src);
        let got = paths(&values);
        assert!(got.contains(&(vec!["project", "dependencies", "0"], "flask>=2.0")));
        assert!(got.contains(&(vec!["project", "dependencies", "1"], "requests")));
    }
}
