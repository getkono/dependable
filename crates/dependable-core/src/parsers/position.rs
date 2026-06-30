//! Shared byte-offset → `(line, column)` helpers for manifest parsers.
//!
//! Parsers record the exact byte range of each version value so the CLI can
//! rewrite it in place during `--fix`. These helpers map a global byte offset
//! (e.g. from a `toml_edit` span, or a manual line scan) into the zero-indexed
//! `(line, column)` coordinates stored on [`crate::item::Item`], where `column`
//! is a byte offset within the line.

/// The byte offset at which each line of `src` begins (line 0 starts at byte 0).
#[must_use]
pub fn line_starts(src: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in src.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Convert a global byte `offset` into a zero-indexed `(line, column)` pair.
///
/// `starts` is the output of [`line_starts`] for the same source. `column` is the
/// byte offset of `offset` within its line.
#[must_use]
pub fn offset_to_line_col(starts: &[usize], offset: usize) -> (usize, usize) {
    let line = starts
        .partition_point(|&start| start <= offset)
        .saturating_sub(1);
    (line, offset - starts[line])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_offsets_across_lines() {
        let src = "ab\ncde\nf";
        let starts = line_starts(src);
        assert_eq!(starts, vec![0, 3, 7]);
        assert_eq!(offset_to_line_col(&starts, 0), (0, 0));
        assert_eq!(offset_to_line_col(&starts, 1), (0, 1));
        assert_eq!(offset_to_line_col(&starts, 3), (1, 0));
        assert_eq!(offset_to_line_col(&starts, 5), (1, 2));
        assert_eq!(offset_to_line_col(&starts, 7), (2, 0));
    }
}
