//! Offline parse of the Go fixture: names, resolved versions, and that recorded
//! offsets slice back to the version token (so `--fix` can rewrite in place).

use std::path::Path;

use dependable_fetch::ManifestKind;
use dependable_fetch::core::parse;

#[test]
fn parses_go_mod_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-go/go.mod");
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed = parse(ManifestKind::GoMod, &content).unwrap();

    let names: Vec<&str> = parsed.items.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"github.com/google/uuid"));
    assert!(names.contains(&"github.com/spf13/cobra"));
    assert!(names.contains(&"golang.org/x/sync"));

    for item in &parsed.items {
        let line = content.lines().nth(item.version_line).unwrap();
        assert_eq!(
            &line[item.version_col_start..item.version_col_end],
            item.version_constraint,
            "offset for {} should slice back to its version",
            item.name
        );
    }
}
