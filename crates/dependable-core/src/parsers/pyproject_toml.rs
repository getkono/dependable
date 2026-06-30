//! Parser for Python `pyproject.toml` (and pixi's `pyproject.toml`/`pixi.toml`).
//!
//! Handles Poetry tables (`[tool.poetry.dependencies]`, groups, legacy
//! dev-dependencies), PEP 621 `[project.dependencies]` / optional-dependencies
//! arrays, PEP 735 `[dependency-groups]`, and pixi's top-level `[dependencies]`.
//! `python`/`requires-python` and `{path=…}`/`{git=…}`/`{url=…}` deps are skipped.

use std::ops::Range;

use toml_edit::{Array, ImDocument, Item as TomlItem, TableLike};

use super::Parser;
use super::position::{line_starts, offset_to_line_col};
use super::requirements_txt::parse_pep508_spec;
use crate::error::ParseError;
use crate::item::{Item, PackageSource};
use crate::manifest::{ManifestKind, ParsedManifest};

/// Parses `pyproject.toml` / `pixi.toml`.
pub struct PyprojectTomlParser;

impl Parser for PyprojectTomlParser {
    fn parse(&self, content: &str) -> Result<ParsedManifest, ParseError> {
        let doc = ImDocument::parse(content.to_owned())?;
        let root = doc.as_table();
        let starts = line_starts(content);
        let mut items = Vec::new();

        // Poetry: [tool.poetry.dependencies], group tables, legacy dev-dependencies.
        if let Some(t) =
            nav(root, &["tool", "poetry", "dependencies"]).and_then(TomlItem::as_table_like)
        {
            collect_table_deps(t, &starts, &mut items);
        }
        if let Some(groups) =
            nav(root, &["tool", "poetry", "group"]).and_then(TomlItem::as_table_like)
        {
            for (_name, group) in groups.iter() {
                if let Some(deps) = group
                    .as_table_like()
                    .and_then(|g| g.get("dependencies"))
                    .and_then(TomlItem::as_table_like)
                {
                    collect_table_deps(deps, &starts, &mut items);
                }
            }
        }
        if let Some(t) =
            nav(root, &["tool", "poetry", "dev-dependencies"]).and_then(TomlItem::as_table_like)
        {
            collect_table_deps(t, &starts, &mut items);
        }

        // PEP 621: [project.dependencies] array + [project.optional-dependencies].
        if let Some(arr) = nav(root, &["project", "dependencies"]).and_then(TomlItem::as_array) {
            collect_pep508_array(arr, &starts, &mut items);
        }
        if let Some(t) =
            nav(root, &["project", "optional-dependencies"]).and_then(TomlItem::as_table_like)
        {
            for (_group, value) in t.iter() {
                if let Some(arr) = value.as_array() {
                    collect_pep508_array(arr, &starts, &mut items);
                }
            }
        }

        // PEP 735: [dependency-groups].
        if let Some(t) = root
            .get("dependency-groups")
            .and_then(TomlItem::as_table_like)
        {
            for (_group, value) in t.iter() {
                if let Some(arr) = value.as_array() {
                    collect_pep508_array(arr, &starts, &mut items);
                }
            }
        }

        // pixi: top-level [dependencies] (name = "version-spec").
        if let Some(t) = root.get("dependencies").and_then(TomlItem::as_table_like) {
            collect_table_deps(t, &starts, &mut items);
        }

        Ok(ParsedManifest {
            kind: ManifestKind::PyprojectToml,
            items,
            alternate_registries: Vec::new(),
        })
    }
}

/// Navigate nested tables along `path`, returning the final item.
fn nav<'a>(root: &'a dyn TableLike, path: &[&str]) -> Option<&'a TomlItem> {
    let mut item = root.get(path[0])?;
    for key in &path[1..] {
        item = item.as_table_like()?.get(key)?;
    }
    Some(item)
}

/// Collect `name = "spec"` / `name = { version = "spec", … }` style dependency
/// tables (Poetry, pixi), skipping `python` and path/git/url sources.
fn collect_table_deps(table: &dyn TableLike, starts: &[usize], items: &mut Vec<Item>) {
    for (name, item) in table.iter() {
        if name == "python" {
            continue;
        }
        if let Some(parsed) = parse_table_dep(name, item, starts) {
            items.push(parsed);
        }
    }
}

fn parse_table_dep(name: &str, item: &TomlItem, starts: &[usize]) -> Option<Item> {
    // String form: `requests = "^2.0"`.
    if let Some(value) = item.as_value()
        && let Some(version) = value.as_str()
    {
        return Some(make_item(
            name,
            version,
            value.span()?,
            PackageSource::Registry,
            starts,
        ));
    }
    // Inline table / `[tool.poetry.dependencies.x]`.
    if let Some(table) = item.as_table_like() {
        if table.contains_key("path") || table.contains_key("url") {
            return Some(skip_item(name, PackageSource::Local));
        }
        if table.contains_key("git") {
            return Some(skip_item(name, PackageSource::Git));
        }
        if let Some(version_item) = table.get("version")
            && let Some(version) = version_item.as_str()
        {
            return Some(make_item(
                name,
                version,
                version_item.span()?,
                PackageSource::Registry,
                starts,
            ));
        }
    }
    None
}

/// Collect a PEP 508 string array (`["flask>=2.0", "requests"]`).
fn collect_pep508_array(array: &Array, starts: &[usize], items: &mut Vec<Item>) {
    for value in array.iter() {
        if let Some(spec) = value.as_str()
            && let Some(span) = value.span()
            && let Some((name, constraint, version_offset)) = parse_pep508_spec(spec)
        {
            let global_start = span.start + 1 + version_offset; // +1 skips the opening quote
            let (line, col_start) = offset_to_line_col(starts, global_start);
            items.push(Item {
                name,
                version_constraint: constraint.to_string(),
                source: PackageSource::Registry,
                version_line: line,
                version_col_start: col_start,
                version_col_end: col_start + constraint.len(),
                registry: None,
                locked_version: None,
            });
        }
    }
}

/// Build an item from a quoted version value's span (quotes excluded).
fn make_item(
    name: &str,
    version: &str,
    span: Range<usize>,
    source: PackageSource,
    starts: &[usize],
) -> Item {
    let inner_start = span.start + 1;
    let inner_end = span.end.saturating_sub(1);
    let (line, col_start) = offset_to_line_col(starts, inner_start);
    Item {
        name: name.to_owned(),
        version_constraint: version.to_owned(),
        source,
        version_line: line,
        version_col_start: col_start,
        version_col_end: col_start + inner_end.saturating_sub(inner_start),
        registry: None,
        locked_version: None,
    }
}

fn skip_item(name: &str, source: PackageSource) -> Item {
    Item {
        name: name.to_owned(),
        version_constraint: String::new(),
        source,
        version_line: 0,
        version_col_start: 0,
        version_col_end: 0,
        registry: None,
        locked_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> ParsedManifest {
        PyprojectTomlParser.parse(content).unwrap()
    }

    fn find<'a>(m: &'a ParsedManifest, name: &str) -> &'a Item {
        m.items
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn sliced<'a>(content: &'a str, item: &Item) -> &'a str {
        let line = content.lines().nth(item.version_line).unwrap();
        &line[item.version_col_start..item.version_col_end]
    }

    #[test]
    fn parses_poetry_dependencies() {
        let content = "[tool.poetry.dependencies]\npython = \"^3.10\"\nrequests = \"^2.28\"\nrich = { version = \">=13.0\", optional = true }\nlocal = { path = \"../local\" }\n";
        let m = parse(content);
        assert!(m.items.iter().all(|i| i.name != "python"));
        assert_eq!(find(&m, "requests").version_constraint, "^2.28");
        assert_eq!(sliced(content, find(&m, "requests")), "^2.28");
        assert_eq!(find(&m, "rich").version_constraint, ">=13.0");
        assert_eq!(sliced(content, find(&m, "rich")), ">=13.0");
        assert_eq!(find(&m, "local").source, PackageSource::Local);
    }

    #[test]
    fn parses_pep621_project_dependencies() {
        let content = "[project]\nname = \"app\"\ndependencies = [\n  \"flask>=2.0\",\n  \"requests==2.28.1\",\n]\n\n[project.optional-dependencies]\ndev = [\"pytest>=7.0\"]\n";
        let m = parse(content);
        assert_eq!(find(&m, "flask").version_constraint, ">=2.0");
        assert_eq!(sliced(content, find(&m, "flask")), ">=2.0");
        assert_eq!(find(&m, "requests").version_constraint, "==2.28.1");
        assert_eq!(sliced(content, find(&m, "requests")), "==2.28.1");
        assert_eq!(find(&m, "pytest").version_constraint, ">=7.0");
    }

    #[test]
    fn parses_dependency_groups() {
        let content = "[dependency-groups]\ntest = [\"pytest>=7.0\", \"coverage>=6.0\"]\n";
        let m = parse(content);
        assert_eq!(find(&m, "pytest").version_constraint, ">=7.0");
        assert_eq!(sliced(content, find(&m, "coverage")), ">=6.0");
    }
}
