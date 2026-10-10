A polyglot monorepo shape: two sibling services under `services/`, one Rust and
one Go, so that `--ecosystem` and `--manifest-glob` can be exercised against the
same tree — an ecosystem filter needs a manifest of another ecosystem to remove,
and `sample-monorepo` is Rust throughout.

Parsed as data, never built (the root `Cargo.toml` excludes `tests/fixtures`).
