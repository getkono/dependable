A monorepo shape for `--manifest-glob` tests: two services one level down, one
manifest a level deeper inside a service, and a tool outside `services/`.
Parsed as data, never built (the root `Cargo.toml` excludes `tests/fixtures`).
