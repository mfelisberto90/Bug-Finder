# Contributing to Bug-Finder

Thank you for contributing. Bug-Finder v2.0 targets a single-binary pure-Rust footprint (`< 15 MB VmRSS`, zero Python dependencies) with strict end-to-end security invariants.

## Prerequisites

- **Rust** `1.89+` (with `rustfmt` and `clippy` components)
- **Node.js** `22+` and `npm` (for building the embedded TypeScript SPA in `ui/`)
- Optional: **Docker** (for running PostgreSQL 17 `FORCE RLS` live isolation tests)

## Local Development Workflow

1. **Build the embedded SPA first** (required by `build.rs`):
   ```bash
   cd ui && npm ci && npm run build && cd ..
   ```
2. **Run native Rust security linter (`< 3 ms`), formatter, Clippy, and tests**:
   ```bash
   cargo fmt --all -- --check
   cargo run -- lint --dir .
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-features
   ```
3. **Run live PostgreSQL 17 `FORCE RLS` isolation tests** (requires Postgres 17 with admin + `NOBYPASSRLS` roles):
   ```bash
   cargo test --test integration_tests postgres_rls_live_isolation_test -- --ignored --nocapture
   ```

## Coding & Security Rules

- Preserve `ENABLE` + `FORCE ROW LEVEL SECURITY` policies and `audit_logs` immutability triggers in [migrations/postgres/001_init_rls.sql](migrations/postgres/001_init_rls.sql) and [migrations/sqlite/001_init.sql](migrations/sqlite/001_init.sql); every change must pass `bugfinder lint`.
- Never use `rand::thread_rng()` or `rand::random()` inside `src/`; always use `rand::rngs::OsRng`.
- Keep HTTP header parsers multi-header compliant (`headers.get_all(...)` for `Cookie` and `X-Forwarded-For`).
- Keep the TypeScript frontend dependency-free at runtime and free of inline `style="..."` or inline `<script>` tags so CSP `style-src-attr 'none'` stays unbroken.
- Never introduce `.py` scripts, `.env` secrets, or private domains; use RFC 2606 domains (`example.com`, `acme.example`) only.
- Keep commits atomic following [Conventional Commits](https://www.conventionalcommits.org/).
