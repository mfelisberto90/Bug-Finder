# Contributing to Bug-Finder

Thank you for contributing! Bug-Finder targets a minimal single-binary footprint (`< 15 MB VmRSS`) with strict enterprise security invariants.

## Prerequisites

- **Rust** `1.89+` (`rustfmt` and `clippy` components installed)
- **Node.js** `22+` and `npm`
- **Python** `3.10+` (for `scripts/security-lint.py`)
- Optional: **Docker** (for running PostgreSQL 17 `FORCE RLS` live isolation tests)

## Local Development Workflow

1. **Build the embedded SPA first** (required by `build.rs`):
   ```bash
   cd ui && npm ci && npm run build && cd ..
   ```
2. **Run linters and unit/integration tests**:
   ```bash
   python3 scripts/security-lint.py
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-features
   ```
3. **Run live PostgreSQL 17 `FORCE RLS` tests** (requires ephemeral container or PG17 instance with admin + `NOBYPASSRLS` roles):
   ```bash
   cargo test --test integration_tests postgres_rls_live_isolation_test -- --ignored --nocapture
   ```

## Coding & Security Rules

- Preserve `ENABLE` + `FORCE ROW LEVEL SECURITY` policies in [`migrations/postgres/001_init_rls.sql`](migrations/postgres/001_init_rls.sql); every tenant/MFA/WebAuthn table change must satisfy `scripts/security-lint.py`.
- Keep the TypeScript frontend dependency-free at runtime and free of inline `style="..."` or inline `<script>` tags so per-request CSP nonces stay strict.
- Never commit `.env` files, personal credentials, API keys, or private test domains.
- Keep commits atomic following [Conventional Commits](https://www.conventionalcommits.org/).
