# Security Policy

## Reporting a Vulnerability

Please **do not** open public GitHub issues for suspected security vulnerabilities.

Instead, use **GitHub Private Security Advisories** (`Security` -> `Advisories` -> `Report a vulnerability` on this repository) so we can triage, validate, and ship a fix before public disclosure.

Include in your report:
- Affected version or commit SHA
- Reproduction steps or proof-of-concept request/code
- Impacted component (PostgreSQL RLS, auth/MFA, ingest parser, Edge WAF, browser SDK, UI)

## Supported Versions

| Version | Supported |
|---|---|
| `2.1.x` / `2.x` | Active security patches |

## End-to-End Security Architecture

- **Browser Edge Zero-PII & Safe Instrumentation**: `bugfinder-mini.js` strips URL `#fragments` (such as OAuth `#access_token=...`) and redacts sensitive query parameter values in the browser prior to transmission, clones `fetch(new Request(...))` headers without mutation, exposes `window.__bfOrigFetch`, guards `securitypolicyviolation` against feedback loops, and restricts `traceparent` propagation strictly to same-origin requests when opted in. Embedded SDK tags verify via SRI `sha384` hashes.
- **RFC 9113 Multi-Header HTTP Parsing**: Session cookies (`headers.get_all(header::COOKIE)`) and reverse-proxy client IP resolution (`headers.get_all("x-forwarded-for")` scanned right-to-left up to 16 hops behind explicit `BUGFINDER_TRUSTED_PROXIES`) handle multi-header frames safely without header-splitting spoofing.
- **Sub-Microsecond Rust SIMD Edge WAF**: Single-pass `AhoCorasick` matching with 2-pass stack-buffered URI percent decoding blocks SQLi, path traversal, cloud metadata SSRF (IPv4 `169.254.169.254`, IPv6-mapped `[::ffff:169.254.169.254]`, AWS IPv6 IMDSv2 `fd00:ec2::254`, GCP/Alibaba/Oracle metadata), XSS, command injection, JNDI/SSTI, prototype pollution, WebDAV verbs, and root dotfiles (exempting RFC 8615 `/.well-known/*`), while rejecting `.js.map` probes with `404` without triggering CGNAT bans. State counters live in `16`-shard `ShardedBoundedMap<[u8; 32], V, 16>` keyed by master HMAC digests.
- **Decompression & Parser Hardening**: Zstd payloads pass an RFC 8878 frame header pre-check (`window_size <= 8 MiB`) before `ruzstd 0.9.1` allocation; `ingest_shield` applies bounded decompression; JSON ingestion strips `\u0000` NUL bytes across keys/values, rejects nesting deeper than `32` levels, clamps forged timestamps to `now ± 24h`, and validates SourceMaps via streaming zero-DOM `IgnoredAny` parsing with per-org quotas.
- **100% OS CSPRNG, `enc:v2:` AEAD & Step-Up Auth**: Password salts, AES-256-GCM nonces, session tokens, API tokens, DSN keys, TOTP secrets, and recovery codes exclusively use OS entropy (`OsRng`, enforced by `bugfinder lint`). Stored secrets use `HKDF-SHA256` + `AES-256-GCM` (`enc:v2:` with `BUGFINDER_PREVIOUS_APP_KEYS` rotation fallback and backward-compatible `enc:v1:` reads). Sensitive mutations enforce Passkey (`/api/auth/reauth/passkey/begin|finish`) or TOTP/password step-up re-authentication, and OIDC SSO binds identities to `(oidc_issuer, oidc_sub)` while enforcing local MFA and `token_endpoint` origin validation.
- **PostgreSQL 17 Row-Level Security & Immutable Audit Ledger**: `ENABLE` + `FORCE ROW LEVEL SECURITY` covers all `15` tables (including `users` and `login_attempts`) under a `NOBYPASSRLS` application role (`bugfinder_app`) with `REVOKE DELETE, TRUNCATE ON users`, fail-closed transaction-scoped GUCs, SHA-256 hash-chained `audit_logs`, `REVOKE UPDATE, DELETE, TRUNCATE` on `audit_logs`, and database-level `BEFORE UPDATE OR DELETE` append-only triggers on both SQLite and PostgreSQL.
- **Zero-CVE Supply Chain & Strict CI Gates**: Direct `sqlx-core` + `sqlx-postgres` (no umbrella `sqlx-mysql` / `rsa`), `rusqlite 0.43`, and `ruzstd 0.9.1` keep `Cargo.lock` at `239` crates with `0` active CVEs checked on every PR via OSV.dev. Per-request cryptographic CSP nonces enforce `style-src-attr 'none'`, outbound webhooks use DNS-pinned SSRF guards with `v2` delivery-UUID anti-replay HMAC signatures, `bugfinder lint` blocks `gitleaks:allow` bypasses, and CI workflows pin all GitHub Actions to 40-char commit SHAs.
