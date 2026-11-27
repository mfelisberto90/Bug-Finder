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
| `2.0.x` | Active security patches |

## End-to-End Security Architecture

- **Browser Edge Zero-PII**: `bugfinder-mini.js` strips URL `#fragments` (such as OAuth `#access_token=...`) and redacts sensitive query parameter values in the browser prior to transmission; embedded SDK tags verify via SRI `sha384` hashes; `traceparent` propagation is strictly restricted to same-origin requests when opted in.
- **RFC 9113 Multi-Header HTTP Parsing**: Session cookies (`headers.get_all(header::COOKIE)`) and reverse-proxy client IP resolution (`headers.get_all("x-forwarded-for")` scanned right-to-left up to 16 hops behind explicit `BUGFINDER_TRUSTED_PROXIES`) handle multi-header frames safely without header-splitting spoofing.
- **Sub-Microsecond Rust SIMD Edge WAF**: Single-pass `AhoCorasick` matching with 2-pass stack-buffered URI percent decoding blocks SQLi, path traversal, cloud metadata SSRF (IPv4 `169.254.169.254`, IPv6-mapped `[::ffff:169.254.169.254]`, AWS IPv6 IMDSv2 `fd00:ec2::254`, GCP/Alibaba/Oracle metadata), XSS, command injection, JNDI/SSTI, prototype pollution, `.js.map` scraping, WebDAV verbs, and root dotfiles (while exempting RFC 8615 `/.well-known/*`). State counters live in `16`-shard `ShardedBoundedMap<[u8; 32], V, 16>` keyed by master HMAC digests.
- **100% OS CSPRNG & AEAD at Rest**: Password salts, AES-256-GCM nonces, session tokens, API tokens, DSN keys, TOTP secrets, and recovery codes exclusively use OS entropy (`OsRng`, enforced by `bugfinder lint`). Stored alert secrets and TOTP seeds use `HKDF-SHA256` + `AES-256-GCM` (`enc:v1:`) with record-bound AAD.
- **PostgreSQL 17 Row-Level Security & Immutable Audit Ledger**: `ENABLE` + `FORCE ROW LEVEL SECURITY` under a `NOBYPASSRLS` application role (`bugfinder_app`), fail-closed transaction-scoped GUCs, SHA-256 hash-chained `audit_logs`, `REVOKE UPDATE, DELETE, TRUNCATE` on `bugfinder_app`, and database-level `BEFORE UPDATE OR DELETE` append-only triggers on both SQLite and PostgreSQL.
- **Strict CSP & Shared-Workstation Hygiene**: Per-request cryptographic CSP nonces with `style-src-attr 'none'`, zero inline styles or scripts, automatic in-memory and `sessionStorage` purge on logout/401/org-switch, DNS-pinned outbound webhooks with `v2` delivery-UUID anti-replay HMAC signatures, and 40-char commit SHA pinning in CI workflows (verified continuously by `bugfinder lint`).
