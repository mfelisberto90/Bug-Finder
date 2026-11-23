# Security Policy

## Reporting a Vulnerability

Please **do not** open public GitHub issues for suspected security vulnerabilities.

Instead, use **GitHub Private Security Advisories** (`Security` -> `Advisories` -> `Report a vulnerability` on this repository) so we can triage, validate, and ship a fix before public disclosure.

Include in your report:
- Affected version or commit SHA
- Reproduction steps or proof-of-concept request/code
- Impacted component (PostgreSQL RLS, auth/MFA, ingest parser, browser SDK, UI)

## Supported Versions

| Version | Supported |
|---|---|
| `1.0.x` | Active security patches |

## Security Architecture Highlights

- **PostgreSQL 17 Row-Level Security**: `ENABLE` + `FORCE ROW LEVEL SECURITY` under a `NOBYPASSRLS` application role (`bugfinder_app`), with fail-closed transaction-scoped `set_config` GUCs checked at startup and verified in `bugfinder doctor`.
- **Fail-Closed Secrets**: Production startup requires an explicit or `.app_key`-persisted key (`>= 32` characters) and validates `BUGFINDER_ALLOWED_HOSTS` / `BUGFINDER_TRUSTED_PROXIES` (wildcards rejected).
- **Cryptography & Sessions**: `scrypt` password hashing, `HKDF-SHA256` + `AES-256-GCM` (`enc:v1:`) for sensitive credentials at rest, `HMAC-SHA256` rate-limit/IP keys, per-request CSP nonces without `unsafe-inline`, TOTP (RFC 6238), and WebAuthn/FIDO2 Passkeys (`ES256`/`Ed25519`, User Verification enforced).
- **Auditability**: Hash-chained `SHA-256` audit log with `REVOKE UPDATE, DELETE, TRUNCATE` enforced on the PostgreSQL runtime role.
