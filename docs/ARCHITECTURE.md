# Bug-Finder v2.0 Architecture & Performance Engine

Bug-Finder compiles the web dashboard (`ui/dist` compressed in `.rodata`), browser SDKs (`sdks/browser/`), ingestion server, Edge WAF, OTLP decoder, CLI, and MCP server into one static Rust executable (~6.5 MB, `< 15 MB VmRSS`).

## Request & Ingestion Pipeline

```text
Browser / Backend App
  └─> [Multi-Header RFC 9113 Extract] (headers.get_all Cookie / X-Forwarded-For)
        └─> [SIMD Edge WAF < 1 us] (src/security/waf.rs: 1-pass AhoCorasick + 2-pass stack URI decode)
              └─> [ShardedBoundedMap (16 shards, stack [u8; 32] HMAC keys)] (src/security/ratelimit.rs)
                    └─> [SIMD Scrubber Prefilter ~15 ns] (src/domain/scrubber.rs -> Cow::Borrowed on clean text)
                          ├─> [Immediate SSE Broadcast < 0.2 ms] -> Live Tail & Connect App modal
                          └─> [Adaptive BatchWriter] (0 ms flush on idle / 5 ms burst coalesce)
                                └─> [SQLite WAL mmap 64MB + prepare_cached] or [PG17 FORCE RLS]
```

## Key Subsystems

1. **Zero-Python Native Security Linter (`src/lint.rs`)**: `bugfinder lint` validates UI CSP rules, ECMAScript `/v` input regex grammar, `OsRng` CSPRNG usage, `get_all` multi-header extraction, SQL comment-stripped PostgreSQL `FORCE RLS` coverage, `audit_logs` immutability triggers, 40-char SHA GitHub Action pinning, and zero-Python/zero-leak repository hygiene in `< 3 ms`.
2. **SIMD Edge WAF (`src/security/waf.rs`)**: Uses precompiled `OnceLock<AhoCorasick>` automatons (`ascii_case_insensitive`) and stack-allocated `[u8; 4096]` decoding buffers (`memchr` precheck) so double-encoded traversal, SQLi, XSS, cloud metadata SSRF (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `100.100.100.200`, `192.0.0.192`), command injection, JNDI/SSTI, prototype pollution, scanner User-Agents, `.js.map` harvesting, and root dotfiles are caught in `< 1 µs` with zero heap allocations on clean requests.
3. **16-Shard Contention-Free Maps (`ShardedBoundedMap<K, V, 16>`)**: Rate limits (`HmacRateLimiter`), `EventDedupeCache`, `InvalidDsnCache`, `DsnAuthCache`, `ApiTokenCache`, `ScannerGuard`, and `ShieldEngine` partition keys across 16 independent mutexes using stack-allocated 32-byte HMAC digests instead of heap `String` hex allocations.
4. **Adaptive Coalescing `BatchWriter` (`src/storage/batch_writer.rs`)**: Eliminates the fixed 50 ms idle wait. Whenever no flush happened in the last `5 ms`, `BatchWriter` drains up to `128` queued items via `try_recv()` and commits immediately (`0 ms` timer wait). Under continuous error bursts, it sleeps `5 ms` to coalesce writes into a single WAL/PostgreSQL transaction.
5. **Storage Optimization (`src/storage/sqlite.rs` & `migrations/`)**: All recurring static queries use `conn.prepare_cached(...)`, read-only SQLite connections enable `PRAGMA mmap_size = 67108864` (64 MB OS page cache), `idx_logs_org_ts` / `idx_pg_logs_org_ts` speed up time-window log histograms, and SQL triggers enforce append-only immutability on `audit_logs`.
