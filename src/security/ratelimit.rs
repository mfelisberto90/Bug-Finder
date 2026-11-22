use crate::domain::models::{ProjectAuthInfo, TenantCtx};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// Fixed-capacity OOM-proof map with deterministic FIFO eviction on overflow.
pub struct BoundedMap<K, V> {
    cap: usize,
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(16),
            map: HashMap::with_capacity(cap.min(1024)),
            order: VecDeque::with_capacity(cap.min(1024)),
        }
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            self.map.insert(key, value);
            return;
        }
        while self.map.len() >= self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        let map = &mut self.map;
        map.retain(|k, v| keep(k, v));
        self.order.retain(|k| map.contains_key(k));
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    count: u32,
    window_start: Instant,
}

pub struct RateLimitDecision {
    pub allowed: bool,
    pub retry_after_sec: u64,
}

/// Multi-bucket HMAC-SHA256 rate limiter. Never stores raw emails or client IPs in memory keys.
pub struct HmacRateLimiter {
    app_key: [u8; 32],
    buckets: Mutex<BoundedMap<String, Bucket>>,
}

impl HmacRateLimiter {
    pub fn new(app_key: [u8; 32], max_buckets: usize) -> Self {
        Self {
            app_key,
            buckets: Mutex::new(BoundedMap::new(max_buckets)),
        }
    }

    pub fn hash_key(&self, scope: &str, raw_id: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.app_key).expect("HMAC accepts 32-byte key");
        mac.update(scope.as_bytes());
        mac.update(b":");
        mac.update(raw_id.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn check_and_record(
        &self,
        scope: &str,
        raw_id: &str,
        max_per_window: u32,
        window: Duration,
    ) -> RateLimitDecision {
        let key = self.hash_key(scope, raw_id);
        let now = Instant::now();
        let mut guard = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = guard.get_mut(&key) {
            if now.duration_since(b.window_start) >= window {
                b.count = 1;
                b.window_start = now;
                return RateLimitDecision {
                    allowed: true,
                    retry_after_sec: 0,
                };
            }
            if b.count >= max_per_window {
                let elapsed = now.duration_since(b.window_start);
                let rem = window.saturating_sub(elapsed).as_secs().max(1);
                return RateLimitDecision {
                    allowed: false,
                    retry_after_sec: rem,
                };
            }
            b.count += 1;
            return RateLimitDecision {
                allowed: true,
                retry_after_sec: 0,
            };
        }
        guard.insert(
            key,
            Bucket {
                count: 1,
                window_start: now,
            },
        );
        RateLimitDecision {
            allowed: true,
            retry_after_sec: 0,
        }
    }

    /// Clear ONLY the principal bucket on login success — never clear the IP spray bucket.
    pub fn clear_bucket(&self, scope: &str, raw_id: &str) {
        let key = self.hash_key(scope, raw_id);
        let mut guard = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&key);
    }
}

/// Bounded LRU/TTL cache deduplicating repeated SDK retries with identical `(project_id, event_id)`.
pub struct EventDedupeCache {
    ttl: Duration,
    inner: Mutex<BoundedMap<(i64, String), Instant>>,
}

impl EventDedupeCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(BoundedMap::new(capacity)),
        }
    }

    /// Read-only check: returns `true` if this `(project_id, event_id)` was already seen within `ttl`.
    pub fn contains(&self, project_id: i64, event_id: &str) -> bool {
        let key = (project_id, event_id.to_string());
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(seen_at) = guard.get_mut(&key) {
            if now.duration_since(*seen_at) < self.ttl {
                return true;
            }
        }
        false
    }

    /// Record `(project_id, event_id)` as ingested only after durable queue acceptance.
    pub fn mark(&self, project_id: i64, event_id: &str) {
        let key = (project_id, event_id.to_string());
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(key, now);
    }

    /// Returns `true` if this `(project_id, event_id)` was already seen within `ttl`.
    pub fn check_and_mark(&self, project_id: i64, event_id: &str) -> bool {
        let key = (project_id, event_id.to_string());
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(seen_at) = guard.get_mut(&key) {
            if now.duration_since(*seen_at) < self.ttl {
                return true;
            }
            *seen_at = now;
            return false;
        }
        guard.insert(key, now);
        false
    }
}

/// Format Sentry SDK rate-limit header (`retry_after:category:scope`).
pub fn sentry_rate_limit_header(retry_after_sec: u64, category: &str) -> String {
    format!("{retry_after_sec}:{category}:project")
}

/// Negative cache for invalid DSN lookups (30s TTL) preventing flood amplification against SQLite/PG.
pub struct InvalidDsnCache {
    ttl: Duration,
    inner: Mutex<BoundedMap<(i64, String), Instant>>,
}

impl InvalidDsnCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(BoundedMap::new(capacity)),
        }
    }

    pub fn is_blocked(&self, project_id: i64, key_sha256: &str) -> bool {
        let key = (project_id, key_sha256.to_string());
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(exp) = guard.get_mut(&key) {
            if now < *exp {
                return true;
            }
            guard.remove(&key);
        }
        false
    }

    pub fn mark_invalid(&self, project_id: i64, key_sha256: &str) {
        let key = (project_id, key_sha256.to_string());
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(key, Instant::now() + self.ttl);
    }

    pub fn invalidate(&self, project_id: i64, key_sha256: &str) {
        let key = (project_id, key_sha256.to_string());
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&key);
    }

    pub fn invalidate_project(&self, project_id: i64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|(pid, _), _| *pid != project_id);
    }
}

/// Short-TTL positive cache for DSN authentication lookups with synchronous invalidation on mutations.
pub struct DsnAuthCache {
    ttl: Duration,
    inner: Mutex<BoundedMap<(i64, String), (ProjectAuthInfo, Instant)>>,
}

impl DsnAuthCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(BoundedMap::new(capacity)),
        }
    }

    pub fn get(&self, project_id: i64, key_sha256: &str) -> Option<ProjectAuthInfo> {
        let key = (project_id, key_sha256.to_string());
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((info, exp)) = guard.get_mut(&key) {
            if now < *exp {
                return Some(info.clone());
            }
            guard.remove(&key);
        }
        None
    }

    pub fn insert(&self, project_id: i64, key_sha256: &str, info: ProjectAuthInfo) {
        let key = (project_id, key_sha256.to_string());
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(key, (info, Instant::now() + self.ttl));
    }

    pub fn invalidate_project(&self, project_id: i64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|(pid, _), _| *pid != project_id);
    }

    pub fn invalidate_org(&self, org_id: i64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (info, _)| info.organization_id != org_id);
    }
}

/// Short-TTL positive cache for Bearer API token lookups with expiry revalidation & sync invalidation.
pub struct ApiTokenCache {
    ttl: Duration,
    inner: Mutex<BoundedMap<(String, Option<String>), (TenantCtx, Instant)>>,
}

impl ApiTokenCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(BoundedMap::new(capacity)),
        }
    }

    pub fn get(
        &self,
        token_sha256: &str,
        org_slug_opt: Option<&str>,
        now_sec: i64,
    ) -> Option<TenantCtx> {
        let key = (token_sha256.to_string(), org_slug_opt.map(ToString::to_string));
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((ctx, exp)) = guard.get_mut(&key) {
            let token_still_valid = ctx.token_expires_at.map_or(true, |e| e > now_sec);
            if now < *exp && token_still_valid {
                return Some(ctx.clone());
            }
            guard.remove(&key);
        }
        None
    }

    pub fn insert(&self, token_sha256: &str, org_slug_opt: Option<&str>, ctx: TenantCtx) {
        let key = (token_sha256.to_string(), org_slug_opt.map(ToString::to_string));
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(key, (ctx, Instant::now() + self.ttl));
    }

    pub fn invalidate_org(&self, org_id: i64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (ctx, _)| ctx.organization_id != org_id);
    }

    pub fn invalidate_user(&self, user_id: i64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (ctx, _)| ctx.user_id != Some(user_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_map_caps_memory_and_rate_limiter_preserves_ip_bucket() {
        let mut bm = BoundedMap::new(16);
        for i in 0..40 {
            bm.insert(i, i);
        }
        assert_eq!(bm.len(), 16);

        let rl = HmacRateLimiter::new([7u8; 32], 128);
        for _ in 0..5 {
            assert!(rl.check_and_record("auth_principal", "user@example.com", 5, Duration::from_secs(60)).allowed);
            assert!(rl.check_and_record("auth_ip", "203.0.113.5", 10, Duration::from_secs(60)).allowed);
        }
        assert!(!rl.check_and_record("auth_principal", "user@example.com", 5, Duration::from_secs(60)).allowed);

        // Clearing principal on success must NOT reset IP bucket
        rl.clear_bucket("auth_principal", "user@example.com");
        assert!(rl.check_and_record("auth_principal", "user@example.com", 5, Duration::from_secs(60)).allowed);
        for _ in 0..5 {
            let _ = rl.check_and_record("auth_ip", "203.0.113.5", 10, Duration::from_secs(60));
        }
        assert!(!rl.check_and_record("auth_ip", "203.0.113.5", 10, Duration::from_secs(60)).allowed);
    }

    #[test]
    fn event_id_dedupe_blocks_sdk_retries() {
        let dedupe = EventDedupeCache::new(64, Duration::from_secs(300));
        assert!(!dedupe.contains(1, "evt_split"));
        dedupe.mark(1, "evt_split");
        assert!(dedupe.contains(1, "evt_split"));

        assert!(!dedupe.check_and_mark(1, "evt_abc"));
        assert!(dedupe.check_and_mark(1, "evt_abc"));
        assert!(!dedupe.check_and_mark(2, "evt_abc"));
    }

    #[test]
    fn positive_auth_caches_enforce_ttl_expiry_and_sync_invalidation() {
        let dsn_cache = DsnAuthCache::new(32, Duration::from_secs(15));
        let info = ProjectAuthInfo {
            project_id: 7,
            organization_id: 99,
            organization_slug: "acme".into(),
            project_slug: "web".into(),
            first_event_at: None,
            rate_limit_per_min: 1000,
            filters: Default::default(),
            org_scrub_ip_addresses: false,
            org_event_throttle_rate: 0,
        };
        dsn_cache.insert(7, "sha_a", info);
        assert!(dsn_cache.get(7, "sha_a").is_some());
        dsn_cache.invalidate_project(7);
        assert!(dsn_cache.get(7, "sha_a").is_none());

        let tok_cache = ApiTokenCache::new(32, Duration::from_secs(10));
        let ctx = TenantCtx::from_token(
            99,
            "acme".into(),
            1,
            crate::domain::models::UserRole::Member,
            "event:read",
        )
        .with_token_expires_at(Some(2000));
        tok_cache.insert("tok_hash", Some("acme"), ctx);
        assert!(tok_cache.get("tok_hash", Some("acme"), 1500).is_some());
        // Expired token must fail immediately on revalidation
        assert!(tok_cache.get("tok_hash", Some("acme"), 2000).is_none());

        let ctx2 = TenantCtx::from_token(
            99,
            "acme".into(),
            2,
            crate::domain::models::UserRole::Admin,
            "org:read",
        );
        tok_cache.insert("tok_hash2", None, ctx2);
        tok_cache.invalidate_org(99);
        assert!(tok_cache.get("tok_hash2", None, 1500).is_none());
    }
}
