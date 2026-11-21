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
        assert!(!dedupe.check_and_mark(1, "evt_abc"));
        assert!(dedupe.check_and_mark(1, "evt_abc"));
        assert!(!dedupe.check_and_mark(2, "evt_abc"));
    }
}
