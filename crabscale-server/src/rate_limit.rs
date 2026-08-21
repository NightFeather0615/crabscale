//! Token-bucket rate limiting for the outer and inner control endpoints.
//!
//! Security hardening (M4-02, #25) adds two rate limits, each responding
//! with HTTP `429 Too Many Requests` and a `Retry-After` delta-seconds header:
//!
//! - `POST /ts2021` is limited per client IP so a single peer cannot consume
//!   all Noise handshake slots. The limit is enforced before the upgrade
//!   request is parsed.
//! - `POST /machine/register` is limited per Noise machine key so an
//!   authenticated client cannot flood the registration path. The limit is
//!   enforced before the register body is parsed.
//!
//! Each key owns an independent token bucket: `burst` capacity refilled at
//! `per_min` tokens per minute. The bucket table is bounded and idle buckets
//! are pruned so a host cannot grow memory without spending tokens.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default `/ts2021` limit: 60 upgrade requests per minute per client IP.
pub const DEFAULT_TS2021_RATE_PER_MIN: u64 = 60;
/// Default `/ts2021` token bucket capacity (burst) per client IP.
pub const DEFAULT_TS2021_BURST: u32 = 10;
/// Default `/machine/register` limit: 30 requests per minute per machine key.
pub const DEFAULT_REGISTER_RATE_PER_MIN: u64 = 30;
/// Default `/machine/register` token bucket capacity (burst) per machine key.
pub const DEFAULT_REGISTER_BURST: u32 = 5;
/// Default maximum number of distinct keys kept in memory per limiter.
pub const DEFAULT_MAX_RATE_KEYS: usize = 4096;

/// How long a freshly refilled (idle) bucket may remain before the prune
/// drops it. Idle buckets cost nothing to recreate, so an aggressive prune
/// is safe and keeps the table small.
const IDLE_TTL: Duration = Duration::from_secs(10 * 60);

/// Configuration for the `/ts2021` and `/machine/register` rate limiters.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum `/ts2021` upgrade requests per minute per client IP.
    pub ts2021_per_min: u64,
    /// Token bucket capacity for `/ts2021` upgrades per client IP.
    pub ts2021_burst: u32,
    /// Maximum `/machine/register` requests per minute per machine key.
    pub register_per_min: u64,
    /// Token bucket capacity for `/machine/register` per machine key.
    pub register_burst: u32,
    /// Maximum number of distinct keys kept in memory per limiter.
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ts2021_per_min: DEFAULT_TS2021_RATE_PER_MIN,
            ts2021_burst: DEFAULT_TS2021_BURST,
            register_per_min: DEFAULT_REGISTER_RATE_PER_MIN,
            register_burst: DEFAULT_REGISTER_BURST,
            max_entries: DEFAULT_MAX_RATE_KEYS,
        }
    }
}

/// A single token bucket for one key.
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// Mutable state shared by every clone of a [`RateLimiter`].
struct Inner {
    buckets: HashMap<String, Bucket>,
    rate_per_sec: f64,
    burst: f64,
    max_entries: usize,
}

/// A shared token-bucket limiter keyed by an arbitrary string.
///
/// [`RateLimiter`] is cheap to clone: clones share one underlying table, so a
/// `ControlRouter` that fans out to many connections enforces one limit.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Inner>>,
}

impl RateLimiter {
    /// Create a limiter with `per_min` tokens refilled per minute and a
    /// `burst` capacity. A `per_min` or `burst` of `0` disables the limit.
    pub fn new(per_min: u64, burst: u32, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                buckets: HashMap::new(),
                rate_per_sec: per_min as f64 / 60.0,
                burst: burst as f64,
                max_entries,
            })),
        }
    }

    /// Check whether `key` may take a token now.
    ///
    /// Returns `None` when a token was consumed (allowed), or `Some(retry)` —
    /// the number of seconds to wait before retrying — when the bucket is
    /// empty (HTTP 429 with `Retry-After: retry`).
    pub fn check(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("rate limiter lock poisoned");

        let rate = inner.rate_per_sec;
        let burst = inner.burst;
        // A disabled limiter always admits.
        if rate <= 0.0 || burst <= 0.0 {
            return None;
        }

        if let Some(bucket) = inner.buckets.get_mut(key) {
            Self::refill(bucket, rate, burst, now);
        } else {
            if inner.buckets.len() >= inner.max_entries {
                inner.prune(now);
            }
            // The prune may have removed `key` if it existed as a stale entry,
            // so always create a fresh bucket.
            if inner.buckets.len() >= inner.max_entries {
                // Still over budget: evict the least recently used bucket.
                inner.evict_oldest();
            }
            inner.buckets.insert(
                key.to_string(),
                Bucket {
                    tokens: burst,
                    updated: now,
                },
            );
        }

        let bucket = inner.buckets.get_mut(key).expect("bucket present");
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            None
        } else {
            let need = 1.0 - bucket.tokens;
            Some(((need / rate).ceil() as u64).max(1))
        }
    }

    /// Refill `bucket` to `now`, capping tokens at `burst`.
    fn refill(bucket: &mut Bucket, rate_per_sec: f64, burst: f64, now: Instant) {
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.updated = now;
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * rate_per_sec).min(burst);
        }
    }
}

impl Inner {
    /// Drop idle (full and untouched for `IDLE_TTL`) buckets, then, if still
    /// over the entry budget, the single oldest bucket.
    fn prune(&mut self, now: Instant) {
        if self.buckets.len() < self.max_entries {
            return;
        }
        self.buckets.retain(|_, bucket| {
            let idle = now.duration_since(bucket.updated) >= IDLE_TTL;
            let full = bucket.tokens >= self.burst;
            // Keep recently-used or partially consumed buckets; drop idle full
            // ones (they never run out, so re-creating them is free).
            !(idle && full)
        });
    }

    /// Evict the least recently updated bucket (used when `prune` alone could
    /// not bring the table under budget).
    fn evict_oldest(&mut self) {
        let oldest_key = self
            .buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.updated)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest_key {
            self.buckets.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_until_burst_is_consumed() {
        let limiter = RateLimiter::new(60, 3, 16);
        assert_eq!(limiter.check("a"), None);
        assert_eq!(limiter.check("a"), None);
        assert_eq!(limiter.check("a"), None);
        // The fourth request within the burst is limited.
        assert!(limiter.check("a").is_some());
    }

    #[test]
    fn keys_are_independent() {
        let limiter = RateLimiter::new(60, 1, 16);
        assert_eq!(limiter.check("a"), None);
        // A different key still has its own token.
        assert_eq!(limiter.check("b"), None);
        // "a" is drained.
        assert!(limiter.check("a").is_some());
    }

    #[test]
    fn bucket_refills_over_time() {
        let limiter = RateLimiter::new(60, 1, 16);
        assert_eq!(limiter.check("a"), None);
        assert!(limiter.check("a").is_some());
        // After ~1.1s, one token has refilled (60 per minute = 1 per second).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(limiter.check("a"), None);
    }

    #[test]
    fn retry_after_is_positive_seconds() {
        let limiter = RateLimiter::new(60, 1, 16);
        assert_eq!(limiter.check("a"), None);
        let retry = limiter.check("a").expect("drained bucket limits");
        assert!(retry >= 1, "retry-after must be at least one second");
    }

    #[test]
    fn zero_rate_disables_limiting() {
        let limiter = RateLimiter::new(0, 5, 16);
        for _ in 0..100 {
            assert_eq!(limiter.check("always"), None);
        }
    }

    #[test]
    fn table_is_bounded() {
        let limiter = RateLimiter::new(1, 10, 4);
        for i in 0..100 {
            assert_eq!(
                limiter.check(&format!("key-{i}")),
                None,
                "a fresh key always gets burst tokens"
            );
        }
        let inner = limiter.inner.lock().unwrap();
        assert!(
            inner.buckets.len() <= 4,
            "bounded table must not exceed its limit, got {}",
            inner.buckets.len()
        );
    }
}
