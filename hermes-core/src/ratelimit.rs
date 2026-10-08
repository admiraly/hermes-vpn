//! Per-key token-bucket rate limiting, shared by the relay and signaling
//! servers to blunt abuse from any single source address.
//!
//! Each key (normally the client's IP) gets a bucket holding up to
//! `burst` tokens that refills at `per_second`. An action costs one token;
//! with the bucket empty it is refused. Idle buckets are dropped by
//! [`RateLimiter::prune`] so memory tracks *active* sources only.

use std::hash::Hash;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Bucket parameters.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    /// Tokens added per second.
    pub per_second: f64,
    /// Bucket capacity — how many actions may happen back to back.
    pub burst: f64,
}

impl Rate {
    /// `count` actions per `period`, with a burst of `burst`.
    #[must_use]
    pub fn new(count: u32, period: Duration, burst: u32) -> Self {
        Self {
            per_second: f64::from(count) / period.as_secs_f64(),
            burst: f64::from(burst),
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// A keyed token-bucket limiter. Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct RateLimiter<K: Eq + Hash> {
    rate: Rate,
    buckets: DashMap<K, Bucket>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    /// A limiter applying `rate` to every key independently.
    #[must_use]
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            buckets: DashMap::new(),
        }
    }

    /// Spend one token for `key`. `false` means the action must be refused.
    pub fn check(&self, key: &K) -> bool {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &K, now: Instant) -> bool {
        let mut bucket = self.buckets.entry(key.clone()).or_insert(Bucket {
            tokens: self.rate.burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate.per_second).min(self.rate.burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets that have refilled completely (their key has been
    /// quiet long enough that forgetting it changes nothing).
    pub fn prune(&self) {
        let now = Instant::now();
        let full_after = self.rate.burst / self.rate.per_second;
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.updated).as_secs_f64() < full_after);
    }

    /// Number of keys currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Is no key tracked?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let rl = RateLimiter::new(Rate::new(10, Duration::from_secs(1), 3));
        let t0 = Instant::now();
        assert!(rl.check_at(&1, t0));
        assert!(rl.check_at(&1, t0));
        assert!(rl.check_at(&1, t0));
        assert!(!rl.check_at(&1, t0), "burst exhausted");
        // Other keys are independent.
        assert!(rl.check_at(&2, t0));
        // 100 ms at 10/s refills one token.
        assert!(rl.check_at(&1, t0 + Duration::from_millis(100)));
        assert!(!rl.check_at(&1, t0 + Duration::from_millis(100)));
        // Long idle never exceeds the burst.
        let later = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert!(rl.check_at(&1, later));
        }
        assert!(!rl.check_at(&1, later));
    }

    #[test]
    fn prune_drops_idle_keys() {
        let rl = RateLimiter::new(Rate::new(1000, Duration::from_secs(1), 1));
        rl.check(&"a");
        std::thread::sleep(Duration::from_millis(5));
        rl.prune();
        assert!(rl.is_empty());
    }
}
