//! Rate limiter — per-agent, per-tool token bucket.

use dashmap::DashMap;
use std::time::Instant;

pub struct RateLimiter {
    /// (agent_id, tool_name) -> bucket
    buckets: DashMap<(String, String), TokenBucket>,
    /// Default calls per minute
    default_rate: u64,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            default_rate: 60, // 60 calls/minute default
        }
    }

    /// Check if a call is within rate limits. Consumes a token if allowed.
    pub fn check(&self, agent_id: &str, tool_name: &str) -> bool {
        let key = (agent_id.to_string(), tool_name.to_string());
        let mut bucket = self.buckets.entry(key).or_insert_with(|| TokenBucket {
            tokens: self.default_rate as f64,
            max_tokens: self.default_rate as f64,
            refill_rate: self.default_rate as f64 / 60.0,
            last_refill: Instant::now(),
        });

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Set rate limit for a specific agent (calls per minute).
    pub fn set_rate(&self, agent_id: &str, calls_per_minute: u64) {
        // Update all existing buckets for this agent
        for mut entry in self.buckets.iter_mut() {
            if entry.key().0 == agent_id {
                entry.value_mut().max_tokens = calls_per_minute as f64;
                entry.value_mut().refill_rate = calls_per_minute as f64 / 60.0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_rate_limit() {
        let limiter = RateLimiter::new();
        // Should allow 60 calls (default bucket)
        for _ in 0..60 {
            assert!(limiter.check("agent", "tool"));
        }
        // 61st should be denied
        assert!(!limiter.check("agent", "tool"));
    }

    #[test]
    fn different_agents_separate_buckets() {
        let limiter = RateLimiter::new();
        for _ in 0..60 {
            limiter.check("agent-a", "tool");
        }
        // agent-b should still have tokens
        assert!(limiter.check("agent-b", "tool"));
    }
}
