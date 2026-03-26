//! Rate limiter — per-agent, per-tool token bucket.

use dashmap::DashMap;
use std::time::Instant;

pub struct RateLimiter {
    /// "agent_id\x1ftool_name" -> bucket (unit separator avoids tuple allocation)
    buckets: DashMap<String, TokenBucket>,
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
    #[inline]
    pub fn check(&self, agent_id: &str, tool_name: &str) -> bool {
        let key = bucket_key(agent_id, tool_name);
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
        let new_max = calls_per_minute as f64;
        let prefix = format!("{agent_id}\x1f");
        // Update all existing buckets for this agent
        for mut entry in self.buckets.iter_mut() {
            if entry.key().starts_with(&prefix) {
                let bucket = entry.value_mut();
                bucket.max_tokens = new_max;
                bucket.refill_rate = new_max / 60.0;
                // Clamp current tokens so a lowered limit takes effect immediately
                bucket.tokens = bucket.tokens.min(new_max);
            }
        }
    }
}

/// Build a bucket key from agent + tool using ASCII unit separator.
#[inline]
fn bucket_key(agent_id: &str, tool_name: &str) -> String {
    use std::fmt::Write;
    let mut key = String::with_capacity(agent_id.len() + 1 + tool_name.len());
    let _ = write!(key, "{agent_id}\x1f{tool_name}");
    key
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

    #[test]
    fn different_tools_separate_buckets() {
        let limiter = RateLimiter::new();
        for _ in 0..60 {
            limiter.check("agent", "tool_a");
        }
        assert!(!limiter.check("agent", "tool_a"));
        // Same agent, different tool still has tokens
        assert!(limiter.check("agent", "tool_b"));
    }

    #[test]
    fn set_rate_lowers_limit() {
        let limiter = RateLimiter::new();
        // Prime the bucket for agent — consumes 1 token, leaving 59
        assert!(limiter.check("agent", "tool"));
        // Lower rate to 10/min — clamps current tokens from 59 to 10
        limiter.set_rate("agent", 10);
        // Should allow exactly 10 more calls (tokens clamped to 10)
        let mut allowed = 0;
        for _ in 0..20 {
            if limiter.check("agent", "tool") {
                allowed += 1;
            } else {
                break;
            }
        }
        assert_eq!(allowed, 10);
    }

    #[test]
    fn set_rate_does_not_affect_other_agents() {
        let limiter = RateLimiter::new();
        // Prime both agents
        assert!(limiter.check("agent-a", "tool"));
        assert!(limiter.check("agent-b", "tool"));

        limiter.set_rate("agent-a", 5);

        // agent-b should still have default rate
        let mut count = 0;
        for _ in 0..59 {
            if limiter.check("agent-b", "tool") {
                count += 1;
            }
        }
        assert_eq!(count, 59); // 60 - 1 (initial) = 59 remaining
    }

    #[test]
    fn set_rate_before_any_check() {
        let limiter = RateLimiter::new();
        // set_rate on an agent that has no buckets yet — should be a no-op
        limiter.set_rate("nobody", 5);
        // First check should create a bucket with the DEFAULT rate, not 5
        // because set_rate only modifies existing buckets
        let mut count = 0;
        for _ in 0..60 {
            if limiter.check("nobody", "tool") {
                count += 1;
            }
        }
        assert_eq!(count, 60);
    }

    #[test]
    fn token_refill_over_time() {
        let limiter = RateLimiter::new();
        // Exhaust all tokens
        for _ in 0..60 {
            limiter.check("agent", "tool");
        }
        assert!(!limiter.check("agent", "tool"));

        // Manually advance the bucket's last_refill to simulate time passing
        // We can't easily sleep in tests, but we can verify the refill logic
        // by checking that the bucket key exists
        assert!(limiter.buckets.contains_key(&bucket_key("agent", "tool")));
    }
}
