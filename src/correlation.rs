//! Cross-agent correlation — detect coordinated multi-agent access patterns.
//!
//! Flags when multiple distinct agents target the same tool within a short
//! time window, which may indicate a coordinated attack.

use chrono::{DateTime, Utc};
use dashmap::DashMap;

/// Configuration for cross-agent correlation detection.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Time window in seconds for grouping calls (default 60).
    pub window_secs: u64,
    /// Minimum distinct agents within the window to trigger an alert (default 3).
    pub agent_threshold: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            agent_threshold: 3,
        }
    }
}

/// Alert raised when coordinated access is detected.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CorrelationAlert {
    /// Multiple agents accessed the same tool within the time window.
    CoordinatedAccess {
        tool_name: String,
        agent_count: usize,
        window_secs: u64,
    },
}

impl std::fmt::Display for CorrelationAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoordinatedAccess {
                tool_name,
                agent_count,
                window_secs,
            } => write!(
                f,
                "coordinated access: {} distinct agents called '{}' within {}s",
                agent_count, tool_name, window_secs
            ),
        }
    }
}

/// Detects when multiple agents target the same tool in a short window.
pub struct CorrelationDetector {
    /// tool_name -> list of (agent_id, timestamp) within recent window
    recent_calls: DashMap<String, Vec<(String, DateTime<Utc>)>>,
    config: CorrelationConfig,
}

impl Default for CorrelationDetector {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

impl CorrelationDetector {
    #[must_use]
    pub fn new(config: CorrelationConfig) -> Self {
        Self {
            recent_calls: DashMap::new(),
            config,
        }
    }

    /// Record a tool call and return an alert if the correlation threshold is met.
    pub fn record_and_check(
        &self,
        agent_id: &str,
        tool_name: &str,
        timestamp: DateTime<Utc>,
    ) -> Option<CorrelationAlert> {
        let cutoff = timestamp - chrono::Duration::seconds(self.config.window_secs as i64);

        let mut entry = self.recent_calls.entry(tool_name.to_string()).or_default();

        // Prune expired entries
        entry.retain(|(_, ts)| *ts >= cutoff);

        // Add current call
        entry.push((agent_id.to_string(), timestamp));

        // Count distinct agents
        let mut agents: Vec<&str> = entry.iter().map(|(a, _)| a.as_str()).collect();
        agents.sort_unstable();
        agents.dedup();

        if agents.len() >= self.config.agent_threshold {
            Some(CorrelationAlert::CoordinatedAccess {
                tool_name: tool_name.to_string(),
                agent_count: agents.len(),
                window_secs: self.config.window_secs,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_alert_single_agent() {
        let detector = CorrelationDetector::default();
        let now = Utc::now();
        for _ in 0..10 {
            assert!(
                detector
                    .record_and_check("agent-1", "tarang_probe", now)
                    .is_none()
            );
        }
    }

    #[test]
    fn detect_coordinated_access() {
        let detector = CorrelationDetector::default();
        let now = Utc::now();
        assert!(
            detector
                .record_and_check("agent-1", "aegis_scan", now)
                .is_none()
        );
        assert!(
            detector
                .record_and_check("agent-2", "aegis_scan", now)
                .is_none()
        );
        // 3rd distinct agent triggers alert
        let alert = detector.record_and_check("agent-3", "aegis_scan", now);
        assert!(alert.is_some());
        match alert.unwrap() {
            CorrelationAlert::CoordinatedAccess { agent_count, .. } => {
                assert_eq!(agent_count, 3);
            }
        }
    }

    #[test]
    fn no_alert_outside_window() {
        let config = CorrelationConfig {
            window_secs: 10,
            agent_threshold: 3,
        };
        let detector = CorrelationDetector::new(config);
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(20);

        // Two agents called long ago
        detector.record_and_check("agent-1", "tool", old);
        detector.record_and_check("agent-2", "tool", old);
        // Third agent calls now — but the first two are outside the window
        assert!(detector.record_and_check("agent-3", "tool", now).is_none());
    }

    #[test]
    fn configurable_threshold() {
        let config = CorrelationConfig {
            window_secs: 60,
            agent_threshold: 5,
        };
        let detector = CorrelationDetector::new(config);
        let now = Utc::now();
        for i in 0..4 {
            assert!(
                detector
                    .record_and_check(&format!("agent-{i}"), "tool", now)
                    .is_none()
            );
        }
        // 5th agent triggers
        assert!(detector.record_and_check("agent-4", "tool", now).is_some());
    }

    #[test]
    fn different_tools_independent() {
        let detector = CorrelationDetector::default();
        let now = Utc::now();
        detector.record_and_check("agent-1", "tool_a", now);
        detector.record_and_check("agent-2", "tool_a", now);
        detector.record_and_check("agent-1", "tool_b", now);
        detector.record_and_check("agent-2", "tool_b", now);
        // Neither tool has 3 distinct agents
        assert!(
            detector
                .record_and_check("agent-3", "tool_a", now)
                .is_some()
        );
        // tool_b still only has 2 agents
        assert!(
            detector
                .record_and_check("agent-1", "tool_b", now)
                .is_none()
        );
    }
}
